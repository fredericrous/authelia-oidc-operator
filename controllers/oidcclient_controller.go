package controllers

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TwiN/deepmerge"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
	"github.com/fredericrous/homelab/authelia-oidc-operator/pkg/assembler"
	"github.com/fredericrous/homelab/authelia-oidc-operator/pkg/config"
	operrors "github.com/fredericrous/homelab/authelia-oidc-operator/pkg/errors"
)

// OIDCClientReconciler reconciles OIDCClient objects
type OIDCClientReconciler struct {
	client.Client
	Log       logr.Logger
	Scheme    *runtime.Scheme
	Recorder  record.EventRecorder
	Config    *config.OperatorConfig
	Assembler *assembler.Assembler
}

// SetupWithManager sets up the controller with the Manager
func (r *OIDCClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Config == nil {
		r.Config = config.NewDefaultConfig()
	}

	r.Assembler = assembler.NewAssembler(r.Client, r.Log.WithName("assembler"))

	opts := controller.Options{
		MaxConcurrentReconciles: r.Config.MaxConcurrentReconciles,
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1alpha1.OIDCClient{},
			// Ignore status-only changes: the reconcile body writes Status.LastSyncedAt
			// on every run across every OIDCClient, which would otherwise trigger N²
			// re-reconciles (writes cascade through the watch).
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		Owns(&corev1.Secret{}).
		// Watch ClaimsPolicy resources — GenerationChanged so their status writes
		// don't fan out into OIDCClient reconciles.
		Watches(
			&securityv1alpha1.ClaimsPolicy{},
			r.enqueueAllOIDCClients(),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// Watch UserAttribute resources
		Watches(
			&securityv1alpha1.UserAttribute{},
			r.enqueueAllOIDCClients(),
			builder.WithPredicates(predicate.GenerationChangedPredicate{}),
		).
		// Watch base ConfigMap
		Watches(
			&corev1.ConfigMap{},
			r.enqueueForBaseConfigMap(),
			builder.WithPredicates(
				predicate.NewPredicateFuncs(func(obj client.Object) bool {
					return obj.GetName() == r.Config.AutheliaConfigMapBaseName &&
						obj.GetNamespace() == r.Config.AutheliaNamespace
				}),
			),
		).
		// Watch Secrets for client secrets and JWKS
		Watches(
			&corev1.Secret{},
			r.enqueueRequestsForSecret(),
			builder.WithPredicates(
				predicate.ResourceVersionChangedPredicate{},
			),
		).
		WithOptions(opts).
		Complete(r)
}

// Reconcile handles the reconciliation loop
// +kubebuilder:rbac:groups=security.homelab.io,resources=oidcclients,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.homelab.io,resources=oidcclients/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.homelab.io,resources=claimspolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=security.homelab.io,resources=userattributes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;create;update

func (r *OIDCClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("oidcclient", req.NamespacedName, "trace_id", generateTraceID())
	ctx = logr.NewContext(ctx, log)

	log.V(1).Info("Starting reconciliation")

	// Fetch all OIDCClients cluster-wide
	oidcClientList := &securityv1alpha1.OIDCClientList{}
	if err := r.List(ctx, oidcClientList); err != nil {
		return ctrl.Result{}, operrors.NewTransientError("failed to list OIDCClients", err)
	}

	// Fetch all ClaimsPolicies cluster-wide
	claimsPolicyList := &securityv1alpha1.ClaimsPolicyList{}
	if err := r.List(ctx, claimsPolicyList); err != nil {
		return ctrl.Result{}, operrors.NewTransientError("failed to list ClaimsPolicies", err)
	}

	// Fetch all UserAttributes cluster-wide
	userAttributeList := &securityv1alpha1.UserAttributeList{}
	if err := r.List(ctx, userAttributeList); err != nil {
		return ctrl.Result{}, operrors.NewTransientError("failed to list UserAttributes", err)
	}

	if len(oidcClientList.Items) == 0 && len(claimsPolicyList.Items) == 0 && len(userAttributeList.Items) == 0 {
		log.Info("No OIDC resources found, skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// Fetch OIDC secrets for JWKS configuration
	oidcSecrets := &corev1.Secret{}
	oidcSecretsKey := types.NamespacedName{
		Name:      r.Config.OIDCSecretsName,
		Namespace: r.Config.AutheliaNamespace,
	}
	if err := r.Get(ctx, oidcSecretsKey, oidcSecrets); err != nil {
		if !errors.IsNotFound(err) {
			return ctrl.Result{}, operrors.NewTransientError("failed to get OIDC secrets", err)
		}
		log.Info("OIDC secrets not found, JWKS will not be configured")
		oidcSecrets = nil
	}

	// Assemble the configuration
	result, err := r.Assembler.Assemble(
		ctx,
		oidcClientList.Items,
		claimsPolicyList.Items,
		userAttributeList.Items,
		oidcSecrets,
	)
	if err != nil {
		log.Error(err, "Assembly failed")
		if len(oidcClientList.Items) > 0 {
			r.Recorder.Event(&oidcClientList.Items[0], corev1.EventTypeWarning, "AssemblyFailed", err.Error())
		}
		if operrors.ShouldRetry(err) {
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	// Update the Authelia ConfigMap with deep merge
	if err := r.updateAutheliaConfig(ctx, result); err != nil {
		if len(oidcClientList.Items) > 0 {
			r.Recorder.Eventf(&oidcClientList.Items[0], corev1.EventTypeWarning, "ConfigUpdateFailed", "Failed to update Authelia config: %v", err)
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Update status for all OIDCClients
	// Clients whose secrets couldn't be resolved are marked not ready
	skippedSet := make(map[string]struct{}, len(result.SkippedClientIDs))
	for _, id := range result.SkippedClientIDs {
		skippedSet[id] = struct{}{}
	}

	now := metav1.Now()
	for i := range oidcClientList.Items {
		oc := &oidcClientList.Items[i]
		if _, skipped := skippedSet[oc.Spec.ClientID]; skipped {
			oc.Status.Ready = false
			r.Recorder.Eventf(oc, corev1.EventTypeWarning, "SecretMissing",
				"Client secret not found for %q — client excluded from Authelia config. "+
					"Ensure the Secret referenced by secretRef exists in namespace %q.",
				oc.Spec.ClientID, cmp.Or(oc.Spec.SecretRef.Namespace, oc.Namespace))
		} else {
			oc.Status.Ready = true
		}
		oc.Status.LastSyncedAt = &now
		if err := r.Status().Update(ctx, oc); err != nil {
			log.Error(err, "Failed to update OIDCClient status", "clientId", oc.Spec.ClientID)
		}
	}

	log.Info("Reconciliation completed successfully",
		"clientCount", len(result.Clients),
		"skippedCount", len(result.SkippedClientIDs),
		"policyCount", len(claimsPolicyList.Items),
		"attributeCount", len(userAttributeList.Items))

	if len(oidcClientList.Items) > 0 {
		r.Recorder.Event(&oidcClientList.Items[0], corev1.EventTypeNormal, "Synced",
			fmt.Sprintf("Successfully assembled %d clients, %d policies, %d attributes",
				len(oidcClientList.Items), len(claimsPolicyList.Items), len(userAttributeList.Items)))
	}

	return ctrl.Result{}, nil
}

// updateAutheliaConfig updates the Authelia ConfigMap with deep-merged configuration
// Uses TwiN/deepmerge for identity_providers.oidc and definitions.user_attributes
func (r *OIDCClientReconciler) updateAutheliaConfig(ctx context.Context, result *assembler.AssemblyResult) error {
	log := logr.FromContextOrDiscard(ctx)

	// Get the base ConfigMap
	baseCM := &corev1.ConfigMap{}
	baseCMKey := types.NamespacedName{
		Name:      r.Config.AutheliaConfigMapBaseName,
		Namespace: r.Config.AutheliaNamespace,
	}
	if err := r.Get(ctx, baseCMKey, baseCM); err != nil {
		return operrors.NewTransientError("failed to get base ConfigMap", err).
			WithContext("name", r.Config.AutheliaConfigMapBaseName)
	}

	// Get the base configuration YAML
	baseYAML, ok := baseCM.Data["configuration.yml"]
	if !ok {
		return operrors.NewConfigError("configuration.yml not found in base ConfigMap", nil)
	}

	// Deep merge using TwiN/deepmerge
	// The assembled YAML (result.ConfigYAML) is merged INTO the base config
	mergedYAML, err := deepmerge.YAML([]byte(baseYAML), []byte(result.ConfigYAML))
	if err != nil {
		return operrors.NewPermanentError("failed to deep merge configs", err)
	}

	// Post-process: merge clients by client_id
	// deepmerge concatenates arrays, so we need to dedupe by client_id
	// CRD clients take precedence over base clients
	mergedYAML, err = r.mergeClientsByID([]byte(baseYAML), []byte(result.ConfigYAML), mergedYAML)
	if err != nil {
		return operrors.NewPermanentError("failed to merge clients", err)
	}

	// Post-process: merge access_control rules
	// CRD rules take precedence over base rules for the same domain
	mergedYAML, err = r.mergeAccessControlRules(ctx, []byte(baseYAML), []byte(result.ConfigYAML), mergedYAML)
	if err != nil {
		return operrors.NewPermanentError("failed to merge access_control rules", err)
	}

	// Compute hash of the final merged YAML to detect any changes
	combinedHash := computeHash(string(mergedYAML))

	existing := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Name: r.Config.AutheliaConfigMapName, Namespace: r.Config.AutheliaNamespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new ConfigMap
			targetCM := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      r.Config.AutheliaConfigMapName,
					Namespace: r.Config.AutheliaNamespace,
					Labels: map[string]string{
						"app.kubernetes.io/managed-by": "authelia-oidc-operator",
					},
					Annotations: map[string]string{
						"authelia.homelab.io/oidc-config-hash": combinedHash,
					},
				},
				Data: map[string]string{
					"configuration.yml": string(mergedYAML),
				},
			}
			log.Info("Creating Authelia ConfigMap", "name", r.Config.AutheliaConfigMapName)
			return r.Create(ctx, targetCM)
		}
		return err
	}

	// Check if the config hash has changed
	existingHash := ""
	if existing.Annotations != nil {
		existingHash = existing.Annotations["authelia.homelab.io/oidc-config-hash"]
	}

	if existingHash == combinedHash {
		log.V(1).Info("Authelia ConfigMap unchanged (hash match), skipping update")
		return nil
	}

	// Update ConfigMap
	existing.Data = map[string]string{
		"configuration.yml": string(mergedYAML),
	}
	if existing.Labels == nil {
		existing.Labels = make(map[string]string)
	}
	existing.Labels["app.kubernetes.io/managed-by"] = "authelia-oidc-operator"
	if existing.Annotations == nil {
		existing.Annotations = make(map[string]string)
	}
	existing.Annotations["authelia.homelab.io/oidc-config-hash"] = combinedHash
	log.Info("Updating Authelia ConfigMap", "name", r.Config.AutheliaConfigMapName, "hash", combinedHash)
	return r.Update(ctx, existing)
}

// mergeAccessControlRules merges access_control rules from base config and CRD-assembled config
// CRD rules appear first, then base rules (excluding duplicates by domain)
// Within the merged result, specific domains come before wildcards
func (r *OIDCClientReconciler) mergeAccessControlRules(ctx context.Context, baseYAML, crdYAML, mergedYAML []byte) ([]byte, error) {
	log := logr.FromContextOrDiscard(ctx)

	var baseConfig, crdConfig, mergedConfig map[string]any
	if err := yaml.Unmarshal(baseYAML, &baseConfig); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(crdYAML, &crdConfig); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(mergedYAML, &mergedConfig); err != nil {
		return nil, err
	}

	crdRules := getAccessControlRules(crdConfig)
	baseRules := getAccessControlRules(baseConfig)

	// If no CRD rules and no base rules, nothing to do
	if len(crdRules) == 0 && len(baseRules) == 0 {
		return mergedYAML, nil
	}

	// Build set of CRD-managed domains
	crdDomains := make(map[string]struct{})
	for _, rule := range crdRules {
		if domain := getRuleDomain(rule); domain != "" {
			crdDomains[domain] = struct{}{}
		}
	}

	// CRD rules first, then base rules not superseded by a CRD rule.
	//
	// "Superseded" means the CRD owns the domain AND the base rule is just as
	// broad. A base rule that NARROWS — one carrying resources/methods/networks
	// — is a carve-out, not a competing definition of the same thing, so
	// dropping it silently deletes configuration the author wrote. That is
	// exactly what happened to a `resources: ^/api/packages/.*` bypass for
	// gitea.daddyshome.fr: the gitea OIDCClient claims the domain, so the rule
	// vanished between authelia-config-base and authelia-config while every
	// reconcile logged success.
	finalRules := crdRules
	for _, rule := range baseRules {
		domain := getRuleDomain(rule)
		if _, managed := crdDomains[domain]; managed && !ruleIsNarrowing(rule) {
			// Keep this loud. Silence here cost a deploy that looked applied
			// and was not; the only symptom was the absence of a line.
			log.Info("Dropping base access_control rule superseded by an OIDCClient rule for the same domain",
				"domain", domain)
			continue
		}
		finalRules = append(finalRules, rule)
	}

	// Re-sort: specific domains before wildcards, then alphabetically
	sortAccessControlRules(finalRules)

	setAccessControlRules(mergedConfig, finalRules)
	return yaml.Marshal(mergedConfig)
}

// mergeClientsByID merges clients from base config and CRD-assembled config
// CRD clients take precedence; base clients not in CRDs are preserved
func (r *OIDCClientReconciler) mergeClientsByID(baseYAML, crdYAML, mergedYAML []byte) ([]byte, error) {
	var baseConfig, crdConfig, mergedConfig map[string]any
	if err := yaml.Unmarshal(baseYAML, &baseConfig); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(crdYAML, &crdConfig); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(mergedYAML, &mergedConfig); err != nil {
		return nil, err
	}

	baseClients := getClients(baseConfig)
	crdClients := getClients(crdConfig)

	// Build set of CRD-managed client IDs
	crdClientIDs := make(map[string]struct{}, len(crdClients))
	for _, c := range crdClients {
		if id := getClientID(c); id != "" {
			crdClientIDs[id] = struct{}{}
		}
	}

	// Start with CRD clients, then add base clients not managed by CRDs
	finalClients := crdClients
	for _, c := range baseClients {
		if id := getClientID(c); id != "" {
			if _, isCRDManaged := crdClientIDs[id]; !isCRDManaged {
				finalClients = append(finalClients, c)
			}
		}
	}

	setClients(mergedConfig, finalClients)
	return yaml.Marshal(mergedConfig)
}

// getClientID extracts client_id from a client map
func getClientID(c any) string {
	if client, ok := c.(map[string]any); ok {
		if id, ok := client["client_id"].(string); ok {
			return id
		}
	}
	return ""
}

// getClients extracts clients from identity_providers.oidc.clients using nested map access
func getClients(config map[string]any) []any {
	return getNestedSlice(config, "identity_providers", "oidc", "clients")
}

// setClients sets clients in identity_providers.oidc.clients, creating intermediate maps as needed
func setClients(config map[string]any, clients []any) {
	ip := getOrCreateNestedMap(config, "identity_providers")
	oidc := getOrCreateNestedMap(ip, "oidc")
	oidc["clients"] = clients
}

// getAccessControlRules extracts rules from access_control.rules
func getAccessControlRules(config map[string]any) []any {
	return getNestedSlice(config, "access_control", "rules")
}

// setAccessControlRules sets rules in access_control.rules
func setAccessControlRules(config map[string]any, rules []any) {
	ac := getOrCreateNestedMap(config, "access_control")
	ac["rules"] = rules
}

// getRuleDomain extracts domain from an access_control rule map
func getRuleDomain(rule any) string {
	if r, ok := rule.(map[string]any); ok {
		if domain, ok := r["domain"].(string); ok {
			return domain
		}
	}
	return ""
}

// ruleIsNarrowing reports whether a rule restricts to less than its whole
// domain. Authelia's matchers beyond `domain`/`domain_regex`: a rule carrying
// any of these applies to a SUBSET of the domain's requests, so it can coexist
// with a domain-wide rule instead of competing with it.
//
// `subject` is deliberately excluded. Authelia treats a subject-less rule as
// matching everyone, so `two_factor for group:x` and `two_factor for everyone`
// are two answers to the same question, and letting a base rule quietly
// out-rank the CRD's is the ambiguity this merge exists to resolve.
func ruleIsNarrowing(rule any) bool {
	r, ok := rule.(map[string]any)
	if !ok {
		return false
	}
	for _, k := range []string{"resources", "methods", "networks", "query"} {
		if v, present := r[k]; present && v != nil {
			return true
		}
	}
	return false
}

// sortAccessControlRules sorts rules so specific domains come before wildcards,
// and within one domain, narrowing rules come before domain-wide ones.
//
// Ordering IS the semantics here: Authelia evaluates rules top-down and takes
// the FIRST match. A `/api/packages/` bypass placed after that domain's
// catch-all never applies. The previous comparator compared domains only, so
// two rules on the same domain tied — and slices.SortFunc is NOT stable, so
// which one won was unspecified. Stable sort plus an explicit narrowing tie-
// break makes the result deterministic and correct rather than incidental.
func sortAccessControlRules(rules []any) {
	slices.SortStableFunc(rules, func(a, b any) int {
		domainA := getRuleDomain(a)
		domainB := getRuleDomain(b)
		aIsWildcard := strings.HasPrefix(domainA, "*")
		bIsWildcard := strings.HasPrefix(domainB, "*")
		if aIsWildcard != bIsWildcard {
			if aIsWildcard {
				return 1 // a (wildcard) goes after b (specific)
			}
			return -1 // a (specific) goes before b (wildcard)
		}
		if c := cmp.Compare(domainA, domainB); c != 0 {
			return c
		}
		aNarrow, bNarrow := ruleIsNarrowing(a), ruleIsNarrowing(b)
		if aNarrow != bNarrow {
			if aNarrow {
				return -1 // carve-out first, or it can never match
			}
			return 1
		}
		return 0 // equal rank; stable sort preserves authored order
	})
}

// getNestedSlice navigates a nested map structure and returns a slice at the final key
func getNestedSlice(m map[string]any, keys ...string) []any {
	for i, key := range keys {
		if i == len(keys)-1 {
			if slice, ok := m[key].([]any); ok {
				return slice
			}
			return nil
		}
		if next, ok := m[key].(map[string]any); ok {
			m = next
		} else {
			return nil
		}
	}
	return nil
}

// getOrCreateNestedMap gets or creates a nested map at the given key
func getOrCreateNestedMap(parent map[string]any, key string) map[string]any {
	if m, ok := parent[key].(map[string]any); ok {
		return m
	}
	m := make(map[string]any)
	parent[key] = m
	return m
}

// computeHash computes a SHA256 hash of the given string
func computeHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// enqueueAllOIDCClients returns a handler that enqueues any OIDCClient to trigger reconciliation
func (r *OIDCClientReconciler) enqueueAllOIDCClients() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		// List all OIDCClients and enqueue one to trigger reconciliation
		oidcClientList := &securityv1alpha1.OIDCClientList{}
		if err := r.List(ctx, oidcClientList); err != nil {
			r.Log.Error(err, "Failed to list OIDCClients")
			return nil
		}

		if len(oidcClientList.Items) == 0 {
			return nil
		}

		// Enqueue the first OIDCClient to trigger reconciliation
		oc := oidcClientList.Items[0]
		r.Log.V(1).Info("Enqueuing OIDCClient due to related resource change",
			"trigger", fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName()),
			"triggerKind", obj.GetObjectKind().GroupVersionKind().Kind)

		return []reconcile.Request{{
			NamespacedName: types.NamespacedName{
				Name:      oc.Name,
				Namespace: oc.Namespace,
			},
		}}
	})
}

// enqueueForBaseConfigMap returns a handler for base ConfigMap changes
func (r *OIDCClientReconciler) enqueueForBaseConfigMap() handler.EventHandler {
	return r.enqueueAllOIDCClients()
}

// enqueueRequestsForSecret returns a handler that enqueues OIDCClient objects
// when referenced secrets change
func (r *OIDCClientReconciler) enqueueRequestsForSecret() handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return nil
		}

		// List all OIDCClients
		oidcClientList := &securityv1alpha1.OIDCClientList{}
		if err := r.List(ctx, oidcClientList); err != nil {
			r.Log.Error(err, "Failed to list OIDCClients")
			return nil
		}

		var requests []reconcile.Request
		for _, oc := range oidcClientList.Items {
			// Check if this OIDCClient references the Secret
			if oc.Spec.SecretRef != nil {
				namespace := oc.Spec.SecretRef.Namespace
				if namespace == "" {
					namespace = oc.Namespace
				}

				if secret.Name == oc.Spec.SecretRef.Name && secret.Namespace == namespace {
					requests = append(requests, reconcile.Request{
						NamespacedName: types.NamespacedName{
							Name:      oc.Name,
							Namespace: oc.Namespace,
						},
					})
				}
			}
		}

		// Also trigger if it's the OIDC secrets for JWKS
		if secret.Name == r.Config.OIDCSecretsName && secret.Namespace == r.Config.AutheliaNamespace {
			// Enqueue any OIDCClient to trigger a full reconciliation
			if len(oidcClientList.Items) > 0 {
				oc := oidcClientList.Items[0]
				requests = append(requests, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      oc.Name,
						Namespace: oc.Namespace,
					},
				})
			}
		}

		if len(requests) > 0 {
			r.Log.V(1).Info("Enqueuing OIDCClients due to Secret change",
				"secret", types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace},
				"count", len(requests))
		}

		return requests
	})
}

func generateTraceID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
