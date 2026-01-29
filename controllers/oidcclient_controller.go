package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
		For(&securityv1alpha1.OIDCClient{}).
		Owns(&corev1.Secret{}).
		// Watch ClaimsPolicy resources
		Watches(
			&securityv1alpha1.ClaimsPolicy{},
			r.enqueueAllOIDCClients(),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		// Watch UserAttribute resources
		Watches(
			&securityv1alpha1.UserAttribute{},
			r.enqueueAllOIDCClients(),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
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
	now := metav1.Now()
	for i := range oidcClientList.Items {
		oc := &oidcClientList.Items[i]
		oc.Status.Ready = true
		oc.Status.LastSyncedAt = &now
		if err := r.Status().Update(ctx, oc); err != nil {
			log.Error(err, "Failed to update OIDCClient status", "clientId", oc.Spec.ClientID)
		}
	}

	log.Info("Reconciliation completed successfully",
		"clientCount", len(oidcClientList.Items),
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

	// Post-process: merge clients by client_id (deepmerge replaces slices, we want to merge by ID)
	mergedYAML, err = r.mergeClientsByID([]byte(baseYAML), mergedYAML)
	if err != nil {
		return operrors.NewPermanentError("failed to merge clients", err)
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

// mergeClientsByID ensures base clients not managed by CRDs are preserved
// deepmerge replaces slices, but we want to merge clients by client_id
func (r *OIDCClientReconciler) mergeClientsByID(baseYAML, mergedYAML []byte) ([]byte, error) {
	var baseConfig, mergedConfig map[string]any
	if err := yaml.Unmarshal(baseYAML, &baseConfig); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(mergedYAML, &mergedConfig); err != nil {
		return nil, err
	}

	baseClients := getClients(baseConfig)
	mergedClients := getClients(mergedConfig)

	// Build set of merged client IDs
	mergedClientIDs := make(map[string]struct{}, len(mergedClients))
	for _, c := range mergedClients {
		if id := getClientID(c); id != "" {
			mergedClientIDs[id] = struct{}{}
		}
	}

	// Append base clients not present in merged
	for _, c := range baseClients {
		if id := getClientID(c); id != "" {
			if _, exists := mergedClientIDs[id]; !exists {
				mergedClients = append(mergedClients, c)
			}
		}
	}

	setClients(mergedConfig, mergedClients)
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
