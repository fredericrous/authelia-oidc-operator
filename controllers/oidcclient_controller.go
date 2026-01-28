package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

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

	if len(oidcClientList.Items) == 0 {
		log.Info("No OIDCClients found, skipping reconciliation")
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
	result, err := r.Assembler.Assemble(ctx, oidcClientList.Items, oidcSecrets)
	if err != nil {
		r.Recorder.Event(&oidcClientList.Items[0], corev1.EventTypeWarning, "AssemblyFailed", err.Error())
		if operrors.ShouldRetry(err) {
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		return ctrl.Result{}, err
	}

	// Create or update generated secrets
	for clientID, secretValue := range result.GeneratedSecrets {
		secretName := fmt.Sprintf("oidc-%s-client", clientID)
		if err := r.createOrUpdateSecret(ctx, secretName, r.Config.AutheliaNamespace, secretValue); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Update the Authelia ConfigMap
	if err := r.updateAutheliaConfig(ctx, result); err != nil {
		r.Recorder.Eventf(&oidcClientList.Items[0], corev1.EventTypeWarning, "ConfigUpdateFailed", "Failed to update Authelia config: %v", err)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Update status and salt annotations for all OIDCClients
	now := metav1.Now()
	for i := range oidcClientList.Items {
		oc := &oidcClientList.Items[i]

		// Update salt annotation if we have a new salt
		if salt, ok := result.ClientSalts[oc.Spec.ClientID]; ok && salt != "" {
			currentSalt := ""
			if oc.ObjectMeta.Annotations != nil {
				currentSalt = oc.ObjectMeta.Annotations[assembler.SaltAnnotationKey]
			}

			// Only update if salt changed
			if currentSalt != salt {
				if oc.ObjectMeta.Annotations == nil {
					oc.ObjectMeta.Annotations = make(map[string]string)
				}
				oc.ObjectMeta.Annotations[assembler.SaltAnnotationKey] = salt
				if err := r.Update(ctx, oc); err != nil {
					log.Error(err, "Failed to update OIDCClient salt annotation", "clientId", oc.Spec.ClientID)
				}
			}
		}

		// Update status
		oc.Status.Ready = true
		oc.Status.LastSyncedAt = &now
		if err := r.Status().Update(ctx, oc); err != nil {
			log.Error(err, "Failed to update OIDCClient status", "clientId", oc.Spec.ClientID)
		}
	}

	log.Info("Reconciliation completed successfully", "clientCount", len(oidcClientList.Items))
	r.Recorder.Event(&oidcClientList.Items[0], corev1.EventTypeNormal, "Synced", fmt.Sprintf("Successfully assembled %d OIDC clients", len(oidcClientList.Items)))

	return ctrl.Result{}, nil
}

// createOrUpdateSecret creates or updates a secret with the given value
func (r *OIDCClientReconciler) createOrUpdateSecret(ctx context.Context, name, namespace, value string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "authelia-oidc-operator",
				"app.kubernetes.io/component":  "oidc-secret",
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"client_secret": value,
		},
	}

	existing := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, existing)
	if err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, secret)
		}
		return err
	}

	// Update if it already exists
	existing.StringData = secret.StringData
	existing.Labels = secret.Labels
	return r.Update(ctx, existing)
}

// updateAutheliaConfig updates the Authelia ConfigMap with the assembled configuration
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

	// Parse the existing configuration
	configYAML, ok := baseCM.Data["configuration.yml"]
	if !ok {
		return operrors.NewConfigError("configuration.yml not found in base ConfigMap", nil)
	}

	var existingConfig map[string]interface{}
	if err := yaml.Unmarshal([]byte(configYAML), &existingConfig); err != nil {
		return operrors.NewConfigError("failed to parse configuration.yml", err)
	}

	// Parse the assembled OIDC config
	var oidcConfig map[string]interface{}
	if err := yaml.Unmarshal([]byte(result.ConfigYAML), &oidcConfig); err != nil {
		return operrors.NewPermanentError("failed to parse assembled config", err)
	}

	// Merge the OIDC configuration into the existing config
	if identityProviders, ok := oidcConfig["identity_providers"].(map[string]interface{}); ok {
		if existingConfig["identity_providers"] == nil {
			existingConfig["identity_providers"] = make(map[string]interface{})
		}
		existingIP := existingConfig["identity_providers"].(map[string]interface{})
		for k, v := range identityProviders {
			existingIP[k] = v
		}
	}

	// Marshal back to YAML
	mergedYAML, err := yaml.Marshal(existingConfig)
	if err != nil {
		return operrors.NewPermanentError("failed to marshal merged config", err)
	}

	// Compute hash of the OIDC config to detect changes
	oidcConfigHash := computeHash(result.ConfigYAML)

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
						"authelia.homelab.io/oidc-config-hash": oidcConfigHash,
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

	// Check if the OIDC config hash has changed
	existingHash := ""
	if existing.Annotations != nil {
		existingHash = existing.Annotations["authelia.homelab.io/oidc-config-hash"]
	}

	if existingHash == oidcConfigHash {
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
	existing.Annotations["authelia.homelab.io/oidc-config-hash"] = oidcConfigHash
	log.Info("Updating Authelia ConfigMap", "name", r.Config.AutheliaConfigMapName, "hash", oidcConfigHash)
	return r.Update(ctx, existing)
}

// computeHash computes a SHA256 hash of the given string
func computeHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
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
