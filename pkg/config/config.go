package config

import (
	"fmt"
	"time"
)

// OperatorConfig holds the operator configuration
type OperatorConfig struct {
	// MetricsAddr is the address for the metrics endpoint
	MetricsAddr string

	// ProbeAddr is the address for health probes
	ProbeAddr string

	// EnableLeaderElection enables leader election
	EnableLeaderElection bool

	// LeaderElectionID is the ID for leader election
	LeaderElectionID string

	// MaxConcurrentReconciles is the maximum number of concurrent reconciles
	MaxConcurrentReconciles int

	// ReconcileTimeout is the timeout for reconcile operations
	ReconcileTimeout time.Duration

	// AutheliaNamespace is the namespace where Authelia is deployed
	AutheliaNamespace string

	// AutheliaConfigMapName is the name of the Authelia ConfigMap
	AutheliaConfigMapName string

	// AutheliaConfigMapBaseName is the name of the base Authelia ConfigMap
	AutheliaConfigMapBaseName string

	// OIDCSecretsName is the name of the OIDC secrets secret
	OIDCSecretsName string
}

// NewDefaultConfig creates a default configuration
func NewDefaultConfig() *OperatorConfig {
	return &OperatorConfig{
		MetricsAddr:               ":8080",
		ProbeAddr:                 ":8081",
		EnableLeaderElection:      false,
		LeaderElectionID:          "authelia-oidc-operator",
		MaxConcurrentReconciles:   3,
		ReconcileTimeout:          5 * time.Minute,
		AutheliaNamespace:         "authelia",
		AutheliaConfigMapName:     "authelia-config",
		AutheliaConfigMapBaseName: "authelia-config-base",
		OIDCSecretsName:           "authelia-oidc-secrets",
	}
}

// Validate validates the configuration
func (c *OperatorConfig) Validate() error {
	if c.MaxConcurrentReconciles < 1 {
		return fmt.Errorf("maxConcurrentReconciles must be at least 1")
	}
	if c.ReconcileTimeout < time.Second {
		return fmt.Errorf("reconcileTimeout must be at least 1 second")
	}
	if c.AutheliaNamespace == "" {
		return fmt.Errorf("autheliaNamespace is required")
	}
	return nil
}
