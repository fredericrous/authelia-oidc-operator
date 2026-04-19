package config

import (
	"strings"
	"testing"
	"time"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid, got %v", err)
	}
	if cfg.AutheliaNamespace == "" || cfg.AutheliaConfigMapName == "" || cfg.AutheliaConfigMapBaseName == "" {
		t.Errorf("default config must populate Authelia namespace/configmap names, got %+v", cfg)
	}
	if cfg.MaxConcurrentReconciles < 1 {
		t.Errorf("MaxConcurrentReconciles default must be >=1, got %d", cfg.MaxConcurrentReconciles)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*OperatorConfig)
		wantErr string // substring; "" means no error
	}{
		{"valid default", func(*OperatorConfig) {}, ""},
		{"reconciles<1", func(c *OperatorConfig) { c.MaxConcurrentReconciles = 0 }, "maxConcurrentReconciles"},
		{"timeout<1s", func(c *OperatorConfig) { c.ReconcileTimeout = 500 * time.Millisecond }, "reconcileTimeout"},
		{"empty namespace", func(c *OperatorConfig) { c.AutheliaNamespace = "" }, "autheliaNamespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewDefaultConfig()
			tc.mutate(c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}
