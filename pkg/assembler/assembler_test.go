package assembler

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
)

func TestBuildClientEntry(t *testing.T) {
	a := &Assembler{Log: logr.Discard()}

	tests := []struct {
		name         string
		oidcClient   *securityv1alpha1.OIDCClient
		clientSecret string
		wantID       string
		wantName     string
		wantPublic   bool
		wantScopes   []string
	}{
		{
			name: "basic client with defaults",
			oidcClient: &securityv1alpha1.OIDCClient{
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				},
			},
			clientSecret: "secret123",
			wantID:       "test-client",
			wantName:     "test-client", // defaults to clientID
			wantPublic:   false,
			wantScopes:   []string{"openid", "profile", "email", "groups"},
		},
		{
			name: "client with custom name and scopes",
			oidcClient: &securityv1alpha1.OIDCClient{
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "custom-client",
					ClientName:   "My Custom Client",
					RedirectURIs: []string{"https://example.com/callback"},
					Scopes:       []string{"openid", "profile"},
				},
			},
			clientSecret: "secret456",
			wantID:       "custom-client",
			wantName:     "My Custom Client",
			wantPublic:   false,
			wantScopes:   []string{"openid", "profile"},
		},
		{
			name: "public client",
			oidcClient: &securityv1alpha1.OIDCClient{
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "public-spa",
					ClientName:   "Public SPA",
					Public:       true,
					RedirectURIs: []string{"https://spa.example.com/callback"},
				},
			},
			clientSecret: "",
			wantID:       "public-spa",
			wantName:     "Public SPA",
			wantPublic:   true,
			wantScopes:   []string{"openid", "profile", "email", "groups"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := a.buildClientEntry(tt.oidcClient, tt.clientSecret)

			if entry.ClientID != tt.wantID {
				t.Errorf("ClientID = %v, want %v", entry.ClientID, tt.wantID)
			}
			if entry.ClientName != tt.wantName {
				t.Errorf("ClientName = %v, want %v", entry.ClientName, tt.wantName)
			}
			if entry.Public != tt.wantPublic {
				t.Errorf("Public = %v, want %v", entry.Public, tt.wantPublic)
			}
			if len(entry.Scopes) != len(tt.wantScopes) {
				t.Errorf("Scopes = %v, want %v", entry.Scopes, tt.wantScopes)
			}
		})
	}
}

func TestBuildClientEntryDefaults(t *testing.T) {
	a := &Assembler{Log: logr.Discard()}

	oidcClient := &securityv1alpha1.OIDCClient{
		Spec: securityv1alpha1.OIDCClientSpec{
			ClientID:     "test",
			RedirectURIs: []string{"https://example.com"},
		},
	}

	entry := a.buildClientEntry(oidcClient, "secret")

	// Check defaults
	if entry.AuthorizationPolicy != "two_factor" {
		t.Errorf("AuthorizationPolicy = %v, want two_factor", entry.AuthorizationPolicy)
	}
	if entry.UserinfoSignedResponseAlg != "none" {
		t.Errorf("UserinfoSignedResponseAlg = %v, want none", entry.UserinfoSignedResponseAlg)
	}
	if entry.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("TokenEndpointAuthMethod = %v, want client_secret_basic", entry.TokenEndpointAuthMethod)
	}
	if len(entry.ResponseTypes) != 1 || entry.ResponseTypes[0] != "code" {
		t.Errorf("ResponseTypes = %v, want [code]", entry.ResponseTypes)
	}
	if len(entry.GrantTypes) != 1 || entry.GrantTypes[0] != "authorization_code" {
		t.Errorf("GrantTypes = %v, want [authorization_code]", entry.GrantTypes)
	}
}

func TestBuildConfigYAML(t *testing.T) {
	a := &Assembler{Log: logr.Discard()}

	clients := []ClientEntry{
		{
			ClientID:     "test-client",
			ClientName:   "Test Client",
			RedirectURIs: []string{"https://example.com/callback"},
			Scopes:       []string{"openid", "profile"},
		},
	}

	configYAML, err := a.buildConfigYAML(clients, nil)
	if err != nil {
		t.Fatalf("buildConfigYAML() error = %v", err)
	}

	// Check that the YAML contains expected content
	if !strings.Contains(configYAML, "identity_providers:") {
		t.Error("configYAML should contain identity_providers")
	}
	if !strings.Contains(configYAML, "oidc:") {
		t.Error("configYAML should contain oidc")
	}
	if !strings.Contains(configYAML, "clients:") {
		t.Error("configYAML should contain clients")
	}
	if !strings.Contains(configYAML, "test-client") {
		t.Error("configYAML should contain test-client")
	}
}

func TestBuildConfigYAMLWithJWKS(t *testing.T) {
	a := &Assembler{Log: logr.Discard()}

	clients := []ClientEntry{
		{
			ClientID:     "test-client",
			RedirectURIs: []string{"https://example.com"},
		},
	}

	oidcSecrets := &corev1.Secret{
		Data: map[string][]byte{
			"issuer_private_key":       []byte("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"),
			"issuer_certificate_chain": []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		},
	}

	configYAML, err := a.buildConfigYAML(clients, oidcSecrets)
	if err != nil {
		t.Fatalf("buildConfigYAML() error = %v", err)
	}

	if !strings.Contains(configYAML, "jwks:") {
		t.Error("configYAML should contain jwks when secrets provided")
	}
	if !strings.Contains(configYAML, "RS256") {
		t.Error("configYAML should contain RS256 algorithm")
	}
}

func TestResolveClientSecretPublic(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	a := &Assembler{Client: fakeClient, Log: logr.Discard()}

	oidcClient := &securityv1alpha1.OIDCClient{
		Spec: securityv1alpha1.OIDCClientSpec{
			ClientID: "public-client",
			Public:   true,
		},
	}

	generatedSecrets := make(map[string]string)
	secret, err := a.resolveClientSecret(context.Background(), oidcClient, generatedSecrets)
	if err != nil {
		t.Fatalf("resolveClientSecret() error = %v", err)
	}

	if secret != "" {
		t.Errorf("Public client should not have a secret, got %v", secret)
	}
	if len(generatedSecrets) != 0 {
		t.Errorf("No secrets should be generated for public client, got %v", generatedSecrets)
	}
}

func TestResolveClientSecretFromRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)

	// Create a secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client_secret": []byte("my-secret-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
	a := &Assembler{Client: fakeClient, Log: logr.Discard()}

	oidcClient := &securityv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-client",
			Namespace: "default",
		},
		Spec: securityv1alpha1.OIDCClientSpec{
			ClientID: "test-client",
			SecretRef: &securityv1alpha1.SecretReference{
				Name: "test-secret",
			},
		},
	}

	generatedSecrets := make(map[string]string)
	resolvedSecret, err := a.resolveClientSecret(context.Background(), oidcClient, generatedSecrets)
	if err != nil {
		t.Fatalf("resolveClientSecret() error = %v", err)
	}

	if resolvedSecret != "my-secret-value" {
		t.Errorf("resolvedSecret = %v, want my-secret-value", resolvedSecret)
	}
}

func TestResolveClientSecretGenerated(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	a := &Assembler{Client: fakeClient, Log: logr.Discard()}

	oidcClient := &securityv1alpha1.OIDCClient{
		Spec: securityv1alpha1.OIDCClientSpec{
			ClientID: "generate-secret-client",
			Public:   false,
		},
	}

	generatedSecrets := make(map[string]string)
	secret, err := a.resolveClientSecret(context.Background(), oidcClient, generatedSecrets)
	if err != nil {
		t.Fatalf("resolveClientSecret() error = %v", err)
	}

	if secret == "" {
		t.Error("Non-public client without secretRef should have generated secret")
	}
	if _, ok := generatedSecrets["generate-secret-client"]; !ok {
		t.Error("Generated secret should be stored in generatedSecrets map")
	}
}

func TestGenerateSecret(t *testing.T) {
	secret1 := generateSecret()
	secret2 := generateSecret()

	if secret1 == "" {
		t.Error("generateSecret() should not return empty string")
	}
	if secret1 == secret2 {
		t.Error("generateSecret() should return different values on each call")
	}
	if len(secret1) < 32 {
		t.Errorf("generateSecret() should return sufficiently long secret, got length %d", len(secret1))
	}
}

func TestHashSecretPBKDF2(t *testing.T) {
	secret := "my-test-secret"
	hashed := hashSecretPBKDF2(secret)

	// Check the format: $pbkdf2-sha512$<iterations>$<salt>$<hash>
	if !strings.HasPrefix(hashed, "$pbkdf2-sha512$") {
		t.Errorf("hashed secret should start with $pbkdf2-sha512$, got %v", hashed)
	}

	parts := strings.Split(hashed, "$")
	if len(parts) != 5 {
		t.Errorf("hashed secret should have 5 parts (empty, algo, iterations, salt, hash), got %d", len(parts))
	}

	// Iterations should be 310000
	if parts[2] != "310000" {
		t.Errorf("iterations should be 310000, got %v", parts[2])
	}

	// Salt and hash should not be empty
	if parts[3] == "" || parts[4] == "" {
		t.Error("salt and hash should not be empty")
	}

	// Same secret should produce different hashes (different salts)
	hashed2 := hashSecretPBKDF2(secret)
	if hashed == hashed2 {
		t.Error("hashing the same secret twice should produce different results (different salts)")
	}
}

func TestAssemble(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	a := NewAssembler(fakeClient, logr.Discard())

	oidcClients := []securityv1alpha1.OIDCClient{
		{
			Spec: securityv1alpha1.OIDCClientSpec{
				ClientID:     "client1",
				ClientName:   "Client 1",
				RedirectURIs: []string{"https://client1.example.com/callback"},
			},
		},
		{
			Spec: securityv1alpha1.OIDCClientSpec{
				ClientID:     "client2",
				ClientName:   "Client 2",
				Public:       true,
				RedirectURIs: []string{"https://client2.example.com/callback"},
			},
		},
	}

	result, err := a.Assemble(context.Background(), oidcClients, nil)
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}

	if len(result.Clients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(result.Clients))
	}

	// client1 should have a generated secret
	if _, ok := result.GeneratedSecrets["client1"]; !ok {
		t.Error("client1 should have a generated secret")
	}

	// client2 (public) should not have a generated secret
	if _, ok := result.GeneratedSecrets["client2"]; ok {
		t.Error("client2 (public) should not have a generated secret")
	}

	if result.ConfigYAML == "" {
		t.Error("ConfigYAML should not be empty")
	}
}
