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
		name          string
		oidcClient    *securityv1alpha1.OIDCClient
		clientSecret  string
		wantID        string
		wantName      string
		wantPublic    bool
		wantScopes    []string
		wantClaims    string
		wantAccessAlg string
	}{
		{
			name: "basic client with defaults",
			oidcClient: &securityv1alpha1.OIDCClient{
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:     "test-client",
					RedirectURIs: []string{"https://example.com/callback"},
				},
			},
			clientSecret:  "secret123",
			wantID:        "test-client",
			wantName:      "test-client", // defaults to clientID
			wantPublic:    false,
			wantScopes:    []string{"openid", "profile", "email", "groups"},
			wantClaims:    "",
			wantAccessAlg: "",
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
			clientSecret:  "secret456",
			wantID:        "custom-client",
			wantName:      "My Custom Client",
			wantPublic:    false,
			wantScopes:    []string{"openid", "profile"},
			wantClaims:    "",
			wantAccessAlg: "",
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
			clientSecret:  "",
			wantID:        "public-spa",
			wantName:      "Public SPA",
			wantPublic:    true,
			wantScopes:    []string{"openid", "profile", "email", "groups"},
			wantClaims:    "",
			wantAccessAlg: "",
		},
		{
			name: "client with extra scopes and claims policy",
			oidcClient: &securityv1alpha1.OIDCClient{
				Spec: securityv1alpha1.OIDCClientSpec{
					ClientID:                     "nextcloud",
					RedirectURIs:                 []string{"https://nextcloud.example.com/oidc"},
					ExtraScopes:                  []string{"nextcloud_userinfo"},
					ClaimsPolicy:                 "nextcloud_userinfo",
					AccessTokenSignedResponseAlg: "none",
				},
			},
			clientSecret:  "secret789",
			wantID:        "nextcloud",
			wantName:      "nextcloud",
			wantPublic:    false,
			wantScopes:    []string{"openid", "profile", "email", "groups", "nextcloud_userinfo"},
			wantClaims:    "nextcloud_userinfo",
			wantAccessAlg: "none",
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
			if entry.ClaimsPolicy != tt.wantClaims {
				t.Errorf("ClaimsPolicy = %v, want %v", entry.ClaimsPolicy, tt.wantClaims)
			}
			if entry.AccessTokenSignedResponseAlg != tt.wantAccessAlg {
				t.Errorf("AccessTokenSignedResponseAlg = %v, want %v", entry.AccessTokenSignedResponseAlg, tt.wantAccessAlg)
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

	result := &AssemblyResult{
		Clients: []ClientEntry{
			{
				ClientID:     "test-client",
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		},
		ClaimsPolicies: make(map[string]ClaimsPolicyEntry),
		Scopes:         make(map[string]ScopeEntry),
		UserAttributes: make(map[string]UserAttributeEntry),
	}

	configYAML, err := a.buildConfigYAML(result)
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

	result := &AssemblyResult{
		Clients: []ClientEntry{
			{
				ClientID:     "test-client",
				RedirectURIs: []string{"https://example.com"},
			},
		},
		ClaimsPolicies: make(map[string]ClaimsPolicyEntry),
		Scopes:         make(map[string]ScopeEntry),
		UserAttributes: make(map[string]UserAttributeEntry),
		JWKS: []map[string]any{
			{
				"algorithm":         "RS256",
				"use":               "sig",
				"key":               "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
				"certificate_chain": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			},
		},
	}

	configYAML, err := a.buildConfigYAML(result)
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

	secret, err := a.resolveClientSecret(context.Background(), oidcClient)
	if err != nil {
		t.Fatalf("resolveClientSecret() error = %v", err)
	}

	if secret != "" {
		t.Errorf("Public client should not have a secret, got %v", secret)
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

	resolvedSecret, err := a.resolveClientSecret(context.Background(), oidcClient)
	if err != nil {
		t.Fatalf("resolveClientSecret() error = %v", err)
	}

	if resolvedSecret != "my-secret-value" {
		t.Errorf("resolvedSecret = %v, want my-secret-value", resolvedSecret)
	}
}

func TestResolveClientSecretConfidentialWithoutSecretRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	a := &Assembler{Client: fakeClient, Log: logr.Discard()}

	oidcClient := &securityv1alpha1.OIDCClient{
		Spec: securityv1alpha1.OIDCClientSpec{
			ClientID: "confidential-client",
			Public:   false,
			// No SecretRef provided
		},
	}

	_, err := a.resolveClientSecret(context.Background(), oidcClient)
	if err == nil {
		t.Fatal("resolveClientSecret() should return error for confidential client without secretRef")
	}

	if !strings.Contains(err.Error(), "confidential client requires secretRef") {
		t.Errorf("error message should mention secretRef requirement, got: %v", err)
	}
}

func TestHashSecretPBKDF2(t *testing.T) {
	secret := "my-test-secret"
	clientId := "test-client"
	hash := hashSecretPBKDF2(secret, clientId)

	// Check the format: $pbkdf2-sha512$<iterations>$<salt>$<hash>
	if !strings.HasPrefix(hash, "$pbkdf2-sha512$") {
		t.Errorf("hashed secret should start with $pbkdf2-sha512$, got %v", hash)
	}

	parts := strings.Split(hash, "$")
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

	// Same secret and clientId should always produce the same hash (deterministic)
	hash2 := hashSecretPBKDF2(secret, clientId)
	if hash != hash2 {
		t.Error("hashing the same secret with same clientId should produce identical hash")
	}

	// Different clientId should produce different hash (different derived salt)
	hash3 := hashSecretPBKDF2(secret, "different-client")
	if hash == hash3 {
		t.Error("hashing the same secret with different clientId should produce different hash")
	}

	// Different secret should produce different hash
	hash4 := hashSecretPBKDF2("different-secret", clientId)
	if hash == hash4 {
		t.Error("hashing different secrets should produce different hashes")
	}
}

func TestAssemble(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)

	// Create secrets for confidential clients
	client1Secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "client1-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client_secret": []byte("client1-secret-value"),
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(client1Secret).Build()
	a := NewAssembler(fakeClient, logr.Discard())

	oidcClients := []securityv1alpha1.OIDCClient{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "client1",
				Namespace: "default",
			},
			Spec: securityv1alpha1.OIDCClientSpec{
				ClientID:     "client1",
				ClientName:   "Client 1",
				RedirectURIs: []string{"https://client1.example.com/callback"},
				SecretRef: &securityv1alpha1.SecretReference{
					Name: "client1-secret",
				},
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

	result, err := a.Assemble(context.Background(), oidcClients, nil, nil, nil)
	if err != nil {
		t.Fatalf("Assemble() error = %v", err)
	}

	if len(result.Clients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(result.Clients))
	}

	if result.ConfigYAML == "" {
		t.Error("ConfigYAML should not be empty")
	}

	// Verify client1 has a hashed secret
	var client1Entry *ClientEntry
	for i := range result.Clients {
		if result.Clients[i].ClientID == "client1" {
			client1Entry = &result.Clients[i]
			break
		}
	}
	if client1Entry == nil {
		t.Fatal("client1 not found in results")
	}
	if !strings.HasPrefix(client1Entry.ClientSecret, "$pbkdf2-sha512$") {
		t.Errorf("client1 should have hashed secret, got %v", client1Entry.ClientSecret)
	}

	// Verify client2 (public) has no secret
	var client2Entry *ClientEntry
	for i := range result.Clients {
		if result.Clients[i].ClientID == "client2" {
			client2Entry = &result.Clients[i]
			break
		}
	}
	if client2Entry == nil {
		t.Fatal("client2 not found in results")
	}
	if client2Entry.ClientSecret != "" {
		t.Errorf("client2 (public) should have no secret, got %v", client2Entry.ClientSecret)
	}
}

func TestAssembleConfidentialClientWithoutSecretRef(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = securityv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
	a := NewAssembler(fakeClient, logr.Discard())

	oidcClients := []securityv1alpha1.OIDCClient{
		{
			Spec: securityv1alpha1.OIDCClientSpec{
				ClientID:     "confidential-client",
				ClientName:   "Confidential Client",
				Public:       false,
				RedirectURIs: []string{"https://example.com/callback"},
				// No SecretRef - should fail
			},
		},
	}

	result, err := a.Assemble(context.Background(), oidcClients, nil, nil, nil)
	if err != nil {
		t.Fatalf("Assemble() should not fail, got: %v", err)
	}

	// Client with missing secretRef should be skipped, not included
	if len(result.Clients) != 0 {
		t.Errorf("expected 0 clients (skipped), got %d", len(result.Clients))
	}
}
