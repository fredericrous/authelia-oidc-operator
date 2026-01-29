package assembler

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/pbkdf2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
	operrors "github.com/fredericrous/homelab/authelia-oidc-operator/pkg/errors"
)

// Note: crypto/rand is still needed for generateSecret()

// Assembler handles OIDC configuration assembly for Authelia
type Assembler struct {
	Client client.Client
	Log    logr.Logger
}

// NewAssembler creates a new Assembler
func NewAssembler(client client.Client, log logr.Logger) *Assembler {
	return &Assembler{
		Client: client,
		Log:    log,
	}
}

// ClientEntry represents an OIDC client entry for Authelia configuration
type ClientEntry struct {
	ClientID                     string   `json:"client_id"`
	ClientName                   string   `json:"client_name"`
	ClientSecret                 string   `json:"client_secret,omitempty"`
	Public                       bool     `json:"public,omitempty"`
	AuthorizationPolicy          string   `json:"authorization_policy,omitempty"`
	ConsentMode                  string   `json:"consent_mode,omitempty"`
	PreconfiguredConsentDuration string   `json:"pre_configured_consent_duration,omitempty"`
	Audience                     []string `json:"audience,omitempty"`
	SectorIdentifierURI          string   `json:"sector_identifier_uri,omitempty"`
	RedirectURIs                 []string `json:"redirect_uris"`
	Scopes                       []string `json:"scopes"`
	ResponseTypes                []string `json:"response_types"`
	GrantTypes                   []string `json:"grant_types"`
	ResponseModes                []string `json:"response_modes"`
	UserinfoSignedResponseAlg    string   `json:"userinfo_signed_response_alg"`
	TokenEndpointAuthMethod      string   `json:"token_endpoint_auth_method"`
	RequirePKCE                  bool     `json:"require_pkce,omitempty"`
	PKCEChallengeMethod          string   `json:"pkce_challenge_method,omitempty"`
}

// AssemblyResult contains the result of OIDC configuration assembly
type AssemblyResult struct {
	// Clients is the list of assembled OIDC client entries
	Clients []ClientEntry

	// GeneratedSecrets contains secrets that were generated for clients
	GeneratedSecrets map[string]string

	// ConfigYAML is the assembled Authelia configuration YAML
	ConfigYAML string
}

// Assemble processes all OIDCClients and assembles the Authelia configuration
func (a *Assembler) Assemble(ctx context.Context, oidcClients []securityv1alpha1.OIDCClient, oidcSecrets *corev1.Secret, autheliaNamespace string) (*AssemblyResult, error) {
	result := &AssemblyResult{
		Clients:          make([]ClientEntry, 0, len(oidcClients)),
		GeneratedSecrets: make(map[string]string),
	}

	// Sort OIDCClients by ClientID for deterministic output
	sortedClients := make([]securityv1alpha1.OIDCClient, len(oidcClients))
	copy(sortedClients, oidcClients)
	sort.Slice(sortedClients, func(i, j int) bool {
		return sortedClients[i].Spec.ClientID < sortedClients[j].Spec.ClientID
	})

	for _, oc := range sortedClients {
		clientSecret, err := a.resolveClientSecret(ctx, &oc, result.GeneratedSecrets, autheliaNamespace)
		if err != nil {
			return nil, operrors.NewTransientError("failed to resolve client secret", err).
				WithContext("clientId", oc.Spec.ClientID)
		}

		entry := a.buildClientEntry(&oc, clientSecret)
		result.Clients = append(result.Clients, entry)
	}

	// Build the OIDC configuration section
	configYAML, err := a.buildConfigYAML(result.Clients, oidcSecrets)
	if err != nil {
		return nil, operrors.NewPermanentError("failed to build config YAML", err)
	}
	result.ConfigYAML = configYAML

	return result, nil
}

// resolveClientSecret resolves the client secret from secretRef, existing generated secret, or generates a new one
func (a *Assembler) resolveClientSecret(ctx context.Context, oc *securityv1alpha1.OIDCClient, generatedSecrets map[string]string, autheliaNamespace string) (string, error) {
	// Public clients don't need a secret
	if oc.Spec.Public {
		return "", nil
	}

	if oc.Spec.SecretRef != nil {
		// Look up the referenced secret
		namespace := oc.Spec.SecretRef.Namespace
		if namespace == "" {
			namespace = oc.ObjectMeta.Namespace
		}

		secret := &corev1.Secret{}
		err := a.Client.Get(ctx, types.NamespacedName{
			Name:      oc.Spec.SecretRef.Name,
			Namespace: namespace,
		}, secret)
		if err != nil {
			return "", operrors.NewTransientError("failed to get secret", err).
				WithContext("secretName", oc.Spec.SecretRef.Name).
				WithContext("namespace", namespace)
		}

		key := oc.Spec.SecretRef.Key
		if key == "" {
			key = "client_secret"
		}

		secretValue, ok := secret.Data[key]
		if !ok {
			return "", operrors.NewConfigError("key not found in secret", nil).
				WithContext("key", key).
				WithContext("secretName", oc.Spec.SecretRef.Name)
		}

		return string(secretValue), nil
	}

	// Honor the GenerateSecret field - if explicitly set to false, don't generate
	if !oc.Spec.GenerateSecret {
		a.Log.Info("Secret generation disabled for client", "clientId", oc.Spec.ClientID)
		return "", nil
	}

	// Check for existing operator-generated secret
	existingSecretName := fmt.Sprintf("oidc-%s-client", oc.Spec.ClientID)
	existingSecret := &corev1.Secret{}
	err := a.Client.Get(ctx, types.NamespacedName{
		Name:      existingSecretName,
		Namespace: autheliaNamespace,
	}, existingSecret)
	if err == nil {
		// Found existing generated secret, use it
		if secretValue, ok := existingSecret.Data["client_secret"]; ok {
			a.Log.V(1).Info("Using existing generated secret", "clientId", oc.Spec.ClientID)
			return string(secretValue), nil
		}
	}

	// Generate a new secret
	a.Log.Info("Generating new client secret", "clientId", oc.Spec.ClientID)
	clientSecret := generateSecret()
	generatedSecrets[oc.Spec.ClientID] = clientSecret
	return clientSecret, nil
}

// buildClientEntry builds a client entry from an OIDCClient
func (a *Assembler) buildClientEntry(oc *securityv1alpha1.OIDCClient, clientSecret string) ClientEntry {
	// Apply defaults
	scopes := oc.Spec.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "groups"}
	}

	responseTypes := oc.Spec.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	grantTypes := oc.Spec.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	responseModes := oc.Spec.ResponseModes
	if len(responseModes) == 0 {
		responseModes = []string{"form_post", "query", "fragment"}
	}

	userinfoAlg := oc.Spec.UserinfoSignedResponseAlg
	if userinfoAlg == "" {
		userinfoAlg = "none"
	}

	tokenAuthMethod := oc.Spec.TokenEndpointAuthMethod
	if tokenAuthMethod == "" {
		if oc.Spec.Public {
			// Public clients should use "none" for token endpoint auth
			tokenAuthMethod = "none"
		} else {
			tokenAuthMethod = "client_secret_basic"
		}
	}

	pkceChallengeMethod := oc.Spec.PKCEChallengeMethod
	if pkceChallengeMethod == "" {
		pkceChallengeMethod = "S256"
	}

	clientName := oc.Spec.ClientName
	if clientName == "" {
		clientName = oc.Spec.ClientID
	}

	authPolicy := oc.Spec.AuthorizationPolicy
	if authPolicy == "" {
		authPolicy = "two_factor"
	}

	entry := ClientEntry{
		ClientID:                  oc.Spec.ClientID,
		ClientName:                clientName,
		Public:                    oc.Spec.Public,
		AuthorizationPolicy:       authPolicy,
		RedirectURIs:              oc.Spec.RedirectURIs,
		Scopes:                    scopes,
		ResponseTypes:             responseTypes,
		GrantTypes:                grantTypes,
		ResponseModes:             responseModes,
		UserinfoSignedResponseAlg: userinfoAlg,
		TokenEndpointAuthMethod:   tokenAuthMethod,
		RequirePKCE:               oc.Spec.RequirePKCE,
		PKCEChallengeMethod:       pkceChallengeMethod,
	}

	// Set optional fields only if specified
	if oc.Spec.ConsentMode != "" {
		entry.ConsentMode = oc.Spec.ConsentMode
	}

	if oc.Spec.SectorIdentifierURI != "" {
		entry.SectorIdentifierURI = oc.Spec.SectorIdentifierURI
	}

	if len(oc.Spec.Audience) > 0 {
		entry.Audience = oc.Spec.Audience
	}

	if oc.Spec.PreconfiguredConsentDuration != nil {
		entry.PreconfiguredConsentDuration = oc.Spec.PreconfiguredConsentDuration.Duration.String()
	}

	// Only set client secret for non-public clients
	if !oc.Spec.Public && clientSecret != "" {
		entry.ClientSecret = hashSecretPBKDF2(clientSecret, oc.Spec.ClientID)
	}

	return entry
}

// buildConfigYAML builds the Authelia OIDC configuration YAML
func (a *Assembler) buildConfigYAML(clients []ClientEntry, oidcSecrets *corev1.Secret) (string, error) {
	oidcConfig := map[string]interface{}{
		"clients": clients,
	}

	// Add JWKS configuration if secrets are available
	if oidcSecrets != nil {
		privateKey := string(oidcSecrets.Data["issuer_private_key"])
		certChain := string(oidcSecrets.Data["issuer_certificate_chain"])

		if privateKey != "" {
			jwks := []map[string]interface{}{
				{
					"algorithm":         "RS256",
					"use":               "sig",
					"key":               privateKey,
					"certificate_chain": certChain,
				},
			}
			oidcConfig["jwks"] = jwks
		}
	}

	config := map[string]interface{}{
		"identity_providers": map[string]interface{}{
			"oidc": oidcConfig,
		},
	}

	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	return string(yamlBytes), nil
}

// generateSecret generates a random secret
func generateSecret() string {
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return "changeme"
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// PHC B64 encoding: standard base64 with . instead of + and no padding
var phcB64Encoding = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./").WithPadding(base64.NoPadding)

// hashSecretPBKDF2 hashes a secret using PBKDF2-SHA512 in Authelia's expected format
// Format: $pbkdf2-sha512$<iterations>$<salt-b64>$<hash-b64>
// The salt is derived deterministically from the clientId to ensure consistent hashes
// across reconciliations without needing to store salt state.
func hashSecretPBKDF2(secret string, clientId string) string {
	iterations := 310000

	// Derive salt deterministically from clientId using SHA256
	// This ensures the same clientId always produces the same salt
	saltHash := sha512.Sum512([]byte("authelia-oidc-salt:" + clientId))
	saltBytes := saltHash[:16] // Use first 16 bytes as salt

	hash := pbkdf2.Key([]byte(secret), saltBytes, iterations, 64, sha512.New)

	saltB64 := phcB64Encoding.EncodeToString(saltBytes)
	hashB64 := phcB64Encoding.EncodeToString(hash)

	return fmt.Sprintf("$pbkdf2-sha512$%d$%s$%s", iterations, saltB64, hashB64)
}
