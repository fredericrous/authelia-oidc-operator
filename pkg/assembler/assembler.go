package assembler

import (
	"cmp"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/pbkdf2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
	operrors "github.com/fredericrous/homelab/authelia-oidc-operator/pkg/errors"
)

// Assembler handles OIDC configuration assembly for Authelia
type Assembler struct {
	Client client.Client
	Log    logr.Logger
}

// NewAssembler creates a new Assembler
func NewAssembler(client client.Client, log logr.Logger) *Assembler {
	return &Assembler{Client: client, Log: log}
}

// ClientEntry represents an OIDC client entry for Authelia configuration
type ClientEntry struct {
	ClientID                     string   `json:"client_id"`
	ClientName                   string   `json:"client_name"`
	ClientSecret                 string   `json:"client_secret,omitempty"`
	Public                       bool     `json:"public,omitempty"`
	AuthorizationPolicy          string   `json:"authorization_policy,omitempty"`
	ClaimsPolicy                 string   `json:"claims_policy,omitempty"`
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
	AccessTokenSignedResponseAlg string   `json:"access_token_signed_response_alg,omitempty"`
	TokenEndpointAuthMethod      string   `json:"token_endpoint_auth_method"`
	RequirePKCE                  bool     `json:"require_pkce,omitempty"`
	PKCEChallengeMethod          string   `json:"pkce_challenge_method,omitempty"`
}

// ClaimsPolicyEntry represents a claims policy entry for Authelia configuration
type ClaimsPolicyEntry struct {
	IDToken       []string               `json:"id_token,omitempty"`
	Userinfo      []string               `json:"userinfo,omitempty"`
	AccessToken   []string               `json:"access_token,omitempty"`
	Introspection []string               `json:"introspection,omitempty"`
	CustomClaims  map[string]any `json:"custom_claims,omitempty"`
}

// ScopeEntry represents a custom scope entry for Authelia configuration
type ScopeEntry struct {
	Claims []string `json:"claims"`
}

// UserAttributeEntry represents a user attribute entry for Authelia configuration
type UserAttributeEntry struct {
	Expression string `json:"expression"`
}

// AssemblyResult contains the result of OIDC configuration assembly
type AssemblyResult struct {
	Clients        []ClientEntry
	ClaimsPolicies map[string]ClaimsPolicyEntry
	Scopes         map[string]ScopeEntry
	UserAttributes map[string]UserAttributeEntry
	JWKS           []map[string]any
	ConfigYAML     string
}

// Default values for OIDC clients
var (
	defaultScopes        = []string{"openid", "profile", "email", "groups"}
	defaultResponseTypes = []string{"code"}
	defaultGrantTypes    = []string{"authorization_code"}
	defaultResponseModes = []string{"form_post", "query", "fragment"}
)

// Assemble processes all OIDCClients, ClaimsPolicies, and UserAttributes
// and assembles the Authelia configuration
func (a *Assembler) Assemble(
	ctx context.Context,
	oidcClients []securityv1alpha1.OIDCClient,
	claimsPolicies []securityv1alpha1.ClaimsPolicy,
	userAttributes []securityv1alpha1.UserAttribute,
	oidcSecrets *corev1.Secret,
) (*AssemblyResult, error) {
	// Validate all references and collisions
	if err := a.validate(oidcClients, claimsPolicies, userAttributes); err != nil {
		return nil, err
	}

	result := &AssemblyResult{
		Clients:        make([]ClientEntry, 0, len(oidcClients)),
		ClaimsPolicies: a.buildClaimsPolicies(claimsPolicies),
		Scopes:         a.buildScopes(claimsPolicies),
		UserAttributes: a.buildUserAttributes(userAttributes),
		JWKS:           a.buildJWKS(oidcSecrets),
	}

	// Build clients (sorted by ClientID for deterministic output)
	sortedClients := slices.Clone(oidcClients)
	slices.SortFunc(sortedClients, func(a, b securityv1alpha1.OIDCClient) int {
		return cmp.Compare(a.Spec.ClientID, b.Spec.ClientID)
	})

	for _, oc := range sortedClients {
		clientSecret, err := a.resolveClientSecret(ctx, &oc)
		if err != nil {
			return nil, operrors.NewTransientError("failed to resolve client secret", err).
				WithContext("clientId", oc.Spec.ClientID)
		}
		result.Clients = append(result.Clients, a.buildClientEntry(&oc, clientSecret))
	}

	// Build the OIDC configuration section
	configYAML, err := a.buildConfigYAML(result)
	if err != nil {
		return nil, operrors.NewPermanentError("failed to build config YAML", err)
	}
	result.ConfigYAML = configYAML

	return result, nil
}

// validate runs all validation checks
func (a *Assembler) validate(
	oidcClients []securityv1alpha1.OIDCClient,
	claimsPolicies []securityv1alpha1.ClaimsPolicy,
	userAttributes []securityv1alpha1.UserAttribute,
) error {
	validators := []func() error{
		func() error { return a.DetectPolicyNameCollisions(claimsPolicies) },
		func() error { return a.DetectAttributeNameCollisions(userAttributes) },
		func() error { return a.DetectScopeNameCollisions(claimsPolicies) },
		func() error { return a.ValidateClaimsPolicies(claimsPolicies, userAttributes) },
		func() error { return a.ValidateOIDCClientPolicies(oidcClients, claimsPolicies) },
	}

	for _, validate := range validators {
		if err := validate(); err != nil {
			return operrors.NewConfigError(err.Error(), nil)
		}
	}
	return nil
}

// buildUserAttributes transforms UserAttribute CRDs to config entries
func (a *Assembler) buildUserAttributes(attrs []securityv1alpha1.UserAttribute) map[string]UserAttributeEntry {
	result := make(map[string]UserAttributeEntry, len(attrs))
	for i := range attrs {
		attr := &attrs[i]
		result[attr.GetResolvedName()] = UserAttributeEntry{Expression: attr.Spec.Expression}
	}
	return result
}

// buildClaimsPolicies transforms ClaimsPolicy CRDs to config entries
func (a *Assembler) buildClaimsPolicies(policies []securityv1alpha1.ClaimsPolicy) map[string]ClaimsPolicyEntry {
	result := make(map[string]ClaimsPolicyEntry, len(policies))
	for i := range policies {
		policy := &policies[i]
		result[policy.GetResolvedName()] = a.buildClaimsPolicyEntry(policy)
	}
	return result
}

// buildScopes extracts custom scopes from ClaimsPolicy CRDs
func (a *Assembler) buildScopes(policies []securityv1alpha1.ClaimsPolicy) map[string]ScopeEntry {
	result := make(map[string]ScopeEntry)
	for i := range policies {
		policy := &policies[i]
		if policy.Spec.CustomScope != nil {
			result[policy.GetScopeName()] = ScopeEntry{Claims: policy.Spec.CustomScope.Claims}
		}
	}
	return result
}

// buildJWKS creates JWKS configuration from secrets
func (a *Assembler) buildJWKS(secrets *corev1.Secret) []map[string]any {
	if secrets == nil {
		return nil
	}

	privateKey := string(secrets.Data["issuer_private_key"])
	if privateKey == "" {
		return nil
	}

	return []map[string]any{{
		"algorithm":         "RS256",
		"use":               "sig",
		"key":               privateKey,
		"certificate_chain": string(secrets.Data["issuer_certificate_chain"]),
	}}
}

// buildClaimsPolicyEntry builds a claims policy entry from a ClaimsPolicy CRD
func (a *Assembler) buildClaimsPolicyEntry(policy *securityv1alpha1.ClaimsPolicy) ClaimsPolicyEntry {
	entry := ClaimsPolicyEntry{
		IDToken:       nonEmpty(policy.Spec.IDToken),
		Userinfo:      nonEmpty(policy.Spec.Userinfo),
		AccessToken:   nonEmpty(policy.Spec.AccessToken),
		Introspection: nonEmpty(policy.Spec.Introspection),
	}

	// CustomClaims are empty maps referencing user attributes
	if len(policy.Spec.CustomClaims) > 0 {
		entry.CustomClaims = make(map[string]any, len(policy.Spec.CustomClaims))
		for _, claim := range policy.Spec.CustomClaims {
			entry.CustomClaims[normalizeToSnakeCase(claim)] = map[string]any{}
		}
	}

	return entry
}

// resolveClientSecret resolves the client secret from secretRef
func (a *Assembler) resolveClientSecret(ctx context.Context, oc *securityv1alpha1.OIDCClient) (string, error) {
	if oc.Spec.Public {
		return "", nil
	}

	if oc.Spec.SecretRef == nil {
		return "", operrors.NewConfigError("confidential client requires secretRef", nil).
			WithContext("clientId", oc.Spec.ClientID).
			WithContext("hint", "use ExternalSecrets to manage the client secret and reference it via secretRef")
	}

	namespace := cmp.Or(oc.Spec.SecretRef.Namespace, oc.ObjectMeta.Namespace)

	secret := &corev1.Secret{}
	if err := a.Client.Get(ctx, types.NamespacedName{Name: oc.Spec.SecretRef.Name, Namespace: namespace}, secret); err != nil {
		return "", operrors.NewTransientError("failed to get secret", err).
			WithContext("secretName", oc.Spec.SecretRef.Name).
			WithContext("namespace", namespace)
	}

	key := cmp.Or(oc.Spec.SecretRef.Key, "client_secret")
	secretValue, ok := secret.Data[key]
	if !ok {
		return "", operrors.NewConfigError("key not found in secret", nil).
			WithContext("key", key).
			WithContext("secretName", oc.Spec.SecretRef.Name)
	}

	return string(secretValue), nil
}

// buildClientEntry builds a client entry from an OIDCClient
func (a *Assembler) buildClientEntry(oc *securityv1alpha1.OIDCClient, clientSecret string) ClientEntry {
	spec := &oc.Spec

	// Merge scopes with extraScopes, deduplicated
	scopes := orSlice(spec.Scopes, defaultScopes)
	if len(spec.ExtraScopes) > 0 {
		scopes = unique(append(slices.Clone(scopes), spec.ExtraScopes...))
	}

	// Determine token endpoint auth method based on client type
	tokenAuthMethod := spec.TokenEndpointAuthMethod
	if tokenAuthMethod == "" {
		if spec.Public {
			tokenAuthMethod = "none"
		} else {
			tokenAuthMethod = "client_secret_basic"
		}
	}

	// PKCE challenge method only set if PKCE is required
	var pkceChallengeMethod string
	if spec.RequirePKCE {
		pkceChallengeMethod = cmp.Or(spec.PKCEChallengeMethod, "S256")
	}

	entry := ClientEntry{
		ClientID:                  spec.ClientID,
		ClientName:                cmp.Or(spec.ClientName, spec.ClientID),
		Public:                    spec.Public,
		AuthorizationPolicy:       cmp.Or(spec.AuthorizationPolicy, "two_factor"),
		RedirectURIs:              spec.RedirectURIs,
		Scopes:                    scopes,
		ResponseTypes:             orSlice(spec.ResponseTypes, defaultResponseTypes),
		GrantTypes:                orSlice(spec.GrantTypes, defaultGrantTypes),
		ResponseModes:             orSlice(spec.ResponseModes, defaultResponseModes),
		UserinfoSignedResponseAlg: cmp.Or(spec.UserinfoSignedResponseAlg, "none"),
		TokenEndpointAuthMethod:   tokenAuthMethod,
		RequirePKCE:               spec.RequirePKCE,
		PKCEChallengeMethod:       pkceChallengeMethod,
		// Optional fields
		ConsentMode:                  spec.ConsentMode,
		ClaimsPolicy:                 spec.ClaimsPolicy,
		SectorIdentifierURI:          spec.SectorIdentifierURI,
		Audience:                     spec.Audience,
		AccessTokenSignedResponseAlg: spec.AccessTokenSignedResponseAlg,
	}

	if spec.PreconfiguredConsentDuration != nil {
		entry.PreconfiguredConsentDuration = spec.PreconfiguredConsentDuration.Duration.String()
	}

	if !spec.Public && clientSecret != "" {
		entry.ClientSecret = hashSecretPBKDF2(clientSecret, spec.ClientID)
	}

	return entry
}

// buildConfigYAML builds the Authelia OIDC configuration YAML
func (a *Assembler) buildConfigYAML(result *AssemblyResult) (string, error) {
	oidcConfig := map[string]any{
		"clients": result.Clients,
	}

	// Only add non-empty maps
	if len(result.ClaimsPolicies) > 0 {
		oidcConfig["claims_policies"] = result.ClaimsPolicies
	}
	if len(result.Scopes) > 0 {
		oidcConfig["scopes"] = result.Scopes
	}
	if len(result.JWKS) > 0 {
		oidcConfig["jwks"] = result.JWKS
	}

	config := map[string]any{
		"identity_providers": map[string]any{
			"oidc": oidcConfig,
		},
	}

	if len(result.UserAttributes) > 0 {
		config["definitions"] = map[string]any{
			"user_attributes": result.UserAttributes,
		}
	}

	yamlBytes, err := yaml.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config: %w", err)
	}

	return string(yamlBytes), nil
}

// PHC B64 encoding: standard base64 without padding (RFC 4648)
var phcB64Encoding = base64.RawStdEncoding

// hashSecretPBKDF2 hashes a secret using PBKDF2-SHA512 in Authelia's expected format
func hashSecretPBKDF2(secret, clientID string) string {
	const iterations = 310000

	// Derive salt deterministically from clientId
	saltHash := sha512.Sum512([]byte("authelia-oidc-salt:" + clientID))
	saltBytes := saltHash[:16]

	hash := pbkdf2.Key([]byte(secret), saltBytes, iterations, 64, sha512.New)

	return fmt.Sprintf("$pbkdf2-sha512$%d$%s$%s",
		iterations,
		phcB64Encoding.EncodeToString(saltBytes),
		phcB64Encoding.EncodeToString(hash),
	)
}

// unique returns a deduplicated slice preserving order
func unique[T comparable](items []T) []T {
	seen := make(map[T]struct{}, len(items))
	result := make([]T, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// nonEmpty returns nil if the slice is empty, otherwise returns the slice
func nonEmpty[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	return s
}

// orSlice returns the first non-empty slice, similar to cmp.Or but for slices
func orSlice[T any](slices ...[]T) []T {
	for _, s := range slices {
		if len(s) > 0 {
			return s
		}
	}
	return nil
}
