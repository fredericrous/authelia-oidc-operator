package assembler

import (
	"fmt"
	"slices"
	"strings"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
)

// NameResolver extracts a resolved name from a resource
type NameResolver[T any] func(*T) string

// KeyResolver extracts a unique key (namespace/name) from a resource
type KeyResolver[T any] func(*T) string

// detectCollisions is a generic collision detector for any resource type
func detectCollisions[T any](
	items []T,
	resolveName NameResolver[T],
	resolveKey KeyResolver[T],
	errPrefix string,
) error {
	seen := make(map[string]string, len(items))
	for i := range items {
		item := &items[i]
		name := resolveName(item)
		key := resolveKey(item)
		if existing, ok := seen[name]; ok {
			return fmt.Errorf("%s name collision: %s and %s both resolve to %q", errPrefix, existing, key, name)
		}
		seen[name] = key
	}
	return nil
}

// ValidateClaimsPolicies validates all claims policies and their references
func (a *Assembler) ValidateClaimsPolicies(
	policies []securityv1alpha1.ClaimsPolicy,
	userAttrs []securityv1alpha1.UserAttribute,
) error {
	// Build lookup set: namespace -> set of resolved attribute names
	attrsByNamespace := make(map[string]map[string]struct{}, len(userAttrs))
	for i := range userAttrs {
		attr := &userAttrs[i]
		if attrsByNamespace[attr.Namespace] == nil {
			attrsByNamespace[attr.Namespace] = make(map[string]struct{})
		}
		attrsByNamespace[attr.Namespace][attr.GetResolvedName()] = struct{}{}
	}

	// Validate each policy's custom claims references
	for i := range policies {
		policy := &policies[i]
		nsAttrs := attrsByNamespace[policy.Namespace]

		for _, claimName := range policy.Spec.CustomClaims {
			attrName := normalizeToSnakeCase(claimName)
			if _, exists := nsAttrs[attrName]; !exists {
				return fmt.Errorf("ClaimsPolicy %s/%s: customClaim %q references non-existent UserAttribute in namespace %s",
					policy.Namespace, policy.Name, claimName, policy.Namespace)
			}
		}
	}
	return nil
}

// ValidateOIDCClientPolicies validates that OIDCClient.claimsPolicy references exist
func (a *Assembler) ValidateOIDCClientPolicies(
	clients []securityv1alpha1.OIDCClient,
	policies []securityv1alpha1.ClaimsPolicy,
) error {
	// Build lookup set: namespace -> set of resolved policy names
	policiesByNamespace := make(map[string]map[string]struct{}, len(policies))
	for i := range policies {
		policy := &policies[i]
		if policiesByNamespace[policy.Namespace] == nil {
			policiesByNamespace[policy.Namespace] = make(map[string]struct{})
		}
		policiesByNamespace[policy.Namespace][policy.GetResolvedName()] = struct{}{}
	}

	// Find first client with invalid policy reference
	for i := range clients {
		client := &clients[i]
		if client.Spec.ClaimsPolicy == "" {
			continue
		}
		nsPolicies := policiesByNamespace[client.Namespace]
		if _, exists := nsPolicies[client.Spec.ClaimsPolicy]; !exists {
			return fmt.Errorf("OIDCClient %s/%s: claimsPolicy %q not found in namespace %s (must be in same namespace)",
				client.Namespace, client.Name, client.Spec.ClaimsPolicy, client.Namespace)
		}
	}
	return nil
}

// DetectPolicyNameCollisions checks for duplicate resolved names among policies
func (a *Assembler) DetectPolicyNameCollisions(policies []securityv1alpha1.ClaimsPolicy) error {
	return detectCollisions(
		policies,
		func(p *securityv1alpha1.ClaimsPolicy) string { return p.GetResolvedName() },
		func(p *securityv1alpha1.ClaimsPolicy) string { return p.Namespace + "/" + p.Name },
		"ClaimsPolicy",
	)
}

// DetectAttributeNameCollisions checks for duplicate resolved names among user attributes
func (a *Assembler) DetectAttributeNameCollisions(attrs []securityv1alpha1.UserAttribute) error {
	return detectCollisions(
		attrs,
		func(a *securityv1alpha1.UserAttribute) string { return a.GetResolvedName() },
		func(a *securityv1alpha1.UserAttribute) string { return a.Namespace + "/" + a.Name },
		"UserAttribute",
	)
}

// DetectScopeNameCollisions checks for duplicate scope names
func (a *Assembler) DetectScopeNameCollisions(policies []securityv1alpha1.ClaimsPolicy) error {
	// Filter to only policies with custom scopes
	withScopes := slices.DeleteFunc(slices.Clone(policies), func(p securityv1alpha1.ClaimsPolicy) bool {
		return p.Spec.CustomScope == nil
	})

	return detectCollisions(
		withScopes,
		func(p *securityv1alpha1.ClaimsPolicy) string { return p.GetScopeName() },
		func(p *securityv1alpha1.ClaimsPolicy) string { return p.Namespace + "/" + p.Name },
		"CustomScope",
	)
}

// ValidateAccessControlSubjects validates subject format in access control specs
func (a *Assembler) ValidateAccessControlSubjects(clients []securityv1alpha1.OIDCClient) error {
	for i := range clients {
		client := &clients[i]
		if client.Spec.AccessControl == nil {
			continue
		}

		for _, subject := range client.Spec.AccessControl.Subjects {
			if !strings.HasPrefix(subject, "group:") && !strings.HasPrefix(subject, "user:") {
				return fmt.Errorf("OIDCClient %s/%s: invalid access control subject %q (must start with 'group:' or 'user:')",
					client.Namespace, client.Name, subject)
			}
		}
	}
	return nil
}

// normalizeToSnakeCase converts a name to snake_case (hyphens to underscores)
func normalizeToSnakeCase(name string) string {
	return strings.ReplaceAll(name, "-", "_")
}
