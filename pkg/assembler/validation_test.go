package assembler

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
)

// --- fixtures ---

func policy(ns, name, resolvedName string, customScope *securityv1alpha1.CustomScopeSpec) securityv1alpha1.ClaimsPolicy {
	return securityv1alpha1.ClaimsPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: securityv1alpha1.ClaimsPolicySpec{
			PolicyName:  resolvedName,
			CustomScope: customScope,
		},
	}
}

func attr(ns, name string) securityv1alpha1.UserAttribute {
	return securityv1alpha1.UserAttribute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
	}
}

func oidcClient(ns, name, claimsPolicy string, subjects ...string) securityv1alpha1.OIDCClient {
	c := securityv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: securityv1alpha1.OIDCClientSpec{
			ClaimsPolicy: claimsPolicy,
		},
	}
	if len(subjects) > 0 {
		c.Spec.AccessControl = &securityv1alpha1.AccessControlSpec{
			Subjects: subjects,
		}
	}
	return c
}

// --- normalizeToSnakeCase ---

func TestNormalizeToSnakeCase(t *testing.T) {
	cases := map[string]string{
		"simple":        "simple",
		"with-dash":     "with_dash",
		"a-b-c":         "a_b_c",
		"":              "",
		"already_snake": "already_snake",
	}
	for in, want := range cases {
		if got := normalizeToSnakeCase(in); got != want {
			t.Errorf("normalizeToSnakeCase(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- DetectPolicyNameCollisions / AttributeNameCollisions / ScopeNameCollisions ---

func TestDetectPolicyNameCollisions(t *testing.T) {
	a := &Assembler{}

	// No collisions when names differ.
	if err := a.DetectPolicyNameCollisions([]securityv1alpha1.ClaimsPolicy{
		policy("ns1", "a", "policy_a", nil),
		policy("ns2", "b", "policy_b", nil),
	}); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Collision when two policies resolve to the same name, even across namespaces.
	err := a.DetectPolicyNameCollisions([]securityv1alpha1.ClaimsPolicy{
		policy("ns1", "foo", "shared_name", nil),
		policy("ns2", "bar", "shared_name", nil),
	})
	if err == nil || !strings.Contains(err.Error(), "ClaimsPolicy") {
		t.Errorf("expected ClaimsPolicy collision error, got %v", err)
	}
}

func TestDetectAttributeNameCollisions(t *testing.T) {
	a := &Assembler{}

	if err := a.DetectAttributeNameCollisions([]securityv1alpha1.UserAttribute{
		attr("ns1", "a"),
		attr("ns2", "b"),
	}); err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Same name across namespaces → collision on the resolved name.
	err := a.DetectAttributeNameCollisions([]securityv1alpha1.UserAttribute{
		attr("ns1", "email"),
		attr("ns2", "email"),
	})
	if err == nil || !strings.Contains(err.Error(), "UserAttribute") {
		t.Errorf("expected UserAttribute collision error, got %v", err)
	}
}

func TestDetectScopeNameCollisions(t *testing.T) {
	a := &Assembler{}
	scope := &securityv1alpha1.CustomScopeSpec{ScopeName: "myscope"}

	// Policies without custom scopes are ignored.
	if err := a.DetectScopeNameCollisions([]securityv1alpha1.ClaimsPolicy{
		policy("ns1", "a", "a_name", nil),
		policy("ns2", "b", "b_name", nil),
	}); err != nil {
		t.Errorf("policies without custom scope should not collide, got %v", err)
	}

	// Two policies with the same scope name collide.
	err := a.DetectScopeNameCollisions([]securityv1alpha1.ClaimsPolicy{
		policy("ns1", "a", "a_name", scope),
		policy("ns2", "b", "b_name", scope),
	})
	if err == nil || !strings.Contains(err.Error(), "CustomScope") {
		t.Errorf("expected CustomScope collision error, got %v", err)
	}
}

// --- ValidateClaimsPolicies ---

func TestValidateClaimsPolicies(t *testing.T) {
	a := &Assembler{}

	attrs := []securityv1alpha1.UserAttribute{
		attr("ns1", "email"),
		attr("ns1", "full-name"), // resolves to full_name via snake_case
	}

	t.Run("valid references", func(t *testing.T) {
		policies := []securityv1alpha1.ClaimsPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns1"},
			Spec:       securityv1alpha1.ClaimsPolicySpec{CustomClaims: []string{"email", "full-name"}},
		}}
		if err := a.ValidateClaimsPolicies(policies, attrs); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("reference to non-existent attribute", func(t *testing.T) {
		policies := []securityv1alpha1.ClaimsPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns1"},
			Spec:       securityv1alpha1.ClaimsPolicySpec{CustomClaims: []string{"missing"}},
		}}
		err := a.ValidateClaimsPolicies(policies, attrs)
		if err == nil || !strings.Contains(err.Error(), "non-existent UserAttribute") {
			t.Errorf("expected non-existent UserAttribute error, got %v", err)
		}
	})

	t.Run("policy in different namespace than attribute", func(t *testing.T) {
		policies := []securityv1alpha1.ClaimsPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns2"},
			Spec:       securityv1alpha1.ClaimsPolicySpec{CustomClaims: []string{"email"}},
		}}
		err := a.ValidateClaimsPolicies(policies, attrs)
		if err == nil {
			t.Errorf("UserAttribute in ns1 must not satisfy policy in ns2")
		}
	})
}

// --- ValidateOIDCClientPolicies ---

func TestValidateOIDCClientPolicies(t *testing.T) {
	a := &Assembler{}
	policies := []securityv1alpha1.ClaimsPolicy{
		policy("ns1", "p", "p", nil),
	}

	t.Run("no claimsPolicy set — no validation", func(t *testing.T) {
		if err := a.ValidateOIDCClientPolicies([]securityv1alpha1.OIDCClient{
			oidcClient("ns1", "c", ""),
		}, policies); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("matching policy in same namespace", func(t *testing.T) {
		if err := a.ValidateOIDCClientPolicies([]securityv1alpha1.OIDCClient{
			oidcClient("ns1", "c", "p"),
		}, policies); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("missing policy", func(t *testing.T) {
		err := a.ValidateOIDCClientPolicies([]securityv1alpha1.OIDCClient{
			oidcClient("ns1", "c", "nonexistent"),
		}, policies)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected not-found error, got %v", err)
		}
	})

	t.Run("policy exists but in wrong namespace", func(t *testing.T) {
		err := a.ValidateOIDCClientPolicies([]securityv1alpha1.OIDCClient{
			oidcClient("ns2", "c", "p"),
		}, policies)
		if err == nil {
			t.Errorf("expected error — ClaimsPolicy must be in same namespace as OIDCClient")
		}
	})
}

// --- ValidateAccessControlSubjects ---

func TestValidateAccessControlSubjects(t *testing.T) {
	a := &Assembler{}

	t.Run("valid subjects", func(t *testing.T) {
		if err := a.ValidateAccessControlSubjects([]securityv1alpha1.OIDCClient{
			oidcClient("ns1", "c", "", "group:admin", "user:alice"),
		}); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("no access control — skipped", func(t *testing.T) {
		if err := a.ValidateAccessControlSubjects([]securityv1alpha1.OIDCClient{
			oidcClient("ns1", "c", ""),
		}); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("bare name is invalid", func(t *testing.T) {
		err := a.ValidateAccessControlSubjects([]securityv1alpha1.OIDCClient{
			oidcClient("ns1", "c", "", "admin"),
		})
		if err == nil || !strings.Contains(err.Error(), "group:") {
			t.Errorf("expected invalid-subject error, got %v", err)
		}
	})
}
