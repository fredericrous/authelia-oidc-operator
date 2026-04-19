package assembler

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	securityv1alpha1 "github.com/fredericrous/homelab/authelia-oidc-operator/api/v1alpha1"
)

// clientWithAC returns an OIDCClient with an AccessControl spec. A separate
// helper from validation_test.go's oidcClient because we need direct control
// over domain/policy/subjects here.
func clientWithAC(name, domain, policy string, subjects ...string) securityv1alpha1.OIDCClient {
	return securityv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns1"},
		Spec: securityv1alpha1.OIDCClientSpec{
			AccessControl: &securityv1alpha1.AccessControlSpec{
				Domain:   domain,
				Policy:   policy,
				Subjects: subjects,
			},
		},
	}
}

func TestBuildAccessControlRules(t *testing.T) {
	a := &Assembler{}

	t.Run("clients without access control are skipped", func(t *testing.T) {
		got := a.buildAccessControlRules([]securityv1alpha1.OIDCClient{
			{ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "ns1"}},
		})
		if len(got) != 0 {
			t.Errorf("expected no rules, got %v", got)
		}
	})

	t.Run("default policy is two_factor", func(t *testing.T) {
		got := a.buildAccessControlRules([]securityv1alpha1.OIDCClient{
			clientWithAC("a", "a.test", "", "user:alice"),
		})
		if len(got) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(got))
		}
		if got[0].Policy != "two_factor" {
			t.Errorf("default policy should be two_factor, got %q", got[0].Policy)
		}
	})

	t.Run("single subject becomes scalar; multiple stay a list", func(t *testing.T) {
		got := a.buildAccessControlRules([]securityv1alpha1.OIDCClient{
			clientWithAC("single", "single.test", "one_factor", "user:alice"),
			clientWithAC("many", "many.test", "one_factor", "user:alice", "group:admin"),
		})
		// Rules sort alphabetically by domain.
		byDomain := map[string]AccessControlRule{}
		for _, r := range got {
			byDomain[r.Domain] = r
		}
		if s, ok := byDomain["single.test"].Subject.(string); !ok || s != "user:alice" {
			t.Errorf("single subject should be a string, got %T %v", byDomain["single.test"].Subject, byDomain["single.test"].Subject)
		}
		if l, ok := byDomain["many.test"].Subject.([]string); !ok || !reflect.DeepEqual(l, []string{"user:alice", "group:admin"}) {
			t.Errorf("multi-subject should stay a list, got %T %v", byDomain["many.test"].Subject, byDomain["many.test"].Subject)
		}
	})

	t.Run("wildcards sort after specific domains; specifics alphabetical", func(t *testing.T) {
		got := a.buildAccessControlRules([]securityv1alpha1.OIDCClient{
			clientWithAC("c", "*.daddyshome.fr", "one_factor", "user:x"),
			clientWithAC("a", "zeta.daddyshome.fr", "one_factor", "user:x"),
			clientWithAC("b", "alpha.daddyshome.fr", "one_factor", "user:x"),
		})
		if len(got) != 3 {
			t.Fatalf("expected 3 rules, got %d", len(got))
		}
		// Specific alphabetical first, then wildcard.
		wantOrder := []string{"alpha.daddyshome.fr", "zeta.daddyshome.fr", "*.daddyshome.fr"}
		for i, w := range wantOrder {
			if got[i].Domain != w {
				t.Errorf("rule[%d].Domain = %q, want %q (full order: %v)",
					i, got[i].Domain, w, rulesDomains(got))
			}
		}
	})
}

func rulesDomains(rules []AccessControlRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Domain)
	}
	return out
}
