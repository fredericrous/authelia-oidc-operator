package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHyphenToUnderscore(t *testing.T) {
	cases := map[string]string{
		"plain":      "plain",
		"with-dash":  "with_dash",
		"a-b-c":      "a_b_c",
		"":           "",
		"trailing-":  "trailing_",
		"already_ok": "already_ok",
	}
	for in, want := range cases {
		if got := hyphenToUnderscore(in); got != want {
			t.Errorf("hyphenToUnderscore(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClaimsPolicy_GetResolvedName(t *testing.T) {
	tests := []struct {
		name string
		p    ClaimsPolicy
		want string
	}{
		{
			"explicit policyName takes precedence",
			ClaimsPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "my-policy"},
				Spec:       ClaimsPolicySpec{PolicyName: "override_name"},
			},
			"override_name",
		},
		{
			"falls back to metadata.name with hyphens converted",
			ClaimsPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "full-profile"},
			},
			"full_profile",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.GetResolvedName(); got != tc.want {
				t.Errorf("GetResolvedName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClaimsPolicy_GetScopeName(t *testing.T) {
	tests := []struct {
		name string
		p    ClaimsPolicy
		want string
	}{
		{
			"no custom scope returns empty",
			ClaimsPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "p"},
			},
			"",
		},
		{
			"explicit scopeName takes precedence",
			ClaimsPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "p"},
				Spec: ClaimsPolicySpec{
					CustomScope: &CustomScopeSpec{ScopeName: "my_scope"},
				},
			},
			"my_scope",
		},
		{
			"falls back to resolved policy name when scope has no explicit name",
			ClaimsPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "my-policy"},
				Spec: ClaimsPolicySpec{
					CustomScope: &CustomScopeSpec{},
				},
			},
			"my_policy",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.GetScopeName(); got != tc.want {
				t.Errorf("GetScopeName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUserAttribute_GetResolvedName(t *testing.T) {
	tests := []struct {
		name string
		u    UserAttribute
		want string
	}{
		{
			"explicit attributeName takes precedence",
			UserAttribute{
				ObjectMeta: metav1.ObjectMeta{Name: "full-name"},
				Spec:       UserAttributeSpec{AttributeName: "given_name"},
			},
			"given_name",
		},
		{
			"falls back to metadata.name with hyphens converted",
			UserAttribute{
				ObjectMeta: metav1.ObjectMeta{Name: "phone-number"},
			},
			"phone_number",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.u.GetResolvedName(); got != tc.want {
				t.Errorf("GetResolvedName() = %q, want %q", got, tc.want)
			}
		})
	}
}
