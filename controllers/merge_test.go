package controllers

import (
	"context"
	"testing"

	"sigs.k8s.io/yaml"
)

// --- trivial extractors ---

func TestGetClientID(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"present", map[string]any{"client_id": "duro"}, "duro"},
		{"missing", map[string]any{}, ""},
		{"wrong type", map[string]any{"client_id": 42}, ""},
		{"not a map", "string", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getClientID(tc.in); got != tc.want {
				t.Errorf("getClientID(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGetRuleDomain(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"present", map[string]any{"domain": "auth.daddyshome.fr"}, "auth.daddyshome.fr"},
		{"missing", map[string]any{}, ""},
		{"nested list type", []any{"a", "b"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getRuleDomain(tc.in); got != tc.want {
				t.Errorf("getRuleDomain(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// --- setters create nested structure as needed ---

func TestSetClients_CreatesNestedPaths(t *testing.T) {
	cfg := map[string]any{}
	setClients(cfg, []any{
		map[string]any{"client_id": "a"},
	})
	clients := getClients(cfg)
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %v", clients)
	}
	if getClientID(clients[0]) != "a" {
		t.Errorf("expected client 'a', got %v", clients[0])
	}
}

func TestSetAccessControlRules_CreatesNestedPaths(t *testing.T) {
	cfg := map[string]any{}
	setAccessControlRules(cfg, []any{
		map[string]any{"domain": "foo.test"},
	})
	rules := getAccessControlRules(cfg)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %v", rules)
	}
	if getRuleDomain(rules[0]) != "foo.test" {
		t.Errorf("expected domain 'foo.test', got %v", rules[0])
	}
}

// --- sort ordering: specific before wildcard, alphabetical within ---

func TestSortAccessControlRules(t *testing.T) {
	rules := []any{
		map[string]any{"domain": "*.daddyshome.fr"},
		map[string]any{"domain": "auth.daddyshome.fr"},
		map[string]any{"domain": "drive.daddyshome.fr"},
	}
	sortAccessControlRules(rules)

	// Wildcards should be last.
	last := getRuleDomain(rules[len(rules)-1])
	if last != "*.daddyshome.fr" {
		t.Errorf("wildcard rule should be last, got order: %v", rules)
	}
	// Non-wildcard rules should be alphabetical.
	if getRuleDomain(rules[0]) != "auth.daddyshome.fr" || getRuleDomain(rules[1]) != "drive.daddyshome.fr" {
		t.Errorf("non-wildcard rules should sort alphabetically, got: %v", rules)
	}
}

// --- full merge logic ---

func TestMergeClientsByID(t *testing.T) {
	base := []byte(`
identity_providers:
  oidc:
    clients:
      - client_id: base_only
        name: Base Only
      - client_id: shared
        name: Base Shared
`)
	crd := []byte(`
identity_providers:
  oidc:
    clients:
      - client_id: shared
        name: CRD Shared
      - client_id: crd_only
        name: CRD Only
`)
	// mergedYAML is what the caller already computed — for this test, an empty skeleton.
	merged := []byte("{}")

	r := &OIDCClientReconciler{}
	got, err := r.mergeClientsByID(base, crd, merged)
	if err != nil {
		t.Fatalf("merge err: %v", err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	clients := getClients(out)

	ids := make(map[string]string, len(clients))
	for _, c := range clients {
		if m, ok := c.(map[string]any); ok {
			if id, ok := m["client_id"].(string); ok {
				if name, ok := m["name"].(string); ok {
					ids[id] = name
				}
			}
		}
	}

	if ids["base_only"] != "Base Only" {
		t.Errorf("base_only should be preserved, got %q", ids["base_only"])
	}
	if ids["shared"] != "CRD Shared" {
		t.Errorf("CRD should win for shared id, got %q (expected 'CRD Shared')", ids["shared"])
	}
	if ids["crd_only"] != "CRD Only" {
		t.Errorf("crd_only should be present, got %q", ids["crd_only"])
	}
	if len(ids) != 3 {
		t.Errorf("expected 3 clients, got %d: %v", len(ids), ids)
	}
}

func TestMergeAccessControlRules(t *testing.T) {
	base := []byte(`
access_control:
  rules:
    - domain: base-only.test
      policy: one_factor
    - domain: shared.test
      policy: deny
`)
	crd := []byte(`
access_control:
  rules:
    - domain: shared.test
      policy: two_factor
    - domain: crd-only.test
      policy: one_factor
`)
	merged := []byte("{}")

	r := &OIDCClientReconciler{}
	got, err := r.mergeAccessControlRules(context.Background(), base, crd, merged)
	if err != nil {
		t.Fatalf("merge err: %v", err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rules := getAccessControlRules(out)
	// All three domains present.
	seen := map[string]string{}
	for _, rule := range rules {
		m, ok := rule.(map[string]any)
		if !ok {
			continue
		}
		domain, _ := m["domain"].(string)
		policy, _ := m["policy"].(string)
		seen[domain] = policy
	}
	if seen["base-only.test"] != "one_factor" {
		t.Errorf("base-only.test should be preserved, got %q", seen["base-only.test"])
	}
	if seen["shared.test"] != "two_factor" {
		t.Errorf("CRD should win for shared.test, got %q", seen["shared.test"])
	}
	if seen["crd-only.test"] != "one_factor" {
		t.Errorf("crd-only.test should be present, got %q", seen["crd-only.test"])
	}
}

func TestMergeAccessControlRules_EmptyInputsNoop(t *testing.T) {
	// When neither base nor CRD has rules, the merged YAML is returned unchanged.
	mergedIn := []byte("some: yaml\n")
	r := &OIDCClientReconciler{}
	got, err := r.mergeAccessControlRules(context.Background(), []byte("{}"), []byte("{}"), mergedIn)
	if err != nil {
		t.Fatalf("merge err: %v", err)
	}
	if string(got) != string(mergedIn) {
		t.Errorf("expected merged unchanged, got %q", got)
	}
}

// The bug this file exists to prevent a repeat of: a base rule that carves out
// a path was dropped because an OIDCClient happened to claim the same domain.
// Live symptom (homelab #398) was the total absence of a line — the rule sat in
// authelia-config-base, never reached authelia-config, and every reconcile
// logged success.
func TestNarrowingBaseRuleSurvivesACRDDomainRule(t *testing.T) {
	base := []byte(`
access_control:
  rules:
    - domain: gitea.test
      resources:
        - "^/api/packages/.*"
      policy: bypass
    - domain: gitea.test
      policy: one_factor
`)
	crd := []byte(`
access_control:
  rules:
    - domain: gitea.test
      policy: two_factor
`)

	r := &OIDCClientReconciler{}
	got, err := r.mergeAccessControlRules(context.Background(), base, crd, []byte("{}"))
	if err != nil {
		t.Fatalf("merge err: %v", err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rules := getAccessControlRules(out)

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (the carve-out + the CRD rule), got %d: %v", len(rules), rules)
	}

	// Ordering is the whole point: Authelia takes the FIRST match, so a bypass
	// placed after the domain-wide rule can never fire.
	first, _ := rules[0].(map[string]any)
	if !ruleIsNarrowing(first) {
		t.Fatalf("the carve-out must sort first, got %v first", first)
	}
	if first["policy"] != "bypass" {
		t.Errorf("first rule should be the bypass, got %v", first["policy"])
	}

	// The domain-wide BASE rule is still correctly superseded by the CRD's.
	second, _ := rules[1].(map[string]any)
	if second["policy"] != "two_factor" {
		t.Errorf("CRD rule should supersede the domain-wide base rule, got %v", second["policy"])
	}
}

func TestRuleIsNarrowing(t *testing.T) {
	cases := []struct {
		name string
		rule any
		want bool
	}{
		{"domain only", map[string]any{"domain": "a.test", "policy": "deny"}, false},
		{"resources", map[string]any{"domain": "a.test", "resources": []any{"^/x"}}, true},
		{"methods", map[string]any{"domain": "a.test", "methods": []any{"GET"}}, true},
		{"networks", map[string]any{"domain": "a.test", "networks": []any{"10.0.0.0/8"}}, true},
		// subject is NOT narrowing: a subject-less rule matches everyone, so
		// letting it outrank the CRD would reintroduce the ambiguity the
		// domain dedupe exists to settle.
		{"subject", map[string]any{"domain": "a.test", "subject": "group:x"}, false},
		{"explicit nil resources", map[string]any{"domain": "a.test", "resources": nil}, false},
		{"not a map", "nonsense", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ruleIsNarrowing(tc.rule); got != tc.want {
				t.Errorf("ruleIsNarrowing(%v) = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

// Same-domain rules used to tie under a NON-stable sort, so which one Authelia
// saw first was unspecified. Sorting an already-correct slice must not disturb
// it, and must not depend on input order.
func TestSortIsDeterministicForSameDomainRules(t *testing.T) {
	narrow := map[string]any{"domain": "a.test", "resources": []any{"^/x"}, "policy": "bypass"}
	wide := map[string]any{"domain": "a.test", "policy": "two_factor"}
	other := map[string]any{"domain": "b.test", "policy": "deny"}
	wildcard := map[string]any{"domain": "*.test", "policy": "deny"}

	for _, start := range [][]any{
		{narrow, wide, other, wildcard},
		{wildcard, wide, narrow, other},
		{other, wildcard, wide, narrow},
	} {
		rules := append([]any(nil), start...)
		sortAccessControlRules(rules)
		if got := rules[0].(map[string]any)["policy"]; got != "bypass" {
			t.Errorf("carve-out must come first, got %v (input %v)", got, start)
		}
		if got := rules[1].(map[string]any)["policy"]; got != "two_factor" {
			t.Errorf("domain-wide a.test must follow its carve-out, got %v", got)
		}
		if got := rules[3].(map[string]any)["domain"]; got != "*.test" {
			t.Errorf("wildcard must sort last, got %v", got)
		}
	}
}
