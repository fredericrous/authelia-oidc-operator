package controllers

import (
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
	got, err := r.mergeAccessControlRules(base, crd, merged)
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
	got, err := r.mergeAccessControlRules([]byte("{}"), []byte("{}"), mergedIn)
	if err != nil {
		t.Fatalf("merge err: %v", err)
	}
	if string(got) != string(mergedIn) {
		t.Errorf("expected merged unchanged, got %q", got)
	}
}
