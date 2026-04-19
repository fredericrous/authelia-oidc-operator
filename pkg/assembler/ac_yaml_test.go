package assembler

import (
	"sigs.k8s.io/yaml"
	"testing"
)

func TestAccessControlRuleYAMLOutput(t *testing.T) {
	cases := []struct {
		name string
		rule AccessControlRule
		want string
	}{
		{
			name: "no subject",
			rule: AccessControlRule{Domain: "auth.example.com", Policy: "bypass"},
			want: "domain: auth.example.com\npolicy: bypass\n",
		},
		{
			name: "single subject renders as scalar",
			rule: AccessControlRule{Domain: "admin.example.com", Policy: "two_factor", Subject: "group:lldap_admin"},
			want: "domain: admin.example.com\npolicy: two_factor\nsubject: group:lldap_admin\n",
		},
		{
			name: "multiple subjects render as YAML sequence",
			rule: AccessControlRule{Domain: "drive.example.com", Policy: "two_factor", Subject: []string{"group:nextcloud-user", "group:lldap_admin"}},
			want: "domain: drive.example.com\npolicy: two_factor\nsubject:\n- group:nextcloud-user\n- group:lldap_admin\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := yaml.Marshal(tc.rule)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("YAML mismatch\n--- want ---\n%s\n--- got ---\n%s", tc.want, string(got))
			}
		})
	}
}
