package main

import "testing"

// TestBuildCATenantPolicy covers issue #8's bootstrap allowlist predicate:
// explicit operator entries plus the server-derived dynamic prefixes, with
// everything else refused.
func TestBuildCATenantPolicy(t *testing.T) {
	cases := []struct {
		name         string
		allowlist    string
		allowDynamic bool
		tenant       string
		want         bool
	}{
		{"dynamic user allowed by default", "", true, "u_abc123", true},
		{"dynamic agent allowed by default", "", true, "a_agent7", true},
		{"arbitrary tenant refused when not listed", "", true, "evilcorp", false},
		{"empty tenant refused", "", true, "", false},
		{"explicit static tenant allowed", "acme, beta ", false, "acme", true},
		{"explicit static tenant allowed (trim)", "acme, beta ", false, "beta", true},
		{"dynamic refused when dynamic disabled", "acme", false, "u_abc123", false},
		{"unlisted refused when dynamic disabled", "acme", false, "gamma", false},
		{"listed allowed even when dynamic disabled", "u_pinned", false, "u_pinned", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := buildCATenantPolicy(config{
				CATenantAllowlist:     tc.allowlist,
				CAAllowDynamicTenants: tc.allowDynamic,
			})
			if got := policy(tc.tenant); got != tc.want {
				t.Fatalf("policy(%q) = %v, want %v", tc.tenant, got, tc.want)
			}
		})
	}
}
