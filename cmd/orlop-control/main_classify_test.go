package main

import "testing"

func TestClassifyArgs(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		want     cliAction
		wantName string
	}{
		{"no args starts server", nil, actionRunServer, ""},
		{"empty slice starts server", []string{}, actionRunServer, ""},
		{"--version", []string{"--version"}, actionVersion, ""},
		{"-version", []string{"-version"}, actionVersion, ""},
		{"version verb", []string{"version"}, actionVersion, ""},
		{"-v", []string{"-v"}, actionVersion, ""},
		{"--help", []string{"--help"}, actionHelp, ""},
		{"-h", []string{"-h"}, actionHelp, ""},
		{"help verb", []string{"help"}, actionHelp, ""},
		{"server subcommand", []string{"server", "register"}, actionSubcommand, "server"},
		{"token subcommand", []string{"token", "issue"}, actionSubcommand, "token"},
		{"ca subcommand", []string{"ca"}, actionSubcommand, "ca"},
		{"unknown flag does not start server", []string{"--port=9090"}, actionUnknown, "--port=9090"},
		{"unknown verb", []string{"bogus"}, actionUnknown, "bogus"},
		{"bare dash", []string{"-"}, actionUnknown, "-"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, name := classifyArgs(tc.args)
			if got != tc.want {
				t.Errorf("classifyArgs(%q) action = %d, want %d", tc.args, got, tc.want)
			}
			if name != tc.wantName {
				t.Errorf("classifyArgs(%q) name = %q, want %q", tc.args, name, tc.wantName)
			}
		})
	}
}

// The regression this guards: an unrecognized first argument must NOT be
// classified as "start the server". Anything that isn't a known subcommand or a
// version/help request has to be actionUnknown (which main() turns into a
// non-zero exit) so a typo can't silently boot a control plane.
func TestClassifyArgsRejectsUnknownInsteadOfBooting(t *testing.T) {
	for _, arg := range []string{"--versionn", "serve", "--config", "-p", "8080"} {
		if got, _ := classifyArgs([]string{arg}); got == actionRunServer {
			t.Errorf("classifyArgs([%q]) = actionRunServer; unknown args must not boot the server", arg)
		}
	}
}
