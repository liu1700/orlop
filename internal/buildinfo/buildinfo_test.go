package buildinfo

import "testing"

func TestVersionNeverEmpty(t *testing.T) {
	if got := Version(); got == "" {
		t.Fatal("Version() returned empty string; must always yield a usable label")
	}
}

func TestVersionPrefersInjected(t *testing.T) {
	saved := version
	t.Cleanup(func() { version = saved })

	version = "1.2.3"
	if got := Version(); got != "1.2.3" {
		t.Fatalf("Version() = %q, want injected %q", got, "1.2.3")
	}
}
