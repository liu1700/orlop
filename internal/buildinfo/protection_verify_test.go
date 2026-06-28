package buildinfo

import "testing"

// TestBranchProtectionDeliberateFailure fails on purpose to verify that main's
// branch protection blocks merging a PR with a red `go` check. This file is a
// throwaway used only to prove the gating works; the PR is closed, never merged.
func TestBranchProtectionDeliberateFailure(t *testing.T) {
	t.Fatal("intentional failure: verifying branch protection blocks this PR from merging")
}
