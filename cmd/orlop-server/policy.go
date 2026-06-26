package main

import (
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
)

// Policy mirrors src/policy.rs: deny first, then require allow-match if allow
// is non-empty. Empty allow set means allow-all. Patterns are gitignore-style
// globs (`*`, `**`, `?`, character classes), matching against a virtual path
// with the mount segment trimmed (see policyPath).
type Policy struct {
	allow []string
	deny  []string
}

// NewPolicy validates the patterns by attempting a single match; an invalid
// pattern fails fast at startup rather than per request.
func NewPolicy(allow, deny []string) (*Policy, error) {
	for _, p := range allow {
		if _, err := doublestar.Match(p, "validate"); err != nil {
			return nil, fmt.Errorf("invalid allow pattern %q: %w", p, err)
		}
	}
	for _, p := range deny {
		if _, err := doublestar.Match(p, "validate"); err != nil {
			return nil, fmt.Errorf("invalid deny pattern %q: %w", p, err)
		}
	}
	return &Policy{allow: allow, deny: deny}, nil
}

// Permits returns true if the path is allowed under the policy.
func (p *Policy) Permits(path string) bool {
	for _, pattern := range p.deny {
		if matched, _ := doublestar.Match(pattern, path); matched {
			return false
		}
	}
	if len(p.allow) == 0 {
		return true
	}
	for _, pattern := range p.allow {
		if matched, _ := doublestar.Match(pattern, path); matched {
			return true
		}
	}
	return false
}

// policyPath strips the leading "/<mount>/" segment from a virtual path so
// policy globs are written against the entity-relative subtree, matching the
// Rust handler semantics in src/server/mod.rs.
func policyPath(virtualPath string) string {
	for len(virtualPath) > 0 && virtualPath[0] == '/' {
		virtualPath = virtualPath[1:]
	}
	for i := 0; i < len(virtualPath); i++ {
		if virtualPath[i] == '/' {
			return virtualPath[i+1:]
		}
	}
	return ""
}
