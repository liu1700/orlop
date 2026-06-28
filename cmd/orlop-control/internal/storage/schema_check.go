package storage

import (
	"fmt"
	"sort"
	"strings"
)

// RequiredTable names a table the control plane needs at runtime, plus any
// columns whose absence has previously slipped through an in-place upgrade.
//
// The motivating incident (#39): squashing the released migrations (#23) reset
// goose numbering, so an already-deployed database skipped the squashed
// baseline and silently lacked access_tokens.consumed_at and the
// cert_revocations table. goose reported success; the gap only surfaced later
// as an opaque runtime error when a user action hit the missing column.
//
// Backends verify the live database against this list — on control-plane boot
// and at the end of `migrate up` — so a schema gap fails fast with an
// actionable error instead of a vague WARN + SQLSTATE. Keep the entries
// backend-agnostic: every table and column here must exist under both the
// Postgres and SQLite schemas. See docs/upgrade-safety.md.
type RequiredTable struct {
	// Name is the table name (identical across both backends).
	Name string
	// Columns lists columns to assert in addition to the table itself. Leave
	// empty to check table existence only — reserve explicit columns for those
	// added after the squashed baseline, which are the upgrade-skew hazard.
	Columns []string
}

// RequiredSchema is the minimal schema the control plane depends on. It is the
// source of truth for the boot-time and migrate-time self-check, not a mirror
// of the full schema: it lists every table the code uses plus the columns most
// likely to be missing on an in-place upgrade.
func RequiredSchema() []RequiredTable {
	return []RequiredTable{
		{Name: "tenants"},
		{Name: "users"},
		{Name: "disk_allocations"},
		{Name: "agent_enrollments"},
		// consumed_at was folded into the squashed baseline after v0.1.0; a
		// pre-squash database that skipped the baseline lacks it, which broke
		// enroll-token minting in v0.2.0.
		{Name: "access_tokens", Columns: []string{"consumed_at"}},
		{Name: "api_tokens"},
		// cert_revocations was likewise added after v0.1.0.
		{Name: "cert_revocations"},
		{Name: "server_pool"},
		{Name: "server_vms"},
		{Name: "dg_ca_secrets"},
		{Name: "sessions_anonymous"},
	}
}

// SchemaGap diffs a set of present tables and columns against RequiredSchema.
// present maps each existing table name to its set of column names. It returns
// nil when the live schema satisfies every requirement, or a *SchemaGapError
// naming exactly what is missing.
func SchemaGap(present map[string]map[string]bool) error {
	var gap SchemaGapError
	for _, t := range RequiredSchema() {
		cols, ok := present[t.Name]
		if !ok {
			gap.MissingTables = append(gap.MissingTables, t.Name)
			continue
		}
		for _, c := range t.Columns {
			if !cols[c] {
				gap.MissingColumns = append(gap.MissingColumns, t.Name+"."+c)
			}
		}
	}
	if len(gap.MissingTables) == 0 && len(gap.MissingColumns) == 0 {
		return nil
	}
	sort.Strings(gap.MissingTables)
	sort.Strings(gap.MissingColumns)
	return &gap
}

// SchemaGapError reports tables and/or columns the live database is missing
// relative to RequiredSchema. Its message names exactly what is absent and how
// to converge the database, so an operator never has to reverse-engineer an
// opaque SQLSTATE.
type SchemaGapError struct {
	MissingTables  []string // table names
	MissingColumns []string // "table.column"
}

func (e *SchemaGapError) Error() string {
	var b strings.Builder
	b.WriteString("control-plane schema is out of date: ")
	var parts []string
	if len(e.MissingTables) > 0 {
		parts = append(parts, "missing tables ["+strings.Join(e.MissingTables, ", ")+"]")
	}
	if len(e.MissingColumns) > 0 {
		parts = append(parts, "missing columns ["+strings.Join(e.MissingColumns, ", ")+"]")
	}
	b.WriteString(strings.Join(parts, "; "))
	fmt.Fprint(&b, ". Run `orlop-control migrate up` against this database. "+
		"If it was already migrated, the release may have renumbered an already-released "+
		"migration — see docs/upgrade-safety.md.")
	return b.String()
}
