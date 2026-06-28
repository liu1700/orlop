package storage

import (
	"errors"
	"strings"
	"testing"
)

// fullSchema builds a present-map that satisfies every RequiredSchema entry, so
// individual tests can remove one piece and assert it is reported.
func fullSchema() map[string]map[string]bool {
	present := map[string]map[string]bool{}
	for _, t := range RequiredSchema() {
		cols := map[string]bool{}
		for _, c := range t.Columns {
			cols[c] = true
		}
		present[t.Name] = cols
	}
	return present
}

func TestSchemaGapComplete(t *testing.T) {
	if err := SchemaGap(fullSchema()); err != nil {
		t.Fatalf("complete schema should pass; got %v", err)
	}
}

func TestSchemaGapMissingTable(t *testing.T) {
	present := fullSchema()
	delete(present, "cert_revocations")

	var gap *SchemaGapError
	err := SchemaGap(present)
	if !errors.As(err, &gap) {
		t.Fatalf("want *SchemaGapError, got %v", err)
	}
	if len(gap.MissingTables) != 1 || gap.MissingTables[0] != "cert_revocations" {
		t.Fatalf("want missing table cert_revocations, got %v", gap.MissingTables)
	}
	if !strings.Contains(err.Error(), "migrate up") {
		t.Fatalf("error should point at migrate up; got %q", err.Error())
	}
}

func TestSchemaGapMissingColumn(t *testing.T) {
	present := fullSchema()
	delete(present["access_tokens"], "consumed_at")

	var gap *SchemaGapError
	err := SchemaGap(present)
	if !errors.As(err, &gap) {
		t.Fatalf("want *SchemaGapError, got %v", err)
	}
	if len(gap.MissingColumns) != 1 || gap.MissingColumns[0] != "access_tokens.consumed_at" {
		t.Fatalf("want missing column access_tokens.consumed_at, got %v", gap.MissingColumns)
	}
}
