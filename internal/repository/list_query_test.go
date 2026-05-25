package repository

import (
	"errors"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Most of these tests exercise the error branches of applyFilterCondition, which
// return before touching the *gorm.DB, so a nil DB is safe input. The LIKE
// wildcard wrapping is pinned with a DryRun statement below; broader happy-path
// SQL generation is verified by the Jest integration suite under tests/ against a
// real MySQL.

// TestApplyFilterCondition_ErrorPaths covers the early-return branches of
// applyFilterCondition. A nil *gorm.DB is safe because every case returns
// before touching it. Successful LIKE wrapping is asserted separately via
// TestApplyFilterCondition_LikeWrapsValueOnce against a DryRun statement.
func TestApplyFilterCondition_ErrorPaths(t *testing.T) {
	mapping := FieldMapping{"name": "name", "id": "id"}

	// errKind: "unknown" -> *UnknownFieldError, "invalid" -> *InvalidFilterError.
	// wantField/wantOp pin error attributes that callers branch on; the empty
	// string skips that field (used for cases where only the error type matters).
	tests := []struct {
		name      string
		cond      FilterCondition
		errKind   string
		wantField string
		wantOp    FilterOperator
	}{
		{name: "unknown field", cond: FilterCondition{Field: "bogus", Operator: FilterEquals, Value: "x"}, errKind: "unknown", wantField: "bogus"},
		{name: "bitwise on non-band field", cond: FilterCondition{Field: "name", Operator: FilterBitwiseAnd, Value: uint8(1)}, errKind: "invalid", wantField: "name", wantOp: FilterBitwiseAnd},
		{name: "like requires string", cond: FilterCondition{Field: "name", Operator: FilterLike, Value: 42}, errKind: "invalid", wantField: "name", wantOp: FilterLike},
		{name: "between nil value", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: nil}, errKind: "invalid"},
		{name: "between wrong type", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: "1,2"}, errKind: "invalid"},
		{name: "between one element", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: []string{"1"}}, errKind: "invalid"},
		{name: "between three elements", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: []string{"1", "2", "3"}}, errKind: "invalid"},
		{name: "unsupported operator", cond: FilterCondition{Field: "id", Operator: FilterOperator("unknown_op"), Value: "x"}, errKind: "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := applyFilterCondition(nil, tt.cond, mapping)
			switch tt.errKind {
			case "unknown":
				var e *UnknownFieldError
				if !errors.As(err, &e) {
					t.Fatalf("expected *UnknownFieldError, got %T (%v)", err, err)
				}
				if e.Kind != "filter" || (tt.wantField != "" && e.Field != tt.wantField) {
					t.Fatalf("got %+v, want filter/%s", e, tt.wantField)
				}
			case "invalid":
				var e *InvalidFilterError
				if !errors.As(err, &e) {
					t.Fatalf("expected *InvalidFilterError, got %T (%v)", err, err)
				}
				if tt.wantField != "" && (e.Field != tt.wantField || e.Operator != tt.wantOp) {
					t.Fatalf("got %+v, want %s/%s", e, tt.wantField, tt.wantOp)
				}
			}
		})
	}
}

// TestApplyFilterCondition_LikeWrapsValueOnce pins the single-wrap contract: the
// handler layer passes the raw substring (internal/utils/query.go) and the
// repository is the only layer that adds the % wildcards. A regression that drops
// the wrap ("news") or double-wraps ("%%news%%") changes the bind variable and
// fails here. DryRun builds the statement without opening a database connection.
func TestApplyFilterCondition_LikeWrapsValueOnce(t *testing.T) {
	out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{
		Field:    "title",
		Operator: FilterLike,
		Value:    "news",
	}, FieldMapping{"title": "title"})
	if err != nil {
		t.Fatalf("applyFilterCondition: %v", err)
	}

	stmt := out.Find(&[]struct{}{}).Statement
	if got := stmt.Vars; len(got) != 1 || got[0] != "%news%" {
		t.Fatalf("LIKE bind vars = %#v, want [%q]", got, "%news%")
	}
}

// dryRunDB returns a GORM DB on the MySQL dialector in DryRun mode. It builds SQL
// and bind variables without connecting (SkipInitializeWithVersion skips the
// version probe; DisableAutomaticPing skips the post-open ping), so it can assert
// generated argument shapes against the real dialect without a live database.
func dryRunDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(mysql.New(mysql.Config{
		SkipInitializeWithVersion: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatalf("open dry-run db: %v", err)
	}
	return db
}

func TestEscapeLikePattern(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain text untouched", in: "news", want: "news"},
		{name: "percent escaped", in: "50%", want: `50\%`},
		{name: "underscore escaped", in: "a_b", want: `a\_b`},
		{name: "backslash escaped", in: `a\b`, want: `a\\b`},
		{name: "backslash before wildcard", in: `\%`, want: `\\\%`},
		{name: "mixed metacharacters", in: "100%_done", want: `100\%\_done`},
		{name: "empty string", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeLikePattern(tt.in); got != tt.want {
				t.Fatalf("escapeLikePattern(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSortDirectionSQL(t *testing.T) {
	if got := sortDirectionSQL(SortAsc); got != "ASC" {
		t.Fatalf("SortAsc -> %q, want ASC", got)
	}
	if got := sortDirectionSQL(SortDesc); got != "DESC" {
		t.Fatalf("SortDesc -> %q, want DESC", got)
	}
	if got := sortDirectionSQL(SortDirection("garbage")); got != "ASC" {
		t.Fatalf("unknown direction -> %q, want ASC fallback", got)
	}
}
