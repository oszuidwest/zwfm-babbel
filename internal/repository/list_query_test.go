package repository

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Most of these tests exercise the error branches of applyFilterCondition, which
// return before touching the *gorm.DB, so a nil DB is safe input. The LIKE
// wildcard wrapping is pinned with a DryRun statement below; broader happy-path
// SQL generation is verified by the Jest integration suite under tests/ against a
// real MySQL.

// Typed constants make a typo a compile error rather than a silent test pass.
type errKind string

const (
	errKindUnknown errKind = "unknown" // -> *UnknownFieldError
	errKindInvalid errKind = "invalid" // -> *InvalidFilterError
)

// TestApplyFilterCondition_ErrorPaths covers the early-return branches of
// applyFilterCondition. A nil *gorm.DB is safe because every case returns
// before touching it. wantField "" skips both the field and operator checks
// (they are linked - cases that pin the operator must also pin the field).
func TestApplyFilterCondition_ErrorPaths(t *testing.T) {
	t.Parallel()
	mapping := FieldMapping{"name": {Column: "name", Type: filterString}, "id": {Column: "id", Type: filterInteger}, "has_audio": {Column: "audio_file", Type: filterBoolean}, "is_breaking": {Column: "is_breaking", Type: filterBoolean}}

	tests := []struct {
		name      string
		cond      FilterCondition
		errKind   errKind
		wantField string
		wantOp    FilterOperator
	}{
		{name: "unknown field", cond: FilterCondition{Field: "bogus", Operator: FilterEquals, Value: "x"}, errKind: errKindUnknown, wantField: "bogus"},
		{name: "bitwise on non-band field", cond: FilterCondition{Field: "name", Operator: FilterBitwiseAnd, Value: uint8(1)}, errKind: errKindInvalid, wantField: "name", wantOp: FilterBitwiseAnd},
		{name: "like requires string", cond: FilterCondition{Field: "name", Operator: FilterLike, Value: 42}, errKind: errKindInvalid, wantField: "name", wantOp: FilterLike},
		{name: "between nil value", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: nil}, errKind: errKindInvalid},
		{name: "between wrong type", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: "1,2"}, errKind: errKindInvalid},
		{name: "between one element", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: []string{"1"}}, errKind: errKindInvalid},
		{name: "between three elements", cond: FilterCondition{Field: "id", Operator: FilterBetween, Value: []string{"1", "2", "3"}}, errKind: errKindInvalid},
		{name: "unsupported operator", cond: FilterCondition{Field: "id", Operator: FilterOperator("unknown_op"), Value: "x"}, errKind: errKindInvalid},
		{name: "has audio requires boolean", cond: FilterCondition{Field: "has_audio", Operator: FilterEquals, Value: "yes"}, errKind: errKindInvalid, wantField: "has_audio", wantOp: FilterEquals},
		{name: "is breaking requires boolean", cond: FilterCondition{Field: "is_breaking", Operator: FilterEquals, Value: "yes"}, errKind: errKindInvalid, wantField: "is_breaking", wantOp: FilterEquals},
		{name: "is breaking in requires booleans", cond: FilterCondition{Field: "is_breaking", Operator: FilterIn, Value: []string{"true", "maybe"}}, errKind: errKindInvalid, wantField: "is_breaking", wantOp: FilterIn},
		{name: "has audio requires string value", cond: FilterCondition{Field: "has_audio", Operator: FilterEquals, Value: true}, errKind: errKindInvalid, wantField: "has_audio", wantOp: FilterEquals},
		{name: "has audio rejects ordering", cond: FilterCondition{Field: "has_audio", Operator: FilterGreaterThan, Value: "true"}, errKind: errKindInvalid, wantField: "has_audio", wantOp: FilterGreaterThan},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := applyFilterCondition(nil, tt.cond, mapping)
			switch tt.errKind {
			case errKindUnknown:
				var e *UnknownFieldError
				if !errors.As(err, &e) {
					t.Fatalf("expected *UnknownFieldError, got %T (%v)", err, err)
				}
				if e.Kind != "filter" || (tt.wantField != "" && e.Field != tt.wantField) {
					t.Fatalf("got %+v, want filter/%s", e, tt.wantField)
				}
			case errKindInvalid:
				var e *InvalidFilterError
				if !errors.As(err, &e) {
					t.Fatalf("expected *InvalidFilterError, got %T (%v)", err, err)
				}
				if tt.wantField != "" && (e.Field != tt.wantField || e.Operator != tt.wantOp) {
					t.Fatalf("got %+v, want %s/%s", e, tt.wantField, tt.wantOp)
				}
			default:
				t.Fatalf("unknown errKind %q - add a case or fix the typo", tt.errKind)
			}
		})
	}
}

func TestApplyFilterCondition_HasAudio(t *testing.T) {
	t.Parallel()

	// Values are strings because that is what the query-parsing layer
	// (internal/utils/query.go) hands the repository. The bind variable is
	// always the empty string: presence is expressed as (non-)emptiness.
	tests := []struct {
		name     string
		operator FilterOperator
		value    string
		wantSQL  string
	}{
		{name: "has audio", operator: FilterEquals, value: "true", wantSQL: "audio_file != ?"},
		{name: "has no audio", operator: FilterEquals, value: "false", wantSQL: "COALESCE(audio_file, '') = ?"},
		{name: "not has audio", operator: FilterNotEquals, value: "true", wantSQL: "COALESCE(audio_file, '') = ?"},
		{name: "not has no audio", operator: FilterNotEquals, value: "false", wantSQL: "audio_file != ?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{
				Field:    "has_audio",
				Operator: tt.operator,
				Value:    tt.value,
			}, FieldMapping{"has_audio": {Column: "audio_file", Type: filterBoolean}})
			if err != nil {
				t.Fatalf("applyFilterCondition: %v", err)
			}

			stmt := out.Find(&[]struct{}{}).Statement
			if !strings.Contains(stmt.SQL.String(), tt.wantSQL) {
				t.Fatalf("SQL = %q, want fragment %q", stmt.SQL.String(), tt.wantSQL)
			}
			if got := stmt.Vars; len(got) != 1 || got[0] != "" {
				t.Fatalf("bind vars = %#v, want [\"\"]", got)
			}
		})
	}
}

// TestApplyFilterCondition_BooleanFields pins the booleanFilterFields
// contract: textual booleans are rewritten to "1"/"0" before binding, because
// MySQL coerces "true"/"false" to 0 in numeric comparisons — an unnormalized
// filter[is_breaking]=true would silently select the FALSE rows.
func TestApplyFilterCondition_BooleanFields(t *testing.T) {
	t.Parallel()
	mapping := FieldMapping{"is_breaking": {Column: "is_breaking", Type: filterBoolean}}

	tests := []struct {
		name     string
		operator FilterOperator
		value    any
		wantSQL  string
		wantVars []any
	}{
		{name: "eq true", operator: FilterEquals, value: "true", wantSQL: "is_breaking = ?", wantVars: []any{"1"}},
		{name: "eq false", operator: FilterEquals, value: "false", wantSQL: "is_breaking = ?", wantVars: []any{"0"}},
		{name: "ne true", operator: FilterNotEquals, value: "true", wantSQL: "is_breaking != ?", wantVars: []any{"1"}},
		{name: "numeric passthrough", operator: FilterEquals, value: "1", wantSQL: "is_breaking = ?", wantVars: []any{"1"}},
		{name: "in normalizes list", operator: FilterIn, value: []string{"true", "false"}, wantSQL: "is_breaking IN", wantVars: []any{"1", "0"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{
				Field:    "is_breaking",
				Operator: tt.operator,
				Value:    tt.value,
			}, mapping)
			if err != nil {
				t.Fatalf("applyFilterCondition: %v", err)
			}

			stmt := out.Find(&[]struct{}{}).Statement
			if !strings.Contains(stmt.SQL.String(), tt.wantSQL) {
				t.Fatalf("SQL = %q, want fragment %q", stmt.SQL.String(), tt.wantSQL)
			}
			if got := stmt.Vars; len(got) != len(tt.wantVars) {
				t.Fatalf("bind vars = %#v, want %#v", got, tt.wantVars)
			} else {
				for i := range got {
					if got[i] != tt.wantVars[i] {
						t.Fatalf("bind vars = %#v, want %#v", got, tt.wantVars)
					}
				}
			}
		})
	}
}

// TestApplySorting_RejectsPresenceFields pins that a presence filter field in
// the FieldMapping does not leak into the sort whitelist: sorting by the
// backing audio_file column would be a meaningless lexicographic path sort.
func TestApplySorting_RejectsPresenceFields(t *testing.T) {
	t.Parallel()
	mapping := FieldMapping{"has_audio": {Column: "audio_file", Type: filterBoolean}, "created_at": {Column: "created_at", Type: filterDateTime}}

	_, err := applySorting(dryRunDB(t).Table("stories"), []SortField{{Field: "has_audio", Direction: SortAsc}}, nil, mapping)
	var e *UnknownFieldError
	if !errors.As(err, &e) {
		t.Fatalf("expected *UnknownFieldError, got %T (%v)", err, err)
	}
	if e.Kind != "sort" || e.Field != "has_audio" {
		t.Fatalf("got %+v, want sort/has_audio", e)
	}
}

// TestApplyFilterCondition_LikeWrapsValueOnce pins the single-wrap contract: the
// handler layer passes the raw substring (internal/utils/query.go) and the
// repository is the only layer that adds the % wildcards. A regression that drops
// the wrap ("news") or double-wraps ("%%news%%") changes the bind variable and
// fails here. DryRun builds the statement without opening a database connection.
func TestApplyFilterCondition_LikeWrapsValueOnce(t *testing.T) {
	t.Parallel()
	out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{
		Field:    "title",
		Operator: FilterLike,
		Value:    "news",
	}, FieldMapping{"title": {Column: "title", Type: filterString}})
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
	t.Parallel()
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
			t.Parallel()
			if got := escapeLikePattern(tt.in); got != tt.want {
				t.Fatalf("escapeLikePattern(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSortDirectionSQL(t *testing.T) {
	t.Parallel()
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

func TestApplyFilterCondition_TypedValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mapping FieldMapping
		field   string
		valid   []string
		invalid []string
		ranges  bool
	}{
		{
			name: "integer", mapping: voiceFieldMapping, field: "id", ranges: true,
			valid:   []string{"0", "-1", "42", "9223372036854775807", "-9223372036854775808"},
			invalid: []string{"abc", "false", "", "1.5", "1e2", "1abc", "9223372036854775808", "-9223372036854775809"},
		},
		{
			name: "number", mapping: stationVoiceFieldMapping, field: "mix_point", ranges: true,
			valid:   []string{"0", "-1.5", "1.25", "1e2"},
			invalid: []string{"abc", "false", "", "1.5abc", "NaN", "Inf", "-Inf", "1e999", "0x1p2", "1_000"},
		},
		{
			name: "date", mapping: storyFieldMapping, field: "start_date", ranges: true,
			valid:   []string{"2024-02-29", "2026-10-07"},
			invalid: []string{"abc", "", "2025-02-29", "2024-13-01", "2024-04-31", "2024-01-01T00:00:00Z"},
		},
		{
			name: "date-time", mapping: bulletinFieldMapping, field: "created_at", ranges: true,
			valid:   []string{"2024-02-29", "2024-01-01T12:30:00Z", "2024-01-01T12:30:00.123456+02:00", "2024-01-01 12:30:00"},
			invalid: []string{"abc", "", "2025-02-29", "2024-01-01T25:00:00Z", "2024-01-01T12:30:00", "2024-02-30 12:30:00", "2024-01-01 25:00:00"},
		},
		{
			name: "status", mapping: storyFieldMapping, field: "status",
			valid: []string{"draft", "active", "expired"}, invalid: []string{"abc", "", "1", "ACTIVE"},
		},
		{
			name: "role", mapping: userFieldMapping, field: "role",
			valid: []string{"admin", "editor", "viewer"}, invalid: []string{"abc", "", "1", "ADMIN"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			for _, raw := range append(append([]string{}, tt.valid...), tt.invalid...) {
				t.Run(raw, func(t *testing.T) {
					valid := slices.Contains(tt.valid, raw)
					conditions := []FilterCondition{
						{Field: tt.field, Operator: FilterEquals, Value: raw},
						{Field: tt.field, Operator: FilterNotEquals, Value: raw},
						{Field: tt.field, Operator: FilterIn, Value: []string{raw, tt.valid[0]}},
						{Field: tt.field, Operator: FilterIn, Value: []string{tt.valid[0], raw}},
					}
					if tt.ranges {
						for _, op := range []FilterOperator{FilterGreaterThan, FilterGreaterOrEq, FilterLessThan, FilterLessOrEq} {
							conditions = append(conditions, FilterCondition{Field: tt.field, Operator: op, Value: raw})
						}
						conditions = append(conditions,
							FilterCondition{Field: tt.field, Operator: FilterBetween, Value: []string{raw, tt.valid[0]}},
							FilterCondition{Field: tt.field, Operator: FilterBetween, Value: []string{tt.valid[0], raw}},
						)
					}
					for _, cond := range conditions {
						if !valid {
							_, err := applyFilterCondition(nil, cond, tt.mapping)
							var invalid *InvalidFilterError
							if !errors.As(err, &invalid) || invalid.Field != tt.field || invalid.Operator != cond.Operator {
								t.Fatalf("%+v: got %v, want InvalidFilterError with field and operator", cond, err)
							}
							continue
						}
						out, err := applyFilterCondition(dryRunDB(t).Table("test"), cond, tt.mapping)
						if err != nil {
							t.Fatalf("%+v: %v", cond, err)
						}
						stmt := out.Find(&[]struct{}{}).Statement
						want := []any{raw}
						if values, ok := cond.Value.([]string); ok {
							want = []any{values[0], values[1]}
						}
						if !slices.Equal(stmt.Vars, want) {
							t.Fatalf("%+v: bind vars = %#v, want %#v", cond, stmt.Vars, want)
						}
					}
				})
			}
		})
	}
}

func TestApplyFilterCondition_ClientFilters(t *testing.T) {
	t.Parallel()
	// Match the HTTP parser's value types: strings for scalars, uint8 for band.
	tests := []struct {
		name        string
		mapping     FieldMapping
		condition   FilterCondition
		wantInvalid bool
	}{
		{
			name: "Knabbel bulletin creation date", mapping: bulletinFieldMapping,
			condition: FilterCondition{Field: "created_at", Operator: FilterGreaterOrEq, Value: "2026-10-07"},
		},
		{
			name: "bulletin date-time lower bound", mapping: bulletinFieldMapping,
			condition: FilterCondition{Field: "created_at", Operator: FilterGreaterOrEq, Value: "2024-01-10 00:00:00"},
		},
		{
			name: "Knabbel story creation date", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "created_at", Operator: FilterGreaterOrEq, Value: "2026-10-07"},
		},
		{
			name: "Knabbel active stories", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "status", Operator: FilterEquals, Value: "active"},
		},
		{
			name: "Knabbel draft stories", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "status", Operator: FilterEquals, Value: "draft"},
		},
		{
			name: "Knabbel breaking stories", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "is_breaking", Operator: FilterEquals, Value: "true"},
		},
		{
			name: "Knabbel story start date", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "start_date", Operator: FilterLessOrEq, Value: "2026-10-07"},
		},
		{
			name: "Knabbel story end date", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "end_date", Operator: FilterGreaterOrEq, Value: "2026-10-07"},
		},
		{
			name: "Knabbel story weekdays", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "weekdays", Operator: FilterBitwiseAnd, Value: uint8(2)},
		},
		{
			name: "Knabbel stories with audio", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "has_audio", Operator: FilterEquals, Value: "true"},
		},
		{
			name: "Knabbel station voice", mapping: stationVoiceFieldMapping,
			condition: FilterCondition{Field: "voice_id", Operator: FilterEquals, Value: "5"},
		},
		{
			name: "WordPress non-draft stories", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "status", Operator: FilterNotEquals, Value: "draft"},
		},
		{
			// A correctly encoded %2B arrives from the HTTP parser as a literal +.
			name: "WordPress encoded creation timestamp", mapping: storyFieldMapping,
			condition: FilterCondition{Field: "created_at", Operator: FilterGreaterOrEq, Value: "2026-10-07T08:00:00+00:00"},
		},
		{
			// oszuidwest/zw-knabbel-wp#97 fixes the unescaped + that decodes to a space.
			name: "WordPress unencoded creation timestamp", mapping: storyFieldMapping,
			condition:   FilterCondition{Field: "created_at", Operator: FilterGreaterOrEq, Value: "2026-10-07T08:00:00 00:00"},
			wantInvalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := applyFilterCondition(dryRunDB(t).Table("test"), tt.condition, tt.mapping)
			if tt.wantInvalid {
				var invalid *InvalidFilterError
				if !errors.As(err, &invalid) || invalid.Field != tt.condition.Field || invalid.Operator != tt.condition.Operator {
					t.Fatalf("got %v, want InvalidFilterError with field and operator", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("applyFilterCondition: %v", err)
			}
		})
	}
}

func TestApplyFilterCondition_FieldContracts(t *testing.T) {
	t.Parallel()
	resources := map[string]FieldMapping{
		"stories": storyFieldMapping, "stations": stationFieldMapping, "voices": voiceFieldMapping,
		"station-voices": stationVoiceFieldMapping, "users": userFieldMapping, "bulletins": bulletinFieldMapping,
	}
	for name, mapping := range resources {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for field, definition := range mapping {
				if definition.Type != filterString {
					_, err := applyFilterCondition(nil, FilterCondition{Field: field, Operator: FilterEquals, Value: "garbage"}, mapping)
					var invalid *InvalidFilterError
					if !errors.As(err, &invalid) {
						t.Fatalf("%s: got %v, want InvalidFilterError", field, err)
					}
				}
				for _, op := range []FilterOperator{FilterIsNull, FilterIsNotNull} {
					out, err := applyFilterCondition(dryRunDB(t).Table("test"), FilterCondition{Field: field, Operator: op}, mapping)
					if !definition.Nullable {
						var invalid *InvalidFilterError
						if !errors.As(err, &invalid) {
							t.Fatalf("%s/%s: got %v, want InvalidFilterError", field, op, err)
						}
						continue
					}
					if err != nil {
						t.Fatalf("%s/%s: %v", field, op, err)
					}
					stmt := out.Find(&[]struct{}{}).Statement
					if len(stmt.Vars) != 0 || !strings.Contains(stmt.SQL.String(), definition.Column+" IS") {
						t.Fatalf("%s/%s: unexpected SQL %s, vars %v", field, op, stmt.SQL.String(), stmt.Vars)
					}
				}
			}
		})
	}
}

func TestApplyFilterCondition_Weekdays(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"0", "1", "62", "127", "128", "255", "-1", "1.5", "abc", "false", ""} {
		for _, op := range []FilterOperator{FilterEquals, FilterNotEquals, FilterBitwiseAnd} {
			t.Run(string(op)+"/"+raw, func(t *testing.T) {
				t.Parallel()
				var value any = raw
				if op == FilterBitwiseAnd {
					if parsed, err := strconv.ParseUint(raw, 10, 8); err == nil {
						value = uint8(parsed)
					}
				}
				cond := FilterCondition{Field: "weekdays", Operator: op, Value: value}
				valid := slices.Contains([]string{"0", "1", "62", "127"}, raw)
				out, err := applyFilterCondition(dryRunDB(t).Table("stories"), cond, storyFieldMapping)
				if !valid {
					var invalid *InvalidFilterError
					if !errors.As(err, &invalid) {
						t.Fatalf("got %v, want InvalidFilterError", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				stmt := out.Find(&[]struct{}{}).Statement
				if !slices.Equal(stmt.Vars, []any{value}) {
					t.Fatalf("bind vars = %#v, want [%v]", stmt.Vars, value)
				}
			})
		}
	}
}

func TestApplyFilterCondition_RejectsTypeOperators(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mapping FieldMapping
		field   string
		op      FilterOperator
		value   any
	}{
		{name: "integer like", mapping: storyFieldMapping, field: "id", op: FilterLike, value: "1"},
		{name: "number like", mapping: stationFieldMapping, field: "pause_seconds", op: FilterLike, value: "1"},
		{name: "date like", mapping: storyFieldMapping, field: "start_date", op: FilterLike, value: "2024-01-01"},
		{name: "datetime like", mapping: storyFieldMapping, field: "created_at", op: FilterLike, value: "2024-01-01"},
		{name: "string range", mapping: storyFieldMapping, field: "title", op: FilterGreaterThan, value: "news"},
		{name: "status like", mapping: storyFieldMapping, field: "status", op: FilterLike, value: "active"},
		{name: "role range", mapping: userFieldMapping, field: "role", op: FilterBetween, value: []string{"admin", "viewer"}},
		{name: "boolean range", mapping: storyFieldMapping, field: "is_breaking", op: FilterGreaterThan, value: "true"},
		{name: "bitmask in", mapping: storyFieldMapping, field: "weekdays", op: FilterIn, value: []string{"1", "2"}},
		{name: "bitmask range", mapping: storyFieldMapping, field: "weekdays", op: FilterGreaterThan, value: "1"},
		{name: "in scalar", mapping: storyFieldMapping, field: "id", op: FilterIn, value: "1"},
		{name: "in empty", mapping: storyFieldMapping, field: "id", op: FilterIn, value: []string{}},
		{name: "eq list", mapping: storyFieldMapping, field: "id", op: FilterEquals, value: []string{"1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := applyFilterCondition(nil, FilterCondition{Field: tt.field, Operator: tt.op, Value: tt.value}, tt.mapping)
			var invalid *InvalidFilterError
			if !errors.As(err, &invalid) || invalid.Field != tt.field || invalid.Operator != tt.op {
				t.Fatalf("got %v, want InvalidFilterError with field and operator", err)
			}
		})
	}
}
