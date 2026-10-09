package repository

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type errKind string

const (
	errKindUnknown errKind = "unknown"
	errKindInvalid errKind = "invalid"
)

func TestApplyFilterCondition_ErrorPaths(t *testing.T) {
	t.Parallel()
	mapping := FieldMapping{
		"name":        {Column: "name", Type: filterString},
		"id":          {Column: "id", Type: filterInteger},
		"has_audio":   {Column: "audio_file", Type: filterPresence},
		"is_breaking": {Column: "is_breaking", Type: filterBoolean},
		"weekdays":    {Column: "weekdays", Type: filterBitmask},
	}

	tests := []struct {
		name      string
		cond      FilterCondition
		errKind   errKind
		wantField string
		wantOp    FilterOperator
	}{
		{name: "unknown field", cond: FilterCondition{Field: "bogus", Operator: FilterEquals, Values: []string{"x"}}, errKind: errKindUnknown, wantField: "bogus"},
		{name: "bitwise on non-band field", cond: FilterCondition{Field: "name", Operator: FilterBitwiseAnd, Values: []string{"1"}}, errKind: errKindInvalid, wantField: "name", wantOp: FilterBitwiseAnd},
		{name: "band above mask range", cond: FilterCondition{Field: "weekdays", Operator: FilterBitwiseAnd, Values: []string{"128"}}, errKind: errKindInvalid, wantField: "weekdays", wantOp: FilterBitwiseAnd},
		{name: "eq without value", cond: FilterCondition{Field: "id", Operator: FilterEquals}, errKind: errKindInvalid, wantField: "id", wantOp: FilterEquals},
		{name: "eq two values", cond: FilterCondition{Field: "id", Operator: FilterEquals, Values: []string{"1", "2"}}, errKind: errKindInvalid},
		{name: "in empty", cond: FilterCondition{Field: "id", Operator: FilterIn}, errKind: errKindInvalid, wantField: "id", wantOp: FilterIn},
		{name: "between nil value", cond: FilterCondition{Field: "id", Operator: FilterBetween}, errKind: errKindInvalid},
		{name: "between one element", cond: FilterCondition{Field: "id", Operator: FilterBetween, Values: []string{"1"}}, errKind: errKindInvalid},
		{name: "between three elements", cond: FilterCondition{Field: "id", Operator: FilterBetween, Values: []string{"1", "2", "3"}}, errKind: errKindInvalid},
		{name: "unsupported operator", cond: FilterCondition{Field: "id", Operator: FilterOperator("unknown_op"), Values: []string{"x"}}, errKind: errKindInvalid},
		{name: "has audio requires boolean", cond: FilterCondition{Field: "has_audio", Operator: FilterEquals, Values: []string{"yes"}}, errKind: errKindInvalid, wantField: "has_audio", wantOp: FilterEquals},
		{name: "is breaking requires boolean", cond: FilterCondition{Field: "is_breaking", Operator: FilterEquals, Values: []string{"yes"}}, errKind: errKindInvalid, wantField: "is_breaking", wantOp: FilterEquals},
		{name: "is breaking in requires booleans", cond: FilterCondition{Field: "is_breaking", Operator: FilterIn, Values: []string{"true", "maybe"}}, errKind: errKindInvalid, wantField: "is_breaking", wantOp: FilterIn},
		{name: "has audio rejects ordering", cond: FilterCondition{Field: "has_audio", Operator: FilterGreaterThan, Values: []string{"true"}}, errKind: errKindInvalid, wantField: "has_audio", wantOp: FilterGreaterThan},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Invalid filters must fail before accessing the database.
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
				Values:   []string{tt.value},
			}, FieldMapping{"has_audio": {Column: "audio_file", Type: filterPresence}})
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

func TestApplyFilterCondition_BooleanFields(t *testing.T) {
	t.Parallel()
	mapping := FieldMapping{"is_breaking": {Column: "is_breaking", Type: filterBoolean}}

	tests := []struct {
		name     string
		operator FilterOperator
		values   []string
		wantSQL  string
		wantVars []any
	}{
		{name: "eq true", operator: FilterEquals, values: []string{"true"}, wantSQL: "is_breaking = ?", wantVars: []any{true}},
		{name: "eq false", operator: FilterEquals, values: []string{"false"}, wantSQL: "is_breaking = ?", wantVars: []any{false}},
		{name: "ne true", operator: FilterNotEquals, values: []string{"true"}, wantSQL: "is_breaking != ?", wantVars: []any{true}},
		{name: "numeric literal", operator: FilterEquals, values: []string{"1"}, wantSQL: "is_breaking = ?", wantVars: []any{true}},
		{name: "in converts list", operator: FilterIn, values: []string{"true", "false"}, wantSQL: "is_breaking IN", wantVars: []any{true, false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{
				Field:    "is_breaking",
				Operator: tt.operator,
				Values:   tt.values,
			}, mapping)
			if err != nil {
				t.Fatalf("applyFilterCondition: %v", err)
			}

			stmt := out.Find(&[]struct{}{}).Statement
			if !strings.Contains(stmt.SQL.String(), tt.wantSQL) {
				t.Fatalf("SQL = %q, want fragment %q", stmt.SQL.String(), tt.wantSQL)
			}
			if got := stmt.Vars; !slices.Equal(got, tt.wantVars) {
				t.Fatalf("bind vars = %#v, want %#v", got, tt.wantVars)
			}
		})
	}
}

func TestApplyFilterCondition_BandBindsInteger(t *testing.T) {
	t.Parallel()
	out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{
		Field:    "weekdays",
		Operator: FilterBitwiseAnd,
		Values:   []string{"62"},
	}, storyFieldMapping)
	if err != nil {
		t.Fatalf("applyFilterCondition: %v", err)
	}
	stmt := out.Find(&[]struct{}{}).Statement
	if !strings.Contains(stmt.SQL.String(), "(weekdays & ?) != 0") || !slices.Equal(stmt.Vars, []any{uint64(62)}) {
		t.Fatalf("SQL = %q, vars = %#v; want (weekdays & ?) != 0 with [62]", stmt.SQL.String(), stmt.Vars)
	}
}

func TestApplyFilterCondition_NullOperators(t *testing.T) {
	t.Parallel()
	for _, op := range []FilterOperator{FilterIsNull, FilterIsNotNull} {
		t.Run(string(op), func(t *testing.T) {
			t.Parallel()
			var invalid *InvalidFilterError
			if _, err := applyFilterCondition(nil, FilterCondition{Field: "id", Operator: op}, storyFieldMapping); !errors.As(err, &invalid) {
				t.Fatalf("non-nullable id: got %v, want InvalidFilterError", err)
			}
			out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{Field: "voice_id", Operator: op}, storyFieldMapping)
			if err != nil {
				t.Fatalf("nullable voice_id: %v", err)
			}
			stmt := out.Find(&[]struct{}{}).Statement
			if len(stmt.Vars) != 0 || !strings.Contains(stmt.SQL.String(), "voice_id IS") {
				t.Fatalf("unexpected SQL %s, vars %v", stmt.SQL.String(), stmt.Vars)
			}
		})
	}
}

func TestApplySorting_RejectsPresenceFields(t *testing.T) {
	t.Parallel()
	mapping := FieldMapping{"has_audio": {Column: "audio_file", Type: filterPresence}, "created_at": {Column: "created_at", Type: filterDateTime}}

	_, err := applySorting(dryRunDB(t).Table("stories"), []SortField{{Field: "has_audio", Direction: SortAsc}}, nil, mapping)
	var e *UnknownFieldError
	if !errors.As(err, &e) {
		t.Fatalf("expected *UnknownFieldError, got %T (%v)", err, err)
	}
	if e.Kind != "sort" || e.Field != "has_audio" {
		t.Fatalf("got %+v, want sort/has_audio", e)
	}
}

func TestApplyFilterCondition_LikeWrapsValueOnce(t *testing.T) {
	t.Parallel()
	out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{
		Field:    "title",
		Operator: FilterLike,
		Values:   []string{"news"},
	}, FieldMapping{"title": {Column: "title", Type: filterString}})
	if err != nil {
		t.Fatalf("applyFilterCondition: %v", err)
	}

	stmt := out.Find(&[]struct{}{}).Statement
	if got := stmt.Vars; len(got) != 1 || got[0] != "%news%" {
		t.Fatalf("LIKE bind vars = %#v, want [%q]", got, "%news%")
	}
}

// dryRunDB builds MySQL statements without a database connection.
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
		ranges  bool // gt/gte/lt/lte/between allowed
		noIn    bool // in not allowed
	}{
		{
			name: "integer", mapping: voiceFieldMapping, field: "id", ranges: true,
			valid:   []string{"0", "-1", "42", "9223372036854775807", "-9223372036854775808"},
			invalid: []string{"abc", "false", "null", "", "1.5", "1e2", "1abc", "9223372036854775808", "-9223372036854775809"},
		},
		{
			name: "number", mapping: stationVoiceFieldMapping, field: "mix_point", ranges: true,
			valid:   []string{"0", "-1.5", "1.25", "1e2"},
			invalid: []string{"abc", "false", "null", "", "1.5abc", "NaN", "Inf", "-Inf", "1e999", "0x1p2", "1_000"},
		},
		{
			name: "date", mapping: storyFieldMapping, field: "start_date", ranges: true,
			valid:   []string{"2024-02-29", "2026-10-07"},
			invalid: []string{"abc", "", "2025-02-29", "2024-13-01", "2024-04-31", "2024-01-01T00:00:00Z"},
		},
		{
			// An unescaped + in a query decodes to a space, invalidating timezone offsets.
			name: "date-time", mapping: bulletinFieldMapping, field: "created_at", ranges: true,
			valid:   []string{"2024-02-29", "2024-01-01T12:30:00Z", "2024-01-01T12:30:00.123456+02:00", "2026-10-07T08:00:00+00:00", "2024-01-01 12:30:00"},
			invalid: []string{"abc", "", "2025-02-29", "2024-01-01T25:00:00Z", "2024-01-01T12:30:00", "2024-02-30 12:30:00", "2024-01-01 25:00:00", "2026-10-07T08:00:00 00:00"},
		},
		{
			name: "bitmask", mapping: storyFieldMapping, field: "weekdays", noIn: true,
			valid:   []string{"0", "62", "127"},
			invalid: []string{"128", "-1", "1.5", "false", "abc", ""},
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
	db := dryRunDB(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conditions := func(raw string) []FilterCondition {
				conds := []FilterCondition{
					{Field: tt.field, Operator: FilterEquals, Values: []string{raw}},
					{Field: tt.field, Operator: FilterNotEquals, Values: []string{raw}},
				}
				if !tt.noIn {
					conds = append(conds,
						FilterCondition{Field: tt.field, Operator: FilterIn, Values: []string{raw, tt.valid[0]}},
						FilterCondition{Field: tt.field, Operator: FilterIn, Values: []string{tt.valid[0], raw}},
					)
				}
				if tt.ranges {
					for _, op := range []FilterOperator{FilterGreaterThan, FilterGreaterOrEq, FilterLessThan, FilterLessOrEq} {
						conds = append(conds, FilterCondition{Field: tt.field, Operator: op, Values: []string{raw}})
					}
					conds = append(conds,
						FilterCondition{Field: tt.field, Operator: FilterBetween, Values: []string{raw, tt.valid[0]}},
						FilterCondition{Field: tt.field, Operator: FilterBetween, Values: []string{tt.valid[0], raw}},
					)
				}
				return conds
			}
			for _, raw := range tt.valid {
				for _, cond := range conditions(raw) {
					out, err := applyFilterCondition(db.Table("test"), cond, tt.mapping)
					if err != nil {
						t.Fatalf("%+v: %v", cond, err)
					}
					want := make([]any, len(cond.Values))
					for i, v := range cond.Values {
						want[i] = v
					}
					if got := out.Find(&[]struct{}{}).Statement.Vars; !slices.Equal(got, want) {
						t.Fatalf("%+v: bind vars = %#v, want %#v", cond, got, want)
					}
				}
			}
			for _, raw := range tt.invalid {
				for _, cond := range conditions(raw) {
					_, err := applyFilterCondition(nil, cond, tt.mapping)
					var invalid *InvalidFilterError
					if !errors.As(err, &invalid) || invalid.Field != tt.field || invalid.Operator != cond.Operator {
						t.Fatalf("%+v: got %v, want InvalidFilterError with field and operator", cond, err)
					}
				}
			}
		})
	}
}

func TestApplyFilterCondition_RejectsTypeOperators(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mapping FieldMapping
		field   string
		op      FilterOperator
		values  []string
	}{
		{name: "integer like", mapping: storyFieldMapping, field: "id", op: FilterLike, values: []string{"1"}},
		{name: "number like", mapping: stationFieldMapping, field: "pause_seconds", op: FilterLike, values: []string{"1"}},
		{name: "date like", mapping: storyFieldMapping, field: "start_date", op: FilterLike, values: []string{"2024-01-01"}},
		{name: "datetime like", mapping: storyFieldMapping, field: "created_at", op: FilterLike, values: []string{"2024-01-01"}},
		{name: "string range", mapping: storyFieldMapping, field: "title", op: FilterGreaterThan, values: []string{"news"}},
		{name: "status like", mapping: storyFieldMapping, field: "status", op: FilterLike, values: []string{"active"}},
		{name: "role range", mapping: userFieldMapping, field: "role", op: FilterBetween, values: []string{"admin", "viewer"}},
		{name: "boolean range", mapping: storyFieldMapping, field: "is_breaking", op: FilterGreaterThan, values: []string{"true"}},
		{name: "bitmask in", mapping: storyFieldMapping, field: "weekdays", op: FilterIn, values: []string{"1", "2"}},
		{name: "bitmask range", mapping: storyFieldMapping, field: "weekdays", op: FilterGreaterThan, values: []string{"1"}},
		{name: "presence in", mapping: storyFieldMapping, field: "has_audio", op: FilterIn, values: []string{"true", "false"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := applyFilterCondition(nil, FilterCondition{Field: tt.field, Operator: tt.op, Values: tt.values}, tt.mapping)
			var invalid *InvalidFilterError
			if !errors.As(err, &invalid) || invalid.Field != tt.field || invalid.Operator != tt.op {
				t.Fatalf("got %v, want InvalidFilterError with field and operator", err)
			}
		})
	}
}
