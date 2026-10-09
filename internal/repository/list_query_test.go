package repository

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestApplyFilterCondition_ErrorPaths(t *testing.T) {
	t.Parallel()
	mapping := FieldMapping{
		"name":      {Column: "name", Type: filterString},
		"id":        {Column: "id", Type: filterInteger},
		"voice_id":  {Column: "voice_id", Type: filterInteger, Nullable: true},
		"has_audio": {Column: "audio_file", Type: filterPresence},
	}

	tests := []struct {
		name string
		cond FilterCondition
	}{
		{name: "bitwise on non-band field", cond: FilterCondition{Field: "name", Operator: FilterBitwiseAnd, Values: []string{"1"}}},
		{name: "eq without value", cond: FilterCondition{Field: "id", Operator: FilterEquals}},
		{name: "eq two values", cond: FilterCondition{Field: "id", Operator: FilterEquals, Values: []string{"1", "2"}}},
		{name: "in empty", cond: FilterCondition{Field: "id", Operator: FilterIn}},
		{name: "between nil value", cond: FilterCondition{Field: "id", Operator: FilterBetween}},
		{name: "between one element", cond: FilterCondition{Field: "id", Operator: FilterBetween, Values: []string{"1"}}},
		{name: "between three elements", cond: FilterCondition{Field: "id", Operator: FilterBetween, Values: []string{"1", "2", "3"}}},
		{name: "null without value", cond: FilterCondition{Field: "voice_id", Operator: FilterIsNull}},
		{name: "null requires boolean", cond: FilterCondition{Field: "voice_id", Operator: FilterIsNull, Values: []string{"maybe"}}},
		{name: "unsupported operator", cond: FilterCondition{Field: "id", Operator: FilterOperator("unknown_op"), Values: []string{"x"}}},
		{name: "has audio requires boolean", cond: FilterCondition{Field: "has_audio", Operator: FilterEquals, Values: []string{"yes"}}},
	}

	// Invalid filters must fail before accessing the database.
	var unknown *UnknownFieldError
	_, err := applyFilterCondition(nil, FilterCondition{Field: "bogus", Operator: FilterEquals, Values: []string{"x"}}, mapping)
	if !errors.As(err, &unknown) || unknown.Kind != "filter" || unknown.Field != "bogus" {
		t.Fatalf("unknown field: got %v, want UnknownFieldError filter/bogus", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var invalid *InvalidFilterError
			_, err := applyFilterCondition(nil, tt.cond, mapping)
			if !errors.As(err, &invalid) || invalid.Field != tt.cond.Field || invalid.Operator != tt.cond.Operator {
				t.Fatalf("got %v, want InvalidFilterError with field and operator", err)
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

func TestApplyFilterCondition_SQL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		cond     FilterCondition
		wantSQL  string
		wantVars []any
	}{
		{FilterCondition{Field: "id", Operator: FilterEquals, Values: []string{"1"}}, "id = ?", []any{"1"}},
		{FilterCondition{Field: "id", Operator: FilterNotEquals, Values: []string{"1"}}, "id != ?", []any{"1"}},
		{FilterCondition{Field: "id", Operator: FilterGreaterThan, Values: []string{"1"}}, "id > ?", []any{"1"}},
		{FilterCondition{Field: "id", Operator: FilterGreaterOrEq, Values: []string{"1"}}, "id >= ?", []any{"1"}},
		{FilterCondition{Field: "id", Operator: FilterLessThan, Values: []string{"1"}}, "id < ?", []any{"1"}},
		{FilterCondition{Field: "id", Operator: FilterLessOrEq, Values: []string{"1"}}, "id <= ?", []any{"1"}},
		{FilterCondition{Field: "id", Operator: FilterIn, Values: []string{"1", "2"}}, "id IN (?,?)", []any{"1", "2"}},
		{FilterCondition{Field: "id", Operator: FilterBetween, Values: []string{"1", "2"}}, "id BETWEEN ? AND ?", []any{"1", "2"}},
		{FilterCondition{Field: "weekdays", Operator: FilterBitwiseAnd, Values: []string{"62"}}, "(weekdays & ?) != 0", []any{uint64(62)}},
		// LIKE wraps the value once and escapes wildcards with the declared escape character.
		{FilterCondition{Field: "title", Operator: FilterLike, Values: []string{`50%_x`}}, `title LIKE ? ESCAPE '\\'`, []any{`%50\%\_x%`}},
	}
	for _, tt := range tests {
		t.Run(string(tt.cond.Operator), func(t *testing.T) {
			t.Parallel()
			out, err := applyFilterCondition(dryRunDB(t).Table("stories"), tt.cond, storyFieldMapping)
			if err != nil {
				t.Fatalf("applyFilterCondition: %v", err)
			}
			stmt := out.Find(&[]struct{}{}).Statement
			if !strings.Contains(stmt.SQL.String(), tt.wantSQL) || !slices.Equal(stmt.Vars, tt.wantVars) {
				t.Fatalf("SQL = %q, vars = %#v; want fragment %q with %#v", stmt.SQL.String(), stmt.Vars, tt.wantSQL, tt.wantVars)
			}
		})
	}
}

func TestApplyFilterCondition_NullOperator(t *testing.T) {
	t.Parallel()
	for value, wantSQL := range map[string]string{"true": "voice_id IS NULL", "false": "voice_id IS NOT NULL", "0": "voice_id IS NOT NULL"} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			var invalid *InvalidFilterError
			if _, err := applyFilterCondition(nil, FilterCondition{Field: "id", Operator: FilterIsNull, Values: []string{value}}, storyFieldMapping); !errors.As(err, &invalid) {
				t.Fatalf("non-nullable id: got %v, want InvalidFilterError", err)
			}
			out, err := applyFilterCondition(dryRunDB(t).Table("stories"), FilterCondition{Field: "voice_id", Operator: FilterIsNull, Values: []string{value}}, storyFieldMapping)
			if err != nil {
				t.Fatalf("nullable voice_id: %v", err)
			}
			stmt := out.Find(&[]struct{}{}).Statement
			if len(stmt.Vars) != 0 || !strings.Contains(stmt.SQL.String(), wantSQL) {
				t.Fatalf("SQL = %q, vars %v; want %q without vars", stmt.SQL.String(), stmt.Vars, wantSQL)
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
		ranges  bool             // gt/gte/lt/lte/between allowed
		noIn    bool             // in not allowed
		bind    func(string) any // nil binds the raw string
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
			valid:   []string{"2024-02-29", "2024-01-01T12:30:00Z", "2024-01-01T12:30:00.123456+02:00", "2026-10-07T08:00:00+00:00", "2024-01-01 12:30:00", "2024-01-01 12:30:00.5", "2024-01-01 12:30:00,5"},
			invalid: []string{"abc", "", "2025-02-29", "2024-01-01T25:00:00Z", "2024-01-01T12:30:00", "2024-02-30 12:30:00", "2024-01-01 25:00:00", "2026-10-07T08:00:00 00:00", "0000-01-01", "0000-01-01T00:00:00Z"},
			bind:    func(raw string) any { value, _ := parseDateTime(raw, time.Local); return value },
		},
		{
			name: "bitmask", mapping: storyFieldMapping, field: "weekdays", noIn: true,
			valid:   []string{"0", "62", "127"},
			invalid: []string{"128", "-1", "1.5", "false", "abc", ""},
			bind:    func(raw string) any { mask, _ := strconv.ParseUint(raw, 10, 7); return mask },
		},
		{
			name: "boolean", mapping: storyFieldMapping, field: "is_breaking",
			valid:   []string{"true", "false", "1", "0"},
			invalid: []string{"yes", "maybe", "", "2"},
			bind:    func(raw string) any { value, _ := strconv.ParseBool(raw); return value },
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
				if tt.mapping[tt.field].Type == filterBitmask {
					conds = append(conds, FilterCondition{Field: tt.field, Operator: FilterBitwiseAnd, Values: []string{raw}})
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
					want := bindArgs(cond.Values, tt.bind)
					if got := out.Find(&[]struct{}{}).Statement.Vars; !slices.EqualFunc(got, want, equalArg) {
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

// equalArg compares bind arguments by instant for times, since parsing an
// offset creates a distinct zone pointer each call.
func equalArg(a, b any) bool {
	if ta, ok := a.(time.Time); ok {
		tb, ok := b.(time.Time)
		return ok && ta.Equal(tb)
	}
	return a == b
}

func TestParseDateTime(t *testing.T) {
	t.Parallel()
	amsterdam, err := time.LoadLocation("Europe/Amsterdam")
	if err != nil {
		t.Fatal(err)
	}
	parse := func(raw string) time.Time {
		t.Helper()
		value, err := parseDateTime(raw, amsterdam)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		return value.(time.Time)
	}

	// MySQL reads a Z suffix as local time, so Go must fix the instant before binding.
	want := time.Date(2024, 1, 1, 12, 30, 0, 0, time.UTC)
	for _, raw := range []string{"2024-01-01T12:30:00Z", "2024-01-01T12:30:00+00:00", "2024-01-01T14:30:00+02:00", "2024-01-01 13:30:00", "2024-01-01 13:30:00.0", "2024-01-01 13:30:00,0"} {
		if got := parse(raw); !got.Equal(want) {
			t.Errorf("%q = %s, want %s", raw, got.UTC().Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
		}
	}
	if got := parse("2024-01-01 13:30:00,5"); !got.Equal(want.Add(500 * time.Millisecond)) {
		t.Errorf("comma fraction = %s, want 500ms after %s", got.UTC().Format(time.RFC3339Nano), want.Format(time.RFC3339))
	}
	if got := parse("2024-07-01"); !got.Equal(time.Date(2024, 6, 30, 22, 0, 0, 0, time.UTC)) {
		t.Errorf("bare date = %s, want local midnight 2024-06-30T22:00:00Z", got.UTC().Format(time.RFC3339))
	}
	for _, raw := range []string{"0000-01-01", "0000-01-01T00:00:00Z"} {
		if _, err := parseDateTime(raw, amsterdam); err == nil {
			t.Errorf("%q: expected error for a year the driver cannot bind", raw)
		}
	}
}

func TestFieldMappingsAreWellFormed(t *testing.T) {
	t.Parallel()
	known := []filterType{filterString, filterInteger, filterNumber, filterDate, filterDateTime, filterBoolean, filterBitmask, filterEnum, filterPresence}
	mappings := map[string]FieldMapping{
		"bulletin": bulletinFieldMapping, "station": stationFieldMapping, "stationVoice": stationVoiceFieldMapping,
		"story": storyFieldMapping, "user": userFieldMapping, "voice": voiceFieldMapping,
	}
	for name, mapping := range mappings {
		for field, f := range mapping {
			switch {
			case f.Column == "", !slices.Contains(known, f.Type):
				t.Errorf("%s.%s: missing column or unknown type %q", name, field, f.Type)
			case (f.Type == filterEnum) != (len(f.Enum) > 0):
				t.Errorf("%s.%s: Enum must be set exactly when Type is enum", name, field)
			case f.Type == filterPresence && f.Nullable:
				t.Errorf("%s.%s: presence fields handle NULL themselves", name, field)
			}
		}
	}
}

// bindArgs returns the expected bind arguments for values; a nil bind keeps raw strings.
func bindArgs(values []string, bind func(string) any) []any {
	args := make([]any, len(values))
	for i, v := range values {
		if bind != nil {
			args[i] = bind(v)
		} else {
			args[i] = v
		}
	}
	return args
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
		{name: "presence range", mapping: storyFieldMapping, field: "has_audio", op: FilterGreaterThan, values: []string{"true"}},
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
