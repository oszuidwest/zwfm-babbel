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

func TestApplyFilterCondition_Rejects(t *testing.T) {
	t.Parallel()
	// Invalid filters must fail before accessing the database.
	var unknown *UnknownFieldError
	_, err := applyFilterCondition(nil, FilterCondition{Field: "bogus", Operator: FilterEquals, Values: []string{"x"}}, storyFieldMapping)
	if !errors.As(err, &unknown) || unknown.Kind != "filter" || unknown.Field != "bogus" {
		t.Fatalf("unknown field: got %v, want UnknownFieldError filter/bogus", err)
	}

	tests := []struct {
		name string
		cond FilterCondition
	}{
		{name: "unsupported operator", cond: FilterCondition{Field: "id", Operator: FilterOperator("unknown_op"), Values: []string{"x"}}},
		{name: "eq without value", cond: FilterCondition{Field: "id", Operator: FilterEquals}},
		{name: "eq two values", cond: FilterCondition{Field: "id", Operator: FilterEquals, Values: []string{"1", "2"}}},
		{name: "in empty", cond: FilterCondition{Field: "id", Operator: FilterIn}},
		{name: "between nil value", cond: FilterCondition{Field: "id", Operator: FilterBetween}},
		{name: "between one element", cond: FilterCondition{Field: "id", Operator: FilterBetween, Values: []string{"1"}}},
		{name: "between three elements", cond: FilterCondition{Field: "id", Operator: FilterBetween, Values: []string{"1", "2", "3"}}},
		{name: "null on required field", cond: FilterCondition{Field: "id", Operator: FilterIsNull, Values: []string{"true"}}},
		{name: "null without value", cond: FilterCondition{Field: "voice_id", Operator: FilterIsNull}},
		{name: "null requires boolean", cond: FilterCondition{Field: "voice_id", Operator: FilterIsNull, Values: []string{"maybe"}}},
		{name: "has audio requires boolean", cond: FilterCondition{Field: "has_audio", Operator: FilterEquals, Values: []string{"yes"}}},
		{name: "integer like", cond: FilterCondition{Field: "id", Operator: FilterLike, Values: []string{"1"}}},
		{name: "number like", cond: FilterCondition{Field: "duration_seconds", Operator: FilterLike, Values: []string{"1"}}},
		{name: "date like", cond: FilterCondition{Field: "start_date", Operator: FilterLike, Values: []string{"2024-01-01"}}},
		{name: "datetime like", cond: FilterCondition{Field: "created_at", Operator: FilterLike, Values: []string{"2024-01-01"}}},
		{name: "string range", cond: FilterCondition{Field: "title", Operator: FilterGreaterThan, Values: []string{"news"}}},
		{name: "string bitwise", cond: FilterCondition{Field: "title", Operator: FilterBitwiseAnd, Values: []string{"1"}}},
		{name: "enum like", cond: FilterCondition{Field: "status", Operator: FilterLike, Values: []string{"active"}}},
		{name: "enum range", cond: FilterCondition{Field: "status", Operator: FilterBetween, Values: []string{"active", "draft"}}},
		{name: "boolean range", cond: FilterCondition{Field: "is_breaking", Operator: FilterGreaterThan, Values: []string{"true"}}},
		{name: "bitmask in", cond: FilterCondition{Field: "weekdays", Operator: FilterIn, Values: []string{"1", "2"}}},
		{name: "bitmask range", cond: FilterCondition{Field: "weekdays", Operator: FilterGreaterThan, Values: []string{"1"}}},
		{name: "presence in", cond: FilterCondition{Field: "has_audio", Operator: FilterIn, Values: []string{"true", "false"}}},
		{name: "presence range", cond: FilterCondition{Field: "has_audio", Operator: FilterGreaterThan, Values: []string{"true"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var invalid *InvalidFilterError
			_, err := applyFilterCondition(nil, tt.cond, storyFieldMapping)
			if !errors.As(err, &invalid) || invalid.Field != tt.cond.Field || invalid.Operator != tt.cond.Operator {
				t.Fatalf("got %v, want InvalidFilterError with field and operator", err)
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
		{FilterCondition{Field: "voice_id", Operator: FilterIsNull, Values: []string{"true"}}, "voice_id IS NULL", nil},
		{FilterCondition{Field: "voice_id", Operator: FilterIsNull, Values: []string{"false"}}, "voice_id IS NOT NULL", nil},
		{FilterCondition{Field: "voice_id", Operator: FilterIsNull, Values: []string{"0"}}, "voice_id IS NOT NULL", nil},
		// NULL and "" both mean absent.
		{FilterCondition{Field: "has_audio", Operator: FilterEquals, Values: []string{"true"}}, "(COALESCE(audio_file, '') != '') = ?", []any{true}},
		{FilterCondition{Field: "has_audio", Operator: FilterEquals, Values: []string{"false"}}, "(COALESCE(audio_file, '') != '') = ?", []any{false}},
		{FilterCondition{Field: "has_audio", Operator: FilterNotEquals, Values: []string{"true"}}, "(COALESCE(audio_file, '') != '') != ?", []any{true}},
		{FilterCondition{Field: "has_audio", Operator: FilterNotEquals, Values: []string{"false"}}, "(COALESCE(audio_file, '') != '') != ?", []any{false}},
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

func TestApplySorting_RejectsPresenceFields(t *testing.T) {
	t.Parallel()
	_, err := applySorting(dryRunDB(t).Table("stories"), []SortField{{Field: "has_audio", Direction: SortAsc}}, nil, storyFieldMapping)
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
	// The driver binds the time in loc, so the year check applies after conversion.
	for _, raw := range []string{"0000-01-01", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00+14:00", "9999-12-31T23:30:00Z"} {
		if _, err := parseDateTime(raw, amsterdam); err == nil {
			t.Errorf("%q: expected error for a year the driver cannot bind", raw)
		}
	}
	for _, raw := range []string{"0001-01-02T00:00:00Z", "9999-12-31T22:00:00Z"} {
		if got := parse(raw); got.Location() != amsterdam {
			t.Errorf("%q: location = %v, want loc so the driver binds the checked year", raw, got.Location())
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
