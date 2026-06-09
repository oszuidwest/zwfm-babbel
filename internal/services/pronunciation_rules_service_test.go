package services

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"gorm.io/gorm"
)

func TestMaterializePronunciationRulesDefaultsAndTrimming(t *testing.T) {
	rules, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{
			StringToReplace: "  PSV  ",
			IPA:             "  piː ɛs veː  ",
		}},
	})
	if err != nil {
		t.Fatalf("materializePronunciationRules() error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(rules))
	}
	rule := rules[0]
	if rule.StringToReplace != "PSV" || rule.IPA != "piː ɛs veː" {
		t.Fatalf("rule = %#v, want trimmed term and IPA", rule)
	}
	if !rule.CaseSensitive || !rule.WordBoundaries {
		t.Fatalf("defaults = %t/%t, want true/true", rule.CaseSensitive, rule.WordBoundaries)
	}
}

func TestMaterializePronunciationRulesPreservesFalseFlags(t *testing.T) {
	rules, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{
			StringToReplace: "PSV",
			IPA:             "piː ɛs veː",
			CaseSensitive:   ptr(false),
			WordBoundaries:  ptr(false),
		}},
	})
	if err != nil {
		t.Fatalf("materializePronunciationRules() error = %v", err)
	}
	if rules[0].CaseSensitive || rules[0].WordBoundaries {
		t.Fatalf("flags = %t/%t, want false/false", rules[0].CaseSensitive, rules[0].WordBoundaries)
	}
}

func TestMaterializePronunciationRulesAcceptsRealisticIPA(t *testing.T) {
	validIPA := []string{
		"ˈstreːkɔmˌrupə",
		"piː ɛs veː",
		"ˈɑlkmaːr ˈzɑːnstreːk",
		"ˌbaɪoʊˈkemɪstri",
		"ˈæktʃuəli",
	}

	for _, ipa := range validIPA {
		t.Run(ipa, func(t *testing.T) {
			_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
				Rules: []PronunciationRuleUpdate{{StringToReplace: "term", IPA: ipa}},
			})
			if err != nil {
				t.Fatalf("materializePronunciationRules() error = %v", err)
			}
		})
	}
}

func TestMaterializePronunciationRulesValidation(t *testing.T) {
	long := strings.Repeat("é", maxPronunciationFieldRunes+1)
	maxWithDiacritics := strings.Repeat("é", maxPronunciationFieldRunes)

	tests := []struct {
		name      string
		rule      PronunciationRuleUpdate
		wantField string
	}{
		{
			name:      "empty string_to_replace",
			rule:      PronunciationRuleUpdate{StringToReplace: " ", IPA: "piː"},
			wantField: "rules[0].string_to_replace",
		},
		{
			name:      "empty ipa",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: " "},
			wantField: "rules[0].ipa",
		},
		{
			name:      "slash in ipa",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: "piː/ɛs"},
			wantField: "rules[0].ipa",
		},
		{
			name:      "control character in string_to_replace",
			rule:      PronunciationRuleUpdate{StringToReplace: "P\nSV", IPA: "piː"},
			wantField: "rules[0].string_to_replace",
		},
		{
			name:      "control character in ipa",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: "piː\u0085x"},
			wantField: "rules[0].ipa",
		},
		{
			name:      "term too long",
			rule:      PronunciationRuleUpdate{StringToReplace: long, IPA: "piː"},
			wantField: "rules[0].string_to_replace",
		},
		{
			name:      "ipa too long",
			rule:      PronunciationRuleUpdate{StringToReplace: "PSV", IPA: long},
			wantField: "rules[0].ipa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
				Rules: []PronunciationRuleUpdate{tt.rule},
			})
			assertPronunciationValidationField(t, err, tt.wantField)
		})
	}

	t.Run("255 runes with diacritics accepted", func(t *testing.T) {
		_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{
			Rules: []PronunciationRuleUpdate{{StringToReplace: maxWithDiacritics, IPA: maxWithDiacritics}},
		})
		if err != nil {
			t.Fatalf("materializePronunciationRules() error = %v", err)
		}
	})
}

func TestMaterializePronunciationRulesConflicts(t *testing.T) {
	tests := []struct {
		name        string
		rules       []PronunciationRuleUpdate
		wantField   string
		wantMessage string
	}{
		{
			name: "byte exact duplicate",
			rules: []PronunciationRuleUpdate{
				{StringToReplace: "PSV", IPA: "one"},
				{StringToReplace: "PSV", IPA: "two"},
			},
			wantField:   "rules[1].string_to_replace",
			wantMessage: "duplicates rules[0]",
		},
		{
			name: "case insensitive shadow",
			rules: []PronunciationRuleUpdate{
				{StringToReplace: "PSV", IPA: "one", CaseSensitive: ptr(false)},
				{StringToReplace: "psv", IPA: "two"},
			},
			wantField:   "rules[0].string_to_replace",
			wantMessage: "conflicts with rules[1] under case-insensitive matching",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{Rules: tt.rules})

			var validationErr *apperrors.ValidationProblemError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error type = %T, want *apperrors.ValidationProblemError", err)
			}
			if !slices.ContainsFunc(validationErr.Errors, func(e apperrors.ValidationError) bool {
				return e.Field == tt.wantField && e.Message == tt.wantMessage
			}) {
				t.Fatalf("errors = %#v, want %s %q", validationErr.Errors, tt.wantField, tt.wantMessage)
			}
		})
	}
}

func TestMaterializePronunciationRulesMaxRules(t *testing.T) {
	rules := make([]PronunciationRuleUpdate, MaxPronunciationRules+1)
	for i := range rules {
		rules[i] = PronunciationRuleUpdate{
			StringToReplace: "term-" + string(rune('a'+(i%26))) + "-" + strings.Repeat("x", i/26),
			IPA:             "ipa",
		}
	}

	_, err := materializePronunciationRules(&UpdatePronunciationRulesRequest{Rules: rules})
	assertPronunciationValidationField(t, err, "rules")
}

func TestPronunciationRulesServiceGet(t *testing.T) {
	updatedAt := time.Unix(1717200000, 0).UTC()
	repo := &fakePronunciationRuleRepo{
		listRules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", true, true)},
		updatedAt: &updatedAt,
	}
	service := NewPronunciationRulesService(repo, nil)

	got, err := service.Get(context.Background())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].StringToReplace != "PSV" {
		t.Fatalf("Rules = %#v, want PSV rule", got.Rules)
	}
	if got.UpdatedAt == nil || !got.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, updatedAt)
	}
	if repo.listCalls != 1 || repo.maxCalls != 1 {
		t.Fatalf("calls list=%d max=%d, want 1 each", repo.listCalls, repo.maxCalls)
	}
}

func TestPronunciationRulesServiceGetTranslatesRepoErrors(t *testing.T) {
	tests := []struct {
		name      string
		repo      *fakePronunciationRuleRepo
		wantError any
	}{
		{
			name:      "list schema unavailable",
			repo:      &fakePronunciationRuleRepo{listErr: repository.ErrSchemaUnavailable},
			wantError: &apperrors.NotInitializedError{},
		},
		{
			name:      "max updated at failed",
			repo:      &fakePronunciationRuleRepo{maxErr: errors.New("max failed")},
			wantError: &apperrors.DatabaseError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewPronunciationRulesService(tt.repo, nil)

			_, err := service.Get(context.Background())
			assertErrorAs(t, err, tt.wantError)
		})
	}
}

func TestPronunciationRulesServiceUpdateHappyPath(t *testing.T) {
	createdAt := time.Unix(1717200000, 0).UTC()
	updatedAt := createdAt.Add(time.Minute)
	actorID := int64(42)
	wordBoundaries := false
	repo := &fakePronunciationRuleRepo{
		listRules: []models.PronunciationRule{
			{
				StringToReplace: "Albert Heijn",
				IPA:             "ˈɑlbərt ˈɦɛin",
				CaseSensitive:   true,
				WordBoundaries:  false,
				CreatedAt:       createdAt,
				UpdatedAt:       updatedAt,
			},
			{
				StringToReplace: "PSV",
				IPA:             "piː ɛs veː",
				CaseSensitive:   true,
				WordBoundaries:  true,
				CreatedAt:       createdAt,
				UpdatedAt:       updatedAt,
			},
		},
		updatedAt: &updatedAt,
	}
	tx := &fakePronunciationRulesTxManager{}
	service := NewPronunciationRulesService(repo, tx)

	got, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{
			{StringToReplace: "PSV", IPA: "piː ɛs veː"},
			{StringToReplace: "Albert Heijn", IPA: "ˈɑlbərt ˈɦɛin", WordBoundaries: &wordBoundaries},
		},
		ActorUserID: &actorID,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	assertHappyPathTxCommitted(t, tx, repo)
	assertHappyPathReplaced(t, repo.replaced)
	assertHappyPathReturned(t, got, updatedAt)
}

func assertHappyPathTxCommitted(t *testing.T, tx *fakePronunciationRulesTxManager, repo *fakePronunciationRuleRepo) {
	t.Helper()
	if !tx.committed || tx.rolledBack {
		t.Fatalf("transaction committed=%v rolledBack=%v, want committed only", tx.committed, tx.rolledBack)
	}
	if repo.replaceCalls != 1 || repo.listCalls != 1 || repo.maxCalls != 1 {
		t.Fatalf("calls replace=%d list=%d max=%d, want 1 each", repo.replaceCalls, repo.listCalls, repo.maxCalls)
	}
}

func assertHappyPathReplaced(t *testing.T, replaced []models.PronunciationRule) {
	t.Helper()
	if len(replaced) != 2 ||
		replaced[0].StringToReplace != "Albert Heijn" ||
		replaced[1].StringToReplace != "PSV" {
		t.Fatalf("replaced order = %#v, want alphabetical", replaced)
	}
	if replaced[0].WordBoundaries || !replaced[1].WordBoundaries {
		t.Fatalf("materialized word boundaries = %#v, want explicit false then default true", replaced)
	}
}

func assertHappyPathReturned(t *testing.T, got *PronunciationRulesResponse, updatedAt time.Time) {
	t.Helper()
	if len(got.Rules) != 2 || got.Rules[0].CreatedAt.IsZero() || got.Rules[0].UpdatedAt.IsZero() {
		t.Fatalf("Rules = %#v, want persisted rules with timestamps", got.Rules)
	}
	if got.UpdatedAt == nil || !got.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("UpdatedAt = %v, want %v", got.UpdatedAt, updatedAt)
	}
}

func TestPronunciationRulesServiceUpdateReplaceAllErrorRollsBack(t *testing.T) {
	repo := &fakePronunciationRuleRepo{replaceErr: errors.New("replace failed")}
	tx := &fakePronunciationRulesTxManager{}
	service := NewPronunciationRulesService(repo, tx)

	_, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{StringToReplace: "PSV", IPA: "piː ɛs veː"}},
	})

	var dbErr *apperrors.DatabaseError
	if !errors.As(err, &dbErr) {
		t.Fatalf("Update() error = %T, want *apperrors.DatabaseError", err)
	}
	if !tx.rolledBack || tx.committed {
		t.Fatalf("transaction committed=%v rolledBack=%v, want rollback only", tx.committed, tx.rolledBack)
	}
	if repo.listCalls != 0 || repo.maxCalls != 0 {
		t.Fatalf("calls list=%d max=%d, want no post-replace reads", repo.listCalls, repo.maxCalls)
	}
}

func TestPronunciationRulesServiceUpdateAnnotatesMaxUpdatedAtError(t *testing.T) {
	repo := &fakePronunciationRuleRepo{
		listRules: []models.PronunciationRule{rule("PSV", "piː ɛs veː", true, true)},
		maxErr:    errors.New("max failed"),
	}
	tx := &fakePronunciationRulesTxManager{}
	service := NewPronunciationRulesService(repo, tx)

	_, err := service.Update(context.Background(), &UpdatePronunciationRulesRequest{
		Rules: []PronunciationRuleUpdate{{StringToReplace: "PSV", IPA: "piː ɛs veː"}},
	})

	var dbErr *apperrors.DatabaseError
	if !errors.As(err, &dbErr) {
		t.Fatalf("Update() error = %T, want *apperrors.DatabaseError", err)
	}
	if !strings.Contains(dbErr.Unwrap().Error(), "max_updated_at") {
		t.Fatalf("DatabaseError cause = %q, want max_updated_at context", dbErr.Unwrap().Error())
	}
	if !tx.rolledBack || tx.committed {
		t.Fatalf("transaction committed=%v rolledBack=%v, want rollback only", tx.committed, tx.rolledBack)
	}
}

func TestSortPronunciationRules(t *testing.T) {
	rules := []models.PronunciationRule{
		rule("Charlie", "c", true, true),
		rule("Alpha", "a", true, true),
		rule("Bravo", "b", true, true),
	}

	sortPronunciationRules(rules)

	got := []string{rules[0].StringToReplace, rules[1].StringToReplace, rules[2].StringToReplace}
	want := []string{"Alpha", "Bravo", "Charlie"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestTranslatePronunciationRulesRepoError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		op        apperrors.Operation
		wantError any
	}{
		{name: "nil", err: nil, op: apperrors.OpQuery, wantError: nil},
		{
			name:      "schema unavailable",
			err:       repository.ErrSchemaUnavailable,
			op:        apperrors.OpQuery,
			wantError: &apperrors.NotInitializedError{},
		},
		{
			name:      "data too long",
			err:       repository.ErrDataTooLong,
			op:        apperrors.OpUpdate,
			wantError: &apperrors.ValidationError{},
		},
		{
			name:      "generic",
			err:       errors.New("db failed"),
			op:        apperrors.OpUpdate,
			wantError: &apperrors.DatabaseError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := translatePronunciationRulesRepoError(tt.op, tt.err)
			if tt.wantError == nil {
				if err != nil {
					t.Fatalf("error = %v, want nil", err)
				}
				return
			}
			assertErrorAs(t, err, tt.wantError)
		})
	}
}

func assertPronunciationValidationField(t *testing.T, err error, wantField string) {
	t.Helper()

	var validationErr *apperrors.ValidationProblemError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type = %T, want *apperrors.ValidationProblemError", err)
	}
	if !slices.ContainsFunc(validationErr.Errors, func(e apperrors.ValidationError) bool {
		return e.Field == wantField
	}) {
		t.Fatalf("errors = %#v, want field %q", validationErr.Errors, wantField)
	}
}

func assertErrorAs(t *testing.T, err error, target any) {
	t.Helper()
	switch target := target.(type) {
	case *apperrors.NotInitializedError:
		if !errors.As(err, &target) {
			t.Fatalf("error = %T, want *apperrors.NotInitializedError", err)
		}
	case *apperrors.DatabaseError:
		if !errors.As(err, &target) {
			t.Fatalf("error = %T, want *apperrors.DatabaseError", err)
		}
	case *apperrors.ValidationError:
		if !errors.As(err, &target) {
			t.Fatalf("error = %T, want *apperrors.ValidationError", err)
		}
	default:
		t.Fatalf("unhandled target type %T", target)
	}
}

type fakePronunciationRuleRepo struct {
	listRules []models.PronunciationRule
	listErr   error
	updatedAt *time.Time
	maxErr    error

	replaceErr error
	replaced   []models.PronunciationRule

	listCalls    int
	replaceCalls int
	maxCalls     int
}

func (f *fakePronunciationRuleRepo) List(context.Context) ([]models.PronunciationRule, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	rules := make([]models.PronunciationRule, len(f.listRules))
	copy(rules, f.listRules)
	return rules, nil
}

func (f *fakePronunciationRuleRepo) ReplaceAll(_ context.Context, rules []models.PronunciationRule) error {
	f.replaceCalls++
	if f.replaceErr != nil {
		return f.replaceErr
	}
	f.replaced = make([]models.PronunciationRule, len(rules))
	copy(f.replaced, rules)
	return nil
}

func (f *fakePronunciationRuleRepo) MaxUpdatedAt(context.Context) (*time.Time, error) {
	f.maxCalls++
	if f.maxErr != nil {
		return nil, f.maxErr
	}
	return f.updatedAt, nil
}

type fakePronunciationRulesTxManager struct {
	committed  bool
	rolledBack bool
}

func (f *fakePronunciationRulesTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	if err := fn(ctx); err != nil {
		f.rolledBack = true
		return fmt.Errorf("transaction failed: %w", err)
	}
	f.committed = true
	return nil
}

func (f *fakePronunciationRulesTxManager) DB() *gorm.DB {
	return nil
}
