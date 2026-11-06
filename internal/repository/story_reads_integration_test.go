//go:build integration

package repository

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

// joinedReadFixture holds a voice, a story with it and one without, created
// in a transaction that is rolled back when the test ends. Every query on tx
// adds one to queries.
type joinedReadFixture struct {
	tx      *gorm.DB
	queries *atomic.Int64
	name    string
	voice   models.Voice
	stories []models.Story
}

func newJoinedReadFixture(t *testing.T) joinedReadFixture {
	t.Helper()
	db := testutil.OpenIntegrationDB(t)
	f := joinedReadFixture{queries: new(atomic.Int64), name: fmt.Sprintf("joined-reads-%d", time.Now().UnixNano())}
	if err := db.Callback().Query().Before("gorm:query").Register("test:count_story_reads", func(*gorm.DB) {
		f.queries.Add(1)
	}); err != nil {
		t.Fatal(err)
	}
	f.tx = db.Begin()
	if f.tx.Error != nil {
		t.Fatal(f.tx.Error)
	}
	t.Cleanup(func() { f.tx.Rollback() })

	f.voice = models.Voice{Name: f.name}
	if err := f.tx.Create(&f.voice).Error; err != nil {
		t.Fatal(err)
	}
	date := models.Date(time.Now())
	f.stories = []models.Story{
		{Title: "Voice &amp; news", Text: "Text &lt;one&gt;", VoiceID: &f.voice.ID, StartDate: date, EndDate: date},
		{Title: "No &amp; voice", Text: "Text &lt;two&gt;", StartDate: date, EndDate: date},
	}
	if err := f.tx.Create(&f.stories).Error; err != nil {
		t.Fatal(err)
	}
	return f
}

func TestStoryReadsIntegration_GetByIDJoinsVoice(t *testing.T) {
	f := newJoinedReadFixture(t)
	repo := NewStoryRepository(f.tx)
	for i, story := range f.stories {
		t.Run(fmt.Sprintf("story %d", i), func(t *testing.T) {
			f.queries.Store(0)
			got, err := repo.GetByID(t.Context(), story.ID)
			if err != nil {
				t.Fatal(err)
			}
			if count := f.queries.Load(); count != 1 {
				t.Fatalf("GetByID queries = %d, want 1", count)
			}
			assertJoinedStory(t, got, story.ID, i == 0, f.voice)
		})
	}
}

func TestStoryReadsIntegration_BulletinStoriesJoinVoice(t *testing.T) {
	f := newJoinedReadFixture(t)
	station := models.Station{Name: f.name}
	if err := f.tx.Create(&station).Error; err != nil {
		t.Fatal(err)
	}
	bulletin := models.Bulletin{StationID: station.ID, Filename: f.name + ".wav"}
	if err := f.tx.Create(&bulletin).Error; err != nil {
		t.Fatal(err)
	}
	bulletins := NewBulletinRepository(f.tx)
	if err := bulletins.LinkStories(t.Context(), bulletin.ID, []int64{f.stories[1].ID, f.stories[0].ID}); err != nil {
		t.Fatal(err)
	}
	f.queries.Store(0)
	got, total, err := bulletins.GetBulletinStories(t.Context(), bulletin.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count := f.queries.Load(); count != 3 {
		t.Fatalf("GetBulletinStories queries = %d, want 3", count)
	}
	if total != 2 || len(got) != 2 {
		t.Fatalf("total = %d, rows = %d, want 2 each", total, len(got))
	}
	for i, row := range got {
		story := f.stories[1-i]
		if row.StoryID != story.ID || row.StoryOrder != i {
			t.Fatalf("row %d = %+v, want story %d at order %d", i, row, story.ID, i)
		}
		assertJoinedStory(t, row.Story, story.ID, i == 1, f.voice)
	}
}

func assertJoinedStory(t *testing.T, story *models.Story, id int64, hasVoice bool, voice models.Voice) {
	t.Helper()
	if story == nil {
		t.Fatal("story is nil")
	}
	wantTitle, wantText := "No & voice", "Text <two>"
	if hasVoice {
		wantTitle, wantText = "Voice & news", "Text <one>"
		if story.Voice == nil || story.Voice.ID != voice.ID || story.Voice.Name != voice.Name || story.VoiceName != voice.Name {
			t.Fatalf("voice = %+v, voice_name = %q, want %s", story.Voice, story.VoiceName, voice.Name)
		}
	} else if story.Voice != nil || story.VoiceName != "" {
		t.Fatalf("voice = %+v, voice_name = %q, want no voice", story.Voice, story.VoiceName)
	}
	if story.ID != id || story.Title != wantTitle || story.Text != wantText || story.AudioURL != fmt.Sprintf("/stories/%d/audio", id) {
		t.Fatalf("story = %+v, want decoded text and computed audio URL for %d", story, id)
	}
}

// TestStoryReadsIntegration_ConcurrentListOutsideTransaction runs the count and
// the page on separate connections, with the voice preload and soft-delete
// scope each statement adds.
func TestStoryReadsIntegration_ConcurrentListOutsideTransaction(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	name := fmt.Sprintf("concurrent-list-%d", time.Now().UnixNano())
	voice := models.Voice{Name: name}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	date := models.Date(time.Now())
	stories := []models.Story{
		{Title: name + " a", VoiceID: &voice.ID, StartDate: date, EndDate: date},
		{Title: name + " b", VoiceID: &voice.ID, StartDate: date, EndDate: date},
		{Title: name + " c", VoiceID: &voice.ID, StartDate: date, EndDate: date},
	}
	if err := db.Create(&stories).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Unscoped().Delete(&stories).Error; err != nil {
			t.Errorf("delete stories: %v", err)
		}
		if err := db.Delete(&voice).Error; err != nil {
			t.Errorf("delete voice: %v", err)
		}
	})
	if err := db.Delete(&stories[2]).Error; err != nil {
		t.Fatal(err)
	}

	repo := NewStoryRepository(db)
	for _, test := range []struct {
		trashed   string
		wantTotal int64
		wantTitle string
	}{
		{trashed: "", wantTotal: 2, wantTitle: name + " b"},
		{trashed: TrashedWith, wantTotal: 3, wantTitle: name + " b"},
		{trashed: TrashedOnly, wantTotal: 1},
	} {
		t.Run("trashed="+test.trashed, func(t *testing.T) {
			result, err := repo.List(t.Context(), &ListQuery{
				Limit: 1, Offset: 1, Trashed: test.trashed,
				Sort:    []SortField{{Field: "title", Direction: SortAsc}},
				Filters: []FilterCondition{{Key: "filter[voice_id]", Field: "voice_id", Operator: FilterEquals, Values: []string{fmt.Sprint(voice.ID)}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if result.Total != test.wantTotal {
				t.Fatalf("total = %d, want %d", result.Total, test.wantTotal)
			}
			if test.wantTitle == "" {
				if len(result.Data) != 0 {
					t.Fatalf("page = %+v, want empty page past the only match", result.Data)
				}
				return
			}
			if len(result.Data) != 1 || result.Data[0].Title != test.wantTitle || result.Data[0].VoiceName != voice.Name {
				t.Fatalf("page = %+v, want %q with voice %q", result.Data, test.wantTitle, voice.Name)
			}
		})
	}
}
