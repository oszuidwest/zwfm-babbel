package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
)

func TestNestedListsValidateBeforeParentLookup(t *testing.T) {
	db, err := gorm.Open(mysql.New(mysql.Config{DSN: "babbel@unix(" + filepath.Join(t.TempDir(), "none.sock") + ")/babbel", SkipInitializeWithVersion: true}),
		&gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	queries := 0
	if err := db.Callback().Query().Before("gorm:query").Register("count", func(*gorm.DB) { queries++ }); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{
		stationSvc:  services.NewStationService(repository.NewStationRepository(db)),
		bulletinSvc: services.NewBulletinService(services.BulletinServiceDeps{BulletinRepo: repository.NewBulletinRepository(db)}),
		storySvc: services.NewStoryService(services.StoryServiceDeps{StoryRepo: repository.NewStoryRepository(db),
			PronunciationInjector: &services.PronunciationInjector{}, TxManager: repository.NewTxManager(db)}),
	}
	for name, handler := range map[string]gin.HandlerFunc{"station": h.GetStationBulletins, "bulletin": h.GetBulletinStories, "story": h.GetStoryBulletinHistory} {
		for _, query := range []string{"?bogus=1", "?limit=1"} {
			t.Run(name+query, func(t *testing.T) {
				queries = 0
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x/999"+query, nil)
				c.Params = gin.Params{{Key: "id", Value: "999"}}
				handler(c)
				wantStatus, wantQueries := http.StatusNotFound, 1
				if query == "?bogus=1" {
					wantStatus, wantQueries = http.StatusUnprocessableEntity, 0
				}
				if rec.Code != wantStatus || queries != wantQueries {
					t.Fatalf("status = %d, queries = %d; want %d, %d", rec.Code, queries, wantStatus, wantQueries)
				}
			})
		}
	}
}
