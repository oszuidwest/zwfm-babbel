package handlers

import (
	"context"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// BulletinStoryHandler manages bulletin-story relationships.
type BulletinStoryHandler struct {
	db *sqlx.DB
}

// bulletinStoryHandler returns a bulletin-story relationship handler.
func (h *Handlers) bulletinStoryHandler() *BulletinStoryHandler {
	return &BulletinStoryHandler{db: h.db}
}

// Create creates bulletin-story relationships with ordering.
func (bsh *BulletinStoryHandler) Create(ctx context.Context, bulletinID int, stories []models.Story) error {
	if len(stories) == 0 {
		return nil
	}

	placeholders := make([]string, len(stories))
	args := make([]interface{}, len(stories)*3)

	for i, story := range stories {
		placeholders[i] = "(?, ?, ?)"
		args[i*3] = bulletinID
		args[i*3+1] = story.ID
		args[i*3+2] = i
	}

	query := "INSERT INTO bulletin_stories (bulletin_id, story_id, story_order) VALUES " +
		strings.Join(placeholders, ", ")

	_, err := bsh.db.ExecContext(ctx, query, args...)
	return err
}

// LoadStories loads stories for multiple bulletins.
func (bsh *BulletinStoryHandler) LoadStories(ctx context.Context, bulletinIDs []int) (map[int][]models.Story, error) {
	if len(bulletinIDs) == 0 {
		return make(map[int][]models.Story), nil
	}

	placeholders := make([]string, len(bulletinIDs))
	args := make([]interface{}, len(bulletinIDs))
	for i, bulletinID := range bulletinIDs {
		placeholders[i] = "?"
		args[i] = bulletinID
	}

	query := `
		SELECT bs.bulletin_id, s.*, v.name as voice_name
		FROM bulletin_stories bs
		JOIN stories s ON bs.story_id = s.id
		LEFT JOIN voices v ON s.voice_id = v.id
		WHERE bs.bulletin_id IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY bs.bulletin_id, bs.story_order`

	rows, err := bsh.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			logger.Error("Failed to close database rows: %v", closeErr)
		}
	}()

	bulletinStories := make(map[int][]models.Story)
	for rows.Next() {
		var bulletinID int
		var story models.Story

		if err := rows.Scan(
			&bulletinID,
			&story.ID,
			&story.Title,
			&story.Text,
			&story.VoiceID,
			&story.AudioFile,
			&story.DurationSeconds,
			&story.Status,
			&story.StartDate,
			&story.EndDate,
			&story.Weekdays,
			&story.Metadata,
			&story.DeletedAt,
			&story.CreatedAt,
			&story.UpdatedAt,
			&story.VoiceName,
		); err != nil {
			return nil, err
		}

		bulletinStories[bulletinID] = append(bulletinStories[bulletinID], story)
	}

	return bulletinStories, nil
}

// LoadStory loads stories for a single bulletin.
func (bsh *BulletinStoryHandler) LoadStory(ctx context.Context, bulletinID int) ([]models.Story, error) {
	bulletinStories, err := bsh.LoadStories(ctx, []int{bulletinID})
	if err != nil {
		return nil, err
	}

	if stories, exists := bulletinStories[bulletinID]; exists {
		return stories, nil
	}

	return []models.Story{}, nil
}
