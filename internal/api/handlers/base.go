// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// Handlers contains all the dependencies needed by the API handlers
type Handlers struct {
	db       *sqlx.DB
	audioSvc *audio.Service
	config   *config.Config
}

// NewHandlers creates a new Handlers instance with the given dependencies
func NewHandlers(db *sqlx.DB, audioSvc *audio.Service, cfg *config.Config) *Handlers {
	return &Handlers{
		db:       db,
		audioSvc: audioSvc,
		config:   cfg,
	}
}
