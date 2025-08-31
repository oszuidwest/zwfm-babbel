// Package auth provides authentication and authorization services.
package auth

import (
	"github.com/casbin/casbin/v2/model"
	"github.com/jmoiron/sqlx"
)

// CasbinAdapter implements persist.Adapter for Casbin using sqlx
type CasbinAdapter struct {
	db *sqlx.DB
}

// NewCasbinAdapter creates a new Casbin adapter
func NewCasbinAdapter(db *sqlx.DB) *CasbinAdapter {
	return &CasbinAdapter{db: db}
}

// LoadPolicy loads all policy rules from the storage
func (a *CasbinAdapter) LoadPolicy(_ model.Model) error {
	// No-op: policies are loaded elsewhere
	return nil
}

// SavePolicy saves all policy rules to the storage
func (a *CasbinAdapter) SavePolicy(_ model.Model) error {
	// No-op: returns nil
	return nil
}

// AddPolicy adds a policy rule to the storage
func (a *CasbinAdapter) AddPolicy(_ string, _ string, _ []string) error {
	// No-op: returns nil
	return nil
}

// RemovePolicy removes a policy rule from the storage
func (a *CasbinAdapter) RemovePolicy(_ string, _ string, _ []string) error {
	// No-op: returns nil
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage
func (a *CasbinAdapter) RemoveFilteredPolicy(_ string, _ string, _ int, _ ...string) error {
	// No-op: returns nil
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered
func (a *CasbinAdapter) IsFiltered() bool {
	return false
}

// IsAutoSave returns true if the adapter has auto-save feature enabled
func (a *CasbinAdapter) IsAutoSave() bool {
	return false
}
