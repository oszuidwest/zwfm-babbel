// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

// Story query constants for common JOIN operations
const (
	StoryWithVoiceQuery = `
        SELECT s.*, COALESCE(v.name, '') as voice_name
        FROM stories s
        LEFT JOIN voices v ON s.voice_id = v.id`

	StoryWithVoiceWhereActive = StoryWithVoiceQuery + ` WHERE s.deleted_at IS NULL`
)

// FilterConfig defines configuration for a single filter
type FilterConfig struct {
	Column   string      // Database column name
	Value    interface{} // Filter value
	Operator string      // Comparison operator: "=", "IN", "IS NULL", "IS NOT NULL", ">=", "<=", etc.
	Table    string      // Optional table alias/prefix (e.g. "s" for "s.status")
}

// PostProcessor defines a function to modify results after querying but before response
type PostProcessor func(result interface{})

// QueryConfig defines configuration for GenericListWithJoins
type QueryConfig struct {
	BaseQuery     string         // SELECT ... FROM ... JOIN ... part
	CountQuery    string         // SELECT COUNT(*) FROM ... JOIN ... part
	Filters       []FilterConfig // Dynamic filters to apply
	DefaultOrder  string         // Default ORDER BY clause (without ORDER BY keyword)
	AllowedArgs   []interface{}  // Base arguments for the queries
	PostProcessor PostProcessor  // Optional function to process results after query
}
