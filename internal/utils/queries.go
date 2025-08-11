package utils

import "strings"

// Story query constants for common JOIN operations
const (
	StoryWithVoiceQuery = `
        SELECT s.*, v.name as voice_name
        FROM stories s 
        JOIN voices v ON s.voice_id = v.id`

	StoryWithVoiceWhereActive = StoryWithVoiceQuery + ` WHERE s.deleted_at IS NULL`
)

// BuildStoryQuery creates story queries with common joins and conditions
func BuildStoryQuery(baseWhere string, includeDeleted bool) string {
	query := StoryWithVoiceQuery

	conditions := []string{}
	if baseWhere != "" {
		conditions = append(conditions, baseWhere)
	}
	if !includeDeleted {
		conditions = append(conditions, "s.deleted_at IS NULL")
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	return query
}
