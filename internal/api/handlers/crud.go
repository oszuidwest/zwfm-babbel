package handlers

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
)

// CRUDHandler provides generic CRUD operations for database models
type CRUDHandler struct {
	db            *sqlx.DB
	tableName     string
	tableAlias    string // extracted alias if table name contains one
	orderBy       string
	selectCols    string
	joins         string
	softDeleteCol string // column name for soft delete (e.g., "deleted_at", "suspended_at")
}

// DependencyCheck defines a check to run before deletion
type DependencyCheck struct {
	Query        string
	ErrorMessage string // Should contain %d for count
}

// NewCRUDHandler creates a new CRUD handler
func NewCRUDHandler(db *sqlx.DB, tableName string, options ...CRUDOption) *CRUDHandler {
	h := &CRUDHandler{
		db:         db,
		tableName:  tableName,
		orderBy:    "id DESC",
		selectCols: "*",
	}

	// Extract table alias if present (e.g., "station_voices sv" -> alias is "sv")
	parts := strings.Fields(tableName)
	if len(parts) > 1 {
		h.tableAlias = parts[1]
	} else {
		h.tableAlias = tableName
	}

	for _, opt := range options {
		opt(h)
	}

	return h
}

// CRUDOption configures a CRUDHandler during initialization.
type CRUDOption func(*CRUDHandler)

// WithOrderBy sets the default order by clause
func WithOrderBy(orderBy string) CRUDOption {
	return func(h *CRUDHandler) {
		h.orderBy = orderBy
	}
}

// WithSelectColumns sets the columns to select
func WithSelectColumns(cols string) CRUDOption {
	return func(h *CRUDHandler) {
		h.selectCols = cols
	}
}

// WithJoins sets the join clauses
func WithJoins(joins string) CRUDOption {
	return func(h *CRUDHandler) {
		h.joins = joins
	}
}

// WithSoftDelete enables soft delete filtering with the specified column
func WithSoftDelete(column string) CRUDOption {
	return func(h *CRUDHandler) {
		h.softDeleteCol = column
	}
}

// List handles generic list operations with pagination and filtering.
func (h *CRUDHandler) List(c *gin.Context, dest interface{}, filters map[string]string) (int64, error) {
	limit, offset := extractPaginationParams(c)

	// Build base query
	baseQuery := fmt.Sprintf("SELECT %s FROM %s", h.selectCols, h.tableName)
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s", h.tableName)

	if h.joins != "" {
		baseQuery += " " + h.joins
		countQuery += " " + h.joins
	}

	// Build WHERE clause from filters
	whereClauses := []string{"1=1"}
	args := []interface{}{}

	for field, paramName := range filters {
		if value := c.Query(paramName); value != "" {
			whereClauses = append(whereClauses, fmt.Sprintf("%s = ?", field))
			args = append(args, value)
		}
	}

	// Handle soft delete filtering
	if h.softDeleteCol != "" {
		// Check for include_deleted/include_suspended parameter
		includeParam := "include_deleted"
		if h.softDeleteCol == "suspended_at" {
			includeParam = "include_suspended"
		}

		if c.Query(includeParam) != "true" {
			// By default, exclude soft-deleted records
			alias := h.tableAlias
			if alias != "" && alias != h.tableName {
				whereClauses = append(whereClauses, fmt.Sprintf("%s.%s IS NULL", alias, h.softDeleteCol))
			} else {
				whereClauses = append(whereClauses, fmt.Sprintf("%s IS NULL", h.softDeleteCol))
			}
		}
	}

	whereClause := " WHERE " + strings.Join(whereClauses, " AND ")
	baseQuery += whereClause
	countQuery += whereClause

	// Get total count
	var total int64
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := h.db.Get(&total, countQuery, countArgs...); err != nil {
		return 0, fmt.Errorf("failed to count records: %w", err)
	}

	// Add ordering and pagination
	baseQuery += fmt.Sprintf(" ORDER BY %s LIMIT ? OFFSET ?", h.orderBy)
	args = append(args, limit, offset)

	// Execute query
	if err := h.db.Select(dest, baseQuery, args...); err != nil {
		return 0, fmt.Errorf("failed to fetch records: %w", err)
	}

	return total, nil
}

// GetByID handles fetching a single record by ID
func (h *CRUDHandler) GetByID(c *gin.Context, id int, dest interface{}) {
	query := fmt.Sprintf("SELECT %s FROM %s", h.selectCols, h.tableName)
	if h.joins != "" {
		query += " " + h.joins
	}
	query += fmt.Sprintf(" WHERE %s.id = ?", h.tableAlias)

	// Exclude soft-deleted records
	if h.softDeleteCol != "" {
		alias := h.tableAlias
		if alias != "" && alias != h.tableName {
			query += fmt.Sprintf(" AND %s.%s IS NULL", alias, h.softDeleteCol)
		} else {
			query += fmt.Sprintf(" AND %s IS NULL", h.softDeleteCol)
		}
	}

	err := h.db.Get(dest, query, id)
	if err == sql.ErrNoRows {
		responses.NotFound(c, "Record not found")
		return
	}
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch record")
		return
	}

	responses.Success(c, dest)
}

// Delete handles generic delete operations
func (h *CRUDHandler) Delete(c *gin.Context, id int) {
	// If soft delete is configured, use SoftDelete instead
	if h.softDeleteCol != "" {
		h.SoftDelete(c, id)
		return
	}

	// Check if record exists
	var exists bool
	checkQuery := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id = ?)", h.tableName)
	if err := h.db.Get(&exists, checkQuery, id); err != nil || !exists {
		responses.NotFound(c, "Record not found")
		return
	}

	// Delete record
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE id = ?", h.tableName)
	if _, err := h.db.ExecContext(c.Request.Context(), deleteQuery, id); err != nil {
		handleDatabaseError(c, err, "delete")
		return
	}

	responses.NoContent(c)
}

// SoftDelete performs a soft delete by setting the soft delete column to NOW()
func (h *CRUDHandler) SoftDelete(c *gin.Context, id int) {
	if h.softDeleteCol == "" {
		responses.InternalServerError(c, "Soft delete not configured")
		return
	}

	// Check if record exists and is not already deleted
	var exists bool
	checkQuery := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id = ? AND %s IS NULL)",
		h.tableName, h.softDeleteCol)
	if err := h.db.Get(&exists, checkQuery, id); err != nil || !exists {
		responses.NotFound(c, "Record not found")
		return
	}

	// Soft delete by setting timestamp
	updateQuery := fmt.Sprintf("UPDATE %s SET %s = NOW() WHERE id = ?", h.tableName, h.softDeleteCol)
	if _, err := h.db.ExecContext(c.Request.Context(), updateQuery, id); err != nil {
		responses.InternalServerError(c, "Failed to delete record")
		return
	}

	responses.NoContent(c)
}

// Restore reverses a soft delete by setting the soft delete column to NULL
func (h *CRUDHandler) Restore(c *gin.Context, id int) {
	if h.softDeleteCol == "" {
		responses.InternalServerError(c, "Soft delete not configured")
		return
	}

	// Check if record exists and is deleted
	var exists bool
	checkQuery := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id = ? AND %s IS NOT NULL)",
		h.tableName, h.softDeleteCol)
	if err := h.db.Get(&exists, checkQuery, id); err != nil || !exists {
		responses.NotFound(c, "Record not found or not deleted")
		return
	}

	// Restore by setting timestamp to NULL
	updateQuery := fmt.Sprintf("UPDATE %s SET %s = NULL WHERE id = ?", h.tableName, h.softDeleteCol)
	if _, err := h.db.ExecContext(c.Request.Context(), updateQuery, id); err != nil {
		responses.InternalServerError(c, "Failed to restore record")
		return
	}

	responses.Success(c, gin.H{"message": "Record restored successfully"})
}

// DeleteWithCheck performs a delete with dependency checking
func (h *CRUDHandler) DeleteWithCheck(c *gin.Context, id int, checks []DependencyCheck) {
	// Check if record exists
	var exists bool
	checkQuery := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id = ?)", h.tableName)
	if err := h.db.Get(&exists, checkQuery, id); err != nil || !exists {
		responses.NotFound(c, "Record not found")
		return
	}

	// Run dependency checks
	for _, check := range checks {
		var count int
		if err := h.db.Get(&count, check.Query, id); err != nil {
			responses.InternalServerError(c, "Failed to check dependencies")
			return
		}
		if count > 0 {
			responses.BadRequest(c, fmt.Sprintf(check.ErrorMessage, count))
			return
		}
	}

	// Delete record
	deleteQuery := fmt.Sprintf("DELETE FROM %s WHERE id = ?", h.tableName)
	if _, err := h.db.ExecContext(c.Request.Context(), deleteQuery, id); err != nil {
		handleDatabaseError(c, err, "delete")
		return
	}

	responses.NoContent(c)
}

// QueryBuilder helps construct dynamic SQL update queries.
type QueryBuilder struct {
	updates []string
	args    []interface{}
}

// NewQueryBuilder creates a new QueryBuilder instance.
func NewQueryBuilder() *QueryBuilder {
	return &QueryBuilder{
		updates: make([]string, 0),
		args:    make([]interface{}, 0),
	}
}

// AddUpdate adds an update clause if the value is not empty.
func (qb *QueryBuilder) AddUpdate(column, value string) {
	if value != "" {
		qb.updates = append(qb.updates, fmt.Sprintf("%s = ?", column))
		qb.args = append(qb.args, value)
	}
}

// AddUpdateInt adds an integer update clause if the value is not zero.
func (qb *QueryBuilder) AddUpdateInt(column string, value int) {
	if value != 0 {
		qb.updates = append(qb.updates, fmt.Sprintf("%s = ?", column))
		qb.args = append(qb.args, value)
	}
}

// AddUpdateFloat adds a float update clause, optionally including zero values.
func (qb *QueryBuilder) AddUpdateFloat(column string, value float64, includeZero bool) {
	if includeZero || value != 0 {
		qb.updates = append(qb.updates, fmt.Sprintf("%s = ?", column))
		qb.args = append(qb.args, value)
	}
}

// BuildUpdateQuery constructs the final UPDATE SQL query with bound parameters.
func (qb *QueryBuilder) BuildUpdateQuery(tableName string, id int) (string, []interface{}) {
	if len(qb.updates) == 0 {
		return "", nil
	}

	query := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?",
		tableName,
		strings.Join(qb.updates, ", "))

	qb.args = append(qb.args, id)
	return query, qb.args
}

// HasUpdates reports whether there are any update clauses to apply.
func (qb *QueryBuilder) HasUpdates() bool {
	return len(qb.updates) > 0
}

// handleDatabaseError converts database errors to appropriate HTTP responses
func handleDatabaseError(c *gin.Context, err error, operation string) {
	// Check for MySQL specific errors
	if mysqlErr, ok := err.(*mysql.MySQLError); ok {
		switch mysqlErr.Number {
		case 1062: // Duplicate entry
			// Extract field name from error message
			if strings.Contains(mysqlErr.Message, "name") {
				responses.BadRequest(c, "A record with this name already exists")
			} else {
				responses.BadRequest(c, "This record already exists")
			}
			return
		case 1451: // Cannot delete parent row (foreign key constraint)
			responses.BadRequest(c, "Cannot delete this record: other records depend on it")
			return
		case 1452: // Cannot add/update child row (foreign key constraint)
			responses.BadRequest(c, "Invalid reference: the related record does not exist")
			return
		}
	}

	// Generic error
	responses.InternalServerError(c, fmt.Sprintf("Failed to %s record", operation))
}
