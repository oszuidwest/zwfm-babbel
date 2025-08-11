// Package utils provides database utilities for count query operations
package utils

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

// CountRecords returns the count of records in a table with optional WHERE clause
func CountRecords(db *sqlx.DB, tableName string, whereClause string, args ...interface{}) (int64, error) {
	var count int64
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", tableName)

	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}

	return count, nil
}

// CountWithJoins returns the count of records with complex query (with joins)
func CountWithJoins(db *sqlx.DB, query string, args ...interface{}) (int64, error) {
	var count int64

	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}

	return count, nil
}

// CountDependencies counts records that depend on a specific foreign key
func CountDependencies(db *sqlx.DB, tableName, foreignKeyColumn string, id int) (int, error) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s = ?", tableName, foreignKeyColumn)

	if err := db.Get(&count, query, id); err != nil {
		return 0, err
	}

	return count, nil
}

// CountByCondition counts records that meet a specific condition
func CountByCondition(db *sqlx.DB, tableName, condition string, args ...interface{}) (int, error) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", tableName, condition)

	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}

	return count, nil
}

// CountActivesExcludingID counts active records (not suspended/deleted) excluding a specific ID
func CountActivesExcludingID(db *sqlx.DB, tableName, condition string, id int) (int, error) {
	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s AND id != ?", tableName, condition)

	if err := db.Get(&count, query, id); err != nil {
		return 0, err
	}

	return count, nil
}
