# Modern Query Parameter System

This document describes the comprehensive modern query parameter system implemented for the Babbel API, following 2024 REST API best practices.

## Overview

The query parameter system provides:
- **Modern filtering**: `?filter[field]=value`, `?filter[created_at][gte]=2024-01-01`
- **Advanced sorting**: `?sort=created_at:desc,name:asc` or `?sort=-created_at,+name`
- **Field selection**: `?fields=id,name,created_at` (sparse fieldsets)
- **Search functionality**: `?search=keyword` for full-text search
- **Soft-delete filtering**: `?trashed=only|with` for controlling visibility of deleted records
- **Status field filters**: `?filter[status]=active|draft|expired` for filtering by status column

## Modern Query Parameter Formats

### 1. Filtering

#### Simple Filters
```http
# Equal filter
GET /api/v1/stories?filter[status]=active

# Not equal filter  
GET /api/v1/stories?filter[status][ne]=draft

# Greater than/less than
GET /api/v1/stories?filter[created_at][gte]=2024-01-01
GET /api/v1/stories?filter[created_at][lt]=2024-12-31
```

#### Array Filters (IN operations)
```http
# Multiple values
GET /api/v1/stories?filter[status][in]=active,draft
GET /api/v1/stories?filter[voice_id][in]=1,2,3
```

#### Pattern Matching
```http
# LIKE searches (case-sensitive pattern matching)
GET /api/v1/stories?filter[title][like]=%news%
```

#### Bitwise Filtering (Bitmask Fields)
```http
# Bitwise AND for bitmask fields like weekdays
# Returns records where (field & value) != 0
GET /api/v1/stories?filter[weekdays][band]=2      # Stories that play on Monday
GET /api/v1/stories?filter[weekdays][band]=64     # Stories that play on Saturday
GET /api/v1/stories?filter[weekdays][band]=65     # Stories that play on weekend (Sat=64 + Sun=1)
```

The `band` (bitwise AND) operator is restricted to specific fields for security:
- `weekdays` - Story scheduling bitmask (Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64)

> **Note:** The `between` and `ilike` operators are not yet implemented. Use `gte` and `lte` for range queries, and `like` for pattern matching.

### 2. Sorting

#### Colon Notation
```http
# Single field
GET /api/v1/stories?sort=created_at:desc

# Multiple fields
GET /api/v1/stories?sort=created_at:desc,title:asc
```

#### Prefix Notation
```http
# Descending (minus prefix)
GET /api/v1/stories?sort=-created_at

# Ascending (plus prefix or no prefix)
GET /api/v1/stories?sort=+title
GET /api/v1/stories?sort=title

# Multiple fields
GET /api/v1/stories?sort=-created_at,+title
```

### 3. Field Selection (Sparse Fieldsets)

```http
# Select specific fields only
GET /api/v1/stories?fields=id,title,created_at

# Reduce response size for mobile apps
GET /api/v1/users?fields=id,username,role
```

### 4. Search

```http
# Full-text search across configured fields
GET /api/v1/stories?search=breaking news
GET /api/v1/users?search=john.doe@example.com
GET /api/v1/stations?search=radio
```

### 5. Soft-Delete Filtering

The `trashed` parameter controls visibility of soft-deleted records:

```http
# Soft-delete filtering (controls deleted_at column)
GET /api/v1/stories                     # Only non-deleted records (default)
GET /api/v1/stories?trashed=only        # Only soft-deleted records
GET /api/v1/stories?trashed=with        # All records including deleted

GET /api/v1/users?trashed=with          # All users including deleted
GET /api/v1/users?trashed=only          # Only deleted users
```

To filter by the `status` field (e.g., draft/active/expired), use `filter[status]`:

```http
# Status field filtering (filters by status column value)
GET /api/v1/stories?filter[status]=active    # Only stories with status='active'
GET /api/v1/stories?filter[status]=draft     # Only draft stories
```

### 6. Common Filter Patterns

```http
# Active stories
GET /api/v1/stories?filter[status]=active

# Non-expired stories (active on or after date)
GET /api/v1/stories?filter[end_date][gte]=2024-06-15

# Stories created in a date range (use gte + lte instead of between)
GET /api/v1/stories?filter[created_at][gte]=2024-01-01&filter[created_at][lte]=2024-12-31
```

> **Note:** The `null` operator is not yet implemented. Use explicit field filters instead.

### 7. Pagination

```http
# Standard pagination (unchanged)
GET /api/v1/stories?limit=20&offset=40
```

## Endpoint-Specific Examples

### Stories API

```http
# Complex filtering with multiple conditions
GET /api/v1/stories?filter[status]=active&filter[voice_id][in]=1,2&filter[created_at][gte]=2024-01-01&search=breaking&sort=-created_at&fields=id,title,voice_name,created_at

# Date-based filtering (active stories on a specific date)
GET /api/v1/stories?filter[start_date][lte]=2024-06-01&filter[end_date][gte]=2024-06-01

# Filter by status and voice
GET /api/v1/stories?filter[status]=active&filter[voice_id][in]=1,2,3
```

### Users API

```http
# Role and status filtering
GET /api/v1/users?filter[role]=editor&status=all&search=john&sort=username

# Date range queries
GET /api/v1/users?filter[last_login_at][gte]=2024-01-01&filter[login_count][gt]=10
```

### Bulletins API

```http
# Station filtering with search
GET /api/v1/bulletins?filter[station_id]=1&search=morning&sort=-created_at&fields=id,filename,created_at,station_name

# File size and duration filtering (use gte/lte for ranges)
GET /api/v1/bulletins?filter[file_size][gte]=1000000&filter[duration_seconds][gte]=60&filter[duration_seconds][lte]=300
```

### Stations & Voices API

```http
# Search functionality
GET /api/v1/stations?search=radio&sort=name
GET /api/v1/voices?search=john&fields=id,name
```


## Response Format

All endpoints return paginated responses with metadata at the root level:

```json
{
  "data": [...],
  "total": 150,
  "limit": 20,
  "offset": 40
}
```

### Field Selection Response

When using `fields` parameter, only requested fields are returned:

```http
GET /api/v1/stories?fields=id,title,created_at
```

```json
{
  "data": [
    {
      "id": 1,
      "title": "Breaking News",
      "created_at": "2024-01-01T10:00:00Z"
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

## Implementation Details

### Core Components

1. **`/internal/utils/query.go`**: Modern query parameter parsing and processing
2. **`/internal/utils/queries.go`**: Enhanced database query building utilities
3. **Handler Updates**: All major handlers updated to support modern parameters

### Key Features

- **Type Safety**: Proper type conversion and validation
- **SQL Injection Protection**: Parameterized queries throughout
- **Performance**: Optimized query building and field mapping
- **Extensibility**: Easy to add new filter types and operations
- **Validation**: Comprehensive input validation and error handling

### Search Configuration

Each endpoint defines searchable fields:

```go
SearchFields: []string{"s.title", "s.text", "v.name"}
```

### Field Mapping

API field names map to database columns:

```go
FieldMapping: map[string]string{
    "id":         "s.id",
    "title":      "s.title",
    "voice_name": "v.name",
}
```

## Error Handling

The system provides detailed error responses for invalid parameters:

```json
{
  "error": "Validation failed",
  "details": [
    "Invalid date format for created_at. Use YYYY-MM-DD",
    "Invalid sort field: invalid_field",
    "Invalid filter operator 'foo' for field 'status'"
  ]
}
```

## Performance Considerations

- **Field Selection**: Reduces payload size and database load
- **Efficient Queries**: Smart WHERE clause building
- **Index Usage**: Proper column mapping preserves index usage
- **Pagination**: Consistent limit/offset handling
- **Caching**: Query parsing results can be cached

## Future Enhancements

Potential additions for future versions:
- **Aggregation**: `?aggregate[field]=sum,avg,count`
- **Joins**: `?include=voice,station` for related data
- **Bulk Operations**: Query parameter-based bulk updates
- **GraphQL-style**: More flexible field selection syntax
- **Real-time**: WebSocket query parameter support

## Implementation Guide

### For API Consumers

1. **Use modern parameters**: All endpoints support the modern query system
2. **Optimize**: Use field selection to reduce bandwidth
3. **Search**: Implement full-text search where applicable
4. **Filter precisely**: Use the filter operators for exact matching

### For Developers

1. **New Endpoints**: Use `ModernListWithQuery` for all list endpoints
2. **Configuration**: Define search fields and field mappings
3. **Testing**: Test modern parameter combinations
4. **Documentation**: Update API documentation with examples

## Examples by Use Case

### Mobile App Optimization
```http
# Minimal fields for mobile list view
GET /api/v1/stories?fields=id,title,voice_name&limit=10&filter[audio_file][ne]=&sort=-created_at
```

### Admin Dashboard
```http
# Full featured admin query with search and filters
GET /api/v1/stories?search=breaking&filter[created_at][gte]=2024-01-01&status=all&sort=-created_at
```

### Data Export
```http
# Bulk export with date range (use gte + lte for ranges)
GET /api/v1/bulletins?filter[created_at][gte]=2024-01-01&filter[created_at][lte]=2024-12-31&limit=1000&fields=id,filename,created_at,station_name
```

### Integration Testing
```http
# Comprehensive query for testing
GET /api/v1/stories?filter[voice_id][in]=1,2&filter[audio_file][ne]=&search=test&sort=-created_at,+title&fields=id,title,status,created_at&limit=5
```

This modern query parameter system provides a robust, scalable foundation for API querying while maintaining backward compatibility and following 2024 REST API best practices.