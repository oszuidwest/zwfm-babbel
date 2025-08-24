# Modern Query Parameter System

This document describes the comprehensive modern query parameter system implemented for the Babbel API, following 2024 REST API best practices.

## Overview

The query parameter system provides:
- **Modern filtering**: `?filter[field]=value`, `?filter[created_at][gte]=2024-01-01`
- **Advanced sorting**: `?sort=created_at:desc,name:asc` or `?sort=-created_at,+name`
- **Field selection**: `?fields=id,name,created_at` (sparse fieldsets)
- **Search functionality**: `?search=keyword` for full-text search
- **Status filtering**: `?status=all|active|deleted|suspended`
- **Status filters**: `?filter[status]=active|inactive|draft`

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

#### Range Filters (BETWEEN operations)
```http
# Date ranges
GET /api/v1/stories?filter[created_at][between]=2024-01-01,2024-12-31

# Numeric ranges
GET /api/v1/stories?filter[duration_seconds][between]=10,60
```

#### Pattern Matching
```http
# LIKE searches (case-sensitive)
GET /api/v1/stories?filter[title][like]=news

# Case-insensitive searches
GET /api/v1/stories?filter[title][ilike]=NEWS
```

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

### 5. Status Filtering

```http
# Status filtering
GET /api/v1/stories?status=all          # All records
GET /api/v1/stories?status=active       # Only active records
GET /api/v1/stories?status=deleted      # Only deleted records
GET /api/v1/stories?status=draft        # Only drafts

GET /api/v1/users?status=all            # All users
GET /api/v1/users?status=suspended      # Only suspended users
```

### 6. Boolean Filters

```http
# Boolean filters
GET /api/v1/stories?filter[voice_id][ne]=null     # Stories with voice assigned
GET /api/v1/stories?filter[voice_id][null]=true   # Stories without voice
GET /api/v1/stories?filter[audio_file][ne]=       # Stories with audio files
GET /api/v1/stories?filter[status]=active         # Active stories
GET /api/v1/stories?filter[end_date][gte]=2024-06-15  # Non-expired stories
```

### 7. Pagination

```http
# Standard pagination (unchanged)
GET /api/v1/stories?limit=20&offset=40
```

## Endpoint-Specific Examples

### Stories API

```http
# Complex filtering
GET /api/v1/stories?filter[status]=active&filter[voice_id][in]=1,2&filter[created_at][gte]=2024-01-01&filter[audio_file][ne]=&search=breaking&sort=-created_at&fields=id,title,voice_name,created_at

# Date-based filtering
GET /api/v1/stories?filter[start_date][lte]=2024-06-01&filter[end_date][gte]=2024-06-01

# Boolean combinations
GET /api/v1/stories?filter[voice_id][ne]=null&filter[status]=active&filter[audio_file]=
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

# File size filtering
GET /api/v1/bulletins?filter[file_size][gte]=1000000&filter[duration_seconds][between]=60,300
```

### Stations & Voices API

```http
# Search functionality
GET /api/v1/stations?search=radio&sort=name
GET /api/v1/voices?search=john&fields=id,name
```


## Response Format

All endpoints return paginated responses with metadata:

```json
{
  "data": [...],
  "pagination": {
    "total": 150,
    "limit": 20,
    "offset": 40,
    "has_next": true,
    "has_previous": true
  }
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
  "pagination": {...}
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
# Bulk export with date range
GET /api/v1/bulletins?filter[created_at][between]=2024-01-01,2024-12-31&limit=1000&fields=id,filename,created_at,station_name
```

### Integration Testing
```http
# Comprehensive query for testing
GET /api/v1/stories?filter[voice_id][in]=1,2&filter[audio_file][ne]=&search=test&sort=-created_at,+title&fields=id,title,status,created_at&limit=5
```

This modern query parameter system provides a robust, scalable foundation for API querying while maintaining backward compatibility and following 2024 REST API best practices.