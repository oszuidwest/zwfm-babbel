// Package main provides a comprehensive OpenAPI documentation generator for the Babbel API.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// OpenAPISpec represents a simplified OpenAPI specification structure for documentation generation.
type OpenAPISpec struct {
	OpenAPI string `yaml:"openapi"`
	Info    struct {
		Title       string `yaml:"title"`
		Description string `yaml:"description"`
		Version     string `yaml:"version"`
	} `yaml:"info"`
	Servers []struct {
		URL string `yaml:"url"`
	} `yaml:"servers"`
	Paths      map[string]map[string]Operation `yaml:"paths"`
	Components struct {
		Schemas         map[string]interface{} `yaml:"schemas"`
		SecuritySchemes map[string]interface{} `yaml:"securitySchemes"`
		Parameters      map[string]Parameter   `yaml:"parameters"`
	} `yaml:"components"`
	Tags []struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"tags"`
}

// Operation represents an OpenAPI operation definition with its metadata and parameters.
type Operation struct {
	Summary     string                 `yaml:"summary"`
	Description string                 `yaml:"description"`
	Tags        []string               `yaml:"tags"`
	Parameters  []Parameter            `yaml:"parameters"`
	RequestBody map[string]interface{} `yaml:"requestBody"`
	Responses   map[string]interface{} `yaml:"responses"`
	Security    []map[string][]string  `yaml:"security"`
	OperationID string                 `yaml:"operationId"`
}

// Parameter represents an OpenAPI parameter definition with validation schema.
type Parameter struct {
	Name        string                 `yaml:"name"`
	In          string                 `yaml:"in"`
	Required    bool                   `yaml:"required"`
	Description string                 `yaml:"description"`
	Schema      map[string]interface{} `yaml:"schema"`
	Ref         string                 `yaml:"$ref"`
	Example     interface{}            `yaml:"example"`
}

// EndpointInfo holds structured endpoint information for better organization
type EndpointInfo struct {
	Method    string
	Path      string
	Operation Operation
	SortKey   string
}

const markdownTemplate = `# {{.Info.Title}} API Reference

{{.Info.Description}}

**Version:** {{.Info.Version}}  
**Base URL:** {{(index .Servers 0).URL}}

## Table of Contents

1. [Authentication](#authentication)
2. [Authorization](#authorization)
3. [Common Parameters](#common-parameters)
4. [Response Formats](#response-formats)
5. [Error Handling](#error-handling)
6. [API Endpoints](#api-endpoints)
{{range .Tags}}   - [{{.Name}}](#{{lower .Name | replace " " "-"}})
{{end}}

---

## Authentication

The Babbel API uses session-based authentication with encrypted cookies. All endpoints require authentication except:
- ` + "`GET /health`" + ` - Health check endpoint
- ` + "`POST /sessions`" + ` - Login endpoint
- ` + "`GET /auth/config`" + ` - Authentication configuration

### Authentication Methods

1. **Local Authentication**
   - Username/password authentication
   - Login: ` + "`POST /sessions`" + ` with ` + "`{\"username\": \"string\", \"password\": \"string\"}`" + `
   - Returns session cookie valid for 24 hours

2. **OAuth/OIDC Authentication**
   - Supports Microsoft Entra ID, Google, Okta
   - Start flow: ` + "`GET /auth/oauth?frontend_url=<redirect_url>`" + `
   - Auto-provisioning for new users (default role: viewer)

3. **Session Management**
   - Check session: ` + "`GET /sessions/current`" + `
   - Logout: ` + "`DELETE /sessions/current`" + `

## Authorization

Role-based access control (RBAC) with three roles:

| Role | Permissions |
|------|------------|
| **admin** | Full system access including user management |
| **editor** | Create, read, update, delete content (stations, voices, stories, bulletins) |
| **viewer** | Read-only access to all resources |

## Common Parameters

### Pagination
All list endpoints support pagination:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| ` + "`limit`" + ` | integer | 20 | Maximum items per page (1-100) |
| ` + "`offset`" + ` | integer | 0 | Number of items to skip |

### Modern Query Parameters
List endpoints support advanced querying:

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| ` + "`search`" + ` | string | ` + "`search=news`" + ` | Full-text search across searchable fields |
| ` + "`filter[field]`" + ` | string | ` + "`filter[station_id]=5`" + ` | Filter by field value |
| ` + "`filter[field][op]`" + ` | string | ` + "`filter[created_at][gte]=2024-01-01`" + ` | Advanced filtering with operators |
| ` + "`sort`" + ` | string | ` + "`sort=-created_at`" + ` | Sort results (- for DESC, field:asc/desc) |
| ` + "`fields`" + ` | string | ` + "`fields=id,name,created_at`" + ` | Select specific fields to return |

#### Filter Operators
- ` + "`gte`" + `: Greater than or equal
- ` + "`lte`" + `: Less than or equal
- ` + "`gt`" + `: Greater than
- ` + "`lt`" + `: Less than
- ` + "`ne`" + `: Not equal
- ` + "`in`" + `: In list (comma-separated)
- ` + "`between`" + `: Between two values (comma-separated)
- ` + "`like`" + `: Pattern matching (% for wildcard)

### Special Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| ` + "`include_deleted`" + ` | boolean | Include soft-deleted records |
| ` + "`include_suspended`" + ` | boolean | Include suspended users |
| ` + "`download`" + ` | boolean | Force file download with appropriate headers |
| ` + "`force`" + ` | boolean | Force regeneration of cached resources |
| ` + "`max_age`" + ` | integer | Maximum age in seconds for cached resources |

## Response Formats

### Success Response - Single Resource
` + "```json" + `
{
  "id": 1,
  "name": "Example",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
` + "```" + `

### Success Response - List with Pagination
` + "```json" + `
{
  "data": [
    {
      "id": 1,
      "name": "Example 1"
    },
    {
      "id": 2,
      "name": "Example 2"
    }
  ],
  "pagination": {
    "total": 150,
    "limit": 20,
    "offset": 0,
    "has_more": true
  }
}
` + "```" + `

### Created Response
` + "```json" + `
{
  "id": 123,
  "message": "Resource created successfully"
}
` + "```" + `

## Error Handling

The API uses RFC 9457 Problem Details for error responses:

` + "```json" + `
{
  "type": "https://babbel.api/problems/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "The request contains invalid fields",
  "errors": [
    {
      "field": "name",
      "message": "Name is required"
    }
  ]
}
` + "```" + `

### Common Error Types

| Status | Type | Description |
|--------|------|-------------|
| 400 | ` + "`validation-error`" + ` | Invalid request parameters or body |
| 401 | ` + "`unauthorized`" + ` | Missing or invalid authentication |
| 403 | ` + "`forbidden`" + ` | Insufficient permissions |
| 404 | ` + "`not-found`" + ` | Resource not found |
| 409 | ` + "`conflict`" + ` | Resource conflict (duplicate, dependency) |
| 500 | ` + "`internal-server-error`" + ` | Server error |

---

## API Endpoints

{{range $tag := .Tags}}
### {{$tag.Name}}

{{if $tag.Description}}{{$tag.Description}}{{end}}

{{range $endpoint := index $.EndpointsByTag $tag.Name}}
#### {{$endpoint.Operation.Summary}}

` + "`{{$endpoint.Method}} {{$endpoint.Path}}`" + `

{{if $endpoint.Operation.Description}}{{$endpoint.Operation.Description}}{{end}}

{{if $endpoint.Operation.Parameters}}
**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
{{range $param := $endpoint.Operation.Parameters}}| ` + "`{{$param.Name}}`" + ` | {{$param.In}} | {{getParamType $param}} | {{if $param.Required}}Yes{{else}}No{{end}} | {{$param.Description}} |
{{end}}{{end}}

{{if $endpoint.Operation.RequestBody}}
**Request Body:** {{getRequestBodyInfo $endpoint.Operation.RequestBody}}
{{end}}

{{if hasSuccessResponse $endpoint.Operation.Responses}}
**Response:** {{getSuccessResponse $endpoint.Operation.Responses}}
{{end}}

{{if hasErrorResponses $endpoint.Operation.Responses}}
**Error Responses:**
{{range $code, $response := $endpoint.Operation.Responses}}{{if isErrorCode $code}}
- ` + "`{{$code}}`" + `: {{getResponseDescription $response}}{{end}}{{end}}
{{end}}

---
{{end}}
{{end}}

## Additional Resources

- [OpenAPI Specification](../openapi.yaml) - Full API specification
- [Authentication Guide](AUTHENTICATION.md) - Detailed authentication setup
- [Docker Setup](DOCKER.md) - Container deployment guide
- [Development Guide](DEVELOPMENT.md) - Local development setup
`

func main() {
	var (
		input  = flag.String("input", "openapi.yaml", "Input OpenAPI specification file")
		output = flag.String("output", "docs/API_REFERENCE.md", "Output markdown file")
	)
	flag.Parse()

	// Read OpenAPI spec
	data, err := os.ReadFile(*input)
	if err != nil {
		log.Fatalf("Failed to read OpenAPI spec: %v", err)
	}

	// Parse YAML
	var spec OpenAPISpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		log.Fatalf("Failed to parse OpenAPI spec: %v", err)
	}

	// Create output directory if needed
	outputDir := filepath.Dir(*output)
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate markdown
	markdown, err := generateMarkdown(spec)
	if err != nil {
		log.Fatalf("Failed to generate markdown: %v", err)
	}

	// Write output
	if err := os.WriteFile(*output, []byte(markdown), 0600); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	fmt.Printf("✓ Documentation generated at %s\n", *output)
}

func generateMarkdown(spec OpenAPISpec) (string, error) {
	// Group endpoints by tag
	endpointsByTag := make(map[string][]EndpointInfo)

	// Collect all endpoints
	for path, methods := range spec.Paths {
		for method, op := range methods {
			// Resolve parameter references
			resolvedParams := make([]Parameter, 0)
			for _, param := range op.Parameters {
				if param.Ref != "" {
					// Extract parameter name from $ref
					// Format: #/components/parameters/paramName
					parts := strings.Split(param.Ref, "/")
					if len(parts) == 4 && parts[0] == "#" && parts[1] == "components" && parts[2] == "parameters" {
						paramName := parts[3]
						if resolvedParam, ok := spec.Components.Parameters[paramName]; ok {
							resolvedParams = append(resolvedParams, resolvedParam)
						}
					}
				} else {
					resolvedParams = append(resolvedParams, param)
				}
			}
			op.Parameters = resolvedParams

			endpoint := EndpointInfo{
				Method:    strings.ToUpper(method),
				Path:      path,
				Operation: op,
				SortKey:   path + method,
			}

			// Add to each tag
			if len(op.Tags) == 0 {
				op.Tags = []string{"Other"}
			}
			for _, tag := range op.Tags {
				endpointsByTag[tag] = append(endpointsByTag[tag], endpoint)
			}
		}
	}

	// Sort endpoints within each tag
	for tag := range endpointsByTag {
		sort.Slice(endpointsByTag[tag], func(i, j int) bool {
			return endpointsByTag[tag][i].SortKey < endpointsByTag[tag][j].SortKey
		})
	}

	// Ensure all tags are present
	if len(spec.Tags) == 0 {
		// Create tags from collected endpoints
		for tag := range endpointsByTag {
			spec.Tags = append(spec.Tags, struct {
				Name        string `yaml:"name"`
				Description string `yaml:"description"`
			}{Name: tag})
		}
		// Sort tags alphabetically
		sort.Slice(spec.Tags, func(i, j int) bool {
			return spec.Tags[i].Name < spec.Tags[j].Name
		})
	}

	funcMap := template.FuncMap{
		"upper":   strings.ToUpper,
		"lower":   strings.ToLower,
		"replace": strings.ReplaceAll,
		"getParamType": func(param Parameter) string {
			if param.Schema != nil {
				if t, ok := param.Schema["type"].(string); ok {
					return t
				}
			}
			return "string"
		},
		"getRequestBodyInfo": func(rb map[string]interface{}) string {
			if content, ok := rb["content"].(map[string]interface{}); ok {
				var contentTypes []string
				for ct := range content {
					contentTypes = append(contentTypes, ct)
				}

				// Get description if available
				desc := ""
				if d, ok := rb["description"].(string); ok {
					desc = " - " + d
				}

				if len(contentTypes) > 0 {
					return fmt.Sprintf("`%s`%s", contentTypes[0], desc)
				}
			}
			return "Required"
		},
		"hasSuccessResponse": func(responses map[string]interface{}) bool {
			for code := range responses {
				if code == "200" || code == "201" || code == "204" {
					return true
				}
			}
			return false
		},
		"getSuccessResponse": func(responses map[string]interface{}) string {
			codes := []string{"200", "201", "204"}
			for _, code := range codes {
				if resp, ok := responses[code]; ok {
					if respMap, ok := resp.(map[string]interface{}); ok {
						if desc, ok := respMap["description"].(string); ok {
							return fmt.Sprintf("`%s` - %s", code, desc)
						}
					}
					return fmt.Sprintf("`%s`", code)
				}
			}
			return ""
		},
		"hasErrorResponses": func(responses map[string]interface{}) bool {
			for code := range responses {
				if code != "200" && code != "201" && code != "204" {
					return true
				}
			}
			return false
		},
		"isErrorCode": func(code string) bool {
			return code != "200" && code != "201" && code != "204"
		},
		"getResponseDescription": func(response interface{}) string {
			if respMap, ok := response.(map[string]interface{}); ok {
				if desc, ok := respMap["description"].(string); ok {
					return desc
				}
			}
			return "Error"
		},
	}

	// Prepare template data
	templateData := struct {
		OpenAPISpec
		EndpointsByTag map[string][]EndpointInfo
	}{
		OpenAPISpec:    spec,
		EndpointsByTag: endpointsByTag,
	}

	tmpl, err := template.New("markdown").Funcs(funcMap).Parse(markdownTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return "", err
	}

	return buf.String(), nil
}
