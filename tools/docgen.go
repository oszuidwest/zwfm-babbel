// Package main provides a simple OpenAPI documentation generator for the Babbel API.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// OpenAPI structures (simplified)
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
	Paths map[string]map[string]Operation `yaml:"paths"`
}

type Operation struct {
	Summary     string                 `yaml:"summary"`
	Description string                 `yaml:"description"`
	Tags        []string               `yaml:"tags"`
	Parameters  []Parameter            `yaml:"parameters"`
	RequestBody map[string]interface{} `yaml:"requestBody"`
	Responses   map[string]interface{} `yaml:"responses"`
}

type Parameter struct {
	Name        string                 `yaml:"name"`
	In          string                 `yaml:"in"`
	Required    bool                   `yaml:"required"`
	Description string                 `yaml:"description"`
	Schema      map[string]interface{} `yaml:"schema"`
	Ref         string                 `yaml:"$ref"`
}

const markdownTemplate = `# {{.Info.Title}}

{{.Info.Description}}

**Version:** {{.Info.Version}}  
**Base URL:** {{(index .Servers 0).URL}}

## Authentication

All endpoints require session-based authentication (except health and login).

**Login:** ` + "`POST /session/login`" + ` with ` + "`{\"username\": \"admin\", \"password\": \"admin\"}`" + `

## API Endpoints

| Method | Endpoint | Description | Parameters | Request Body |
|--------|----------|-------------|------------|--------------|
{{range $path, $methods := .Paths}}{{range $method, $op := $methods}}| {{upper $method}} | {{$path}} | {{$op.Summary}} | {{getParams $op.Parameters}} | {{getRequestBody $op.RequestBody}} |
{{end}}{{end}}

## Response Formats

**Paginated List:**
` + "```json" + `
{"data": [...], "total": 150, "limit": 20, "offset": 0}
` + "```" + `

**Error:**
` + "```json" + `
{"error": "error_code", "message": "Human readable message"}
` + "```" + `

## Common Parameters

- ` + "`limit`" + `/` + "`offset`" + `: Pagination (default: 20/0)
- ` + "`station_id`" + `, ` + "`voice_id`" + `: Filter by ID
- ` + "`include_deleted`" + `, ` + "`include_suspended`" + `: Include soft-deleted records
- ` + "`download=true`" + `: Download file instead of JSON
- ` + "`force=true`" + `: Force new generation
- ` + "`max_age=300`" + `: Reuse if created within seconds
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
	funcMap := template.FuncMap{
		"upper": strings.ToUpper,
		"getParams": func(params []Parameter) string {
			if len(params) == 0 {
				return "-"
			}
			var result []string
			for _, p := range params {
				paramStr := p.Name
				if p.Required {
					paramStr += "*"
				}
				result = append(result, paramStr)
			}
			return strings.Join(result, ", ")
		},
		"getRequestBody": func(rb map[string]interface{}) string {
			if len(rb) == 0 {
				return "-"
			}
			if content, ok := rb["content"].(map[string]interface{}); ok {
				for contentType := range content {
					if strings.Contains(contentType, "json") {
						return "JSON"
					}
					if strings.Contains(contentType, "form-data") {
						return "Form"
					}
					return "Body"
				}
			}
			return "Body"
		},
	}

	tmpl, err := template.New("markdown").Funcs(funcMap).Parse(markdownTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, spec); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func formatSchema(schema interface{}) string {
	// Simplified schema formatting
	if schemaMap, ok := schema.(map[string]interface{}); ok {
		if schemaData, ok := schemaMap["schema"].(map[string]interface{}); ok {
			return formatSchemaData(schemaData, 0)
		}
	}
	return "See OpenAPI specification for schema details"
}

func formatSchemaData(schema map[string]interface{}, indent int) string {
	var result strings.Builder
	prefix := strings.Repeat("  ", indent)

	if t, ok := schema["type"].(string); ok {
		result.WriteString(fmt.Sprintf("%sType: %s\n", prefix, t))
	}

	if props, ok := schema["properties"].(map[string]interface{}); ok {
		result.WriteString(fmt.Sprintf("%sProperties:\n", prefix))
		for name := range props {
			result.WriteString(fmt.Sprintf("%s  - %s\n", prefix, name))
		}
	}

	return result.String()
}
