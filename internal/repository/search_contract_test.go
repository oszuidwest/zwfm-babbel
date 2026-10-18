package repository

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Searchable operations must document the fields the repository really uses.
func TestSearchFieldsMatchOpenAPI(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]struct {
			Get struct {
				Fields     []string `yaml:"x-search-fields"`
				Parameters []struct {
					Ref string `yaml:"$ref"`
				} `yaml:"parameters"`
			} `yaml:"get"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	fieldsByPath := map[string][]string{
		"/api/v1/stations":                stationSearchFields,
		"/api/v1/voices":                  voiceSearchFields,
		"/api/v1/stories":                 storySearchFields,
		"/api/v1/users":                   userSearchFields,
		"/api/v1/bulletins":               bulletinSearchFields,
		"/api/v1/stations/{id}/bulletins": bulletinSearchFields,
		"/api/v1/stories/{id}/bulletins":  bulletinSearchFields,
	}
	for path, operation := range spec.Paths {
		searchable := false
		for _, parameter := range operation.Get.Parameters {
			searchable = searchable || parameter.Ref == "#/components/parameters/search"
		}
		if !searchable {
			if len(operation.Get.Fields) != 0 {
				t.Errorf("%s declares search fields without search", path)
			}
			continue
		}
		expected, ok := fieldsByPath[path]
		if !ok {
			t.Errorf("%s needs a repository search-field mapping", path)
			continue
		}
		want := make([]string, len(expected))
		for i, field := range expected {
			want[i] = field[strings.LastIndex(field, ".")+1:]
		}
		slices.Sort(want)
		got := slices.Clone(operation.Get.Fields)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s x-search-fields = %v, repository uses %v", path, got, want)
		}
		delete(fieldsByPath, path)
	}
	for path := range fieldsByPath {
		t.Errorf("%s is missing its search parameter", path)
	}
}
