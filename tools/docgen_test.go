package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGeneratedReferenceTreats2xxAsSuccess(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec OpenAPISpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	markdown, err := generateMarkdown(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(markdown, "**Response:** `202` -") {
		t.Fatal("bulletin generation's 202 response is missing from success responses")
	}
	for _, code := range []string{"202", "206"} {
		if strings.Contains(markdown, "- `"+code+"`:") {
			t.Errorf("%s is listed as an error", code)
		}
	}
}
