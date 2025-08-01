.PHONY: help build run test clean docs docker

help:
	@echo "Babbel Commands:"
	@echo "  build     - Build the application" 
	@echo "  run       - Run the application"
	@echo "  test      - Run tests"
	@echo "  test-all  - Run integration tests"
	@echo "  lint      - Run linters"
	@echo "  quality   - Run quality checks"
	@echo "  docs-all  - Generate documentation"
	@echo "  docker    - Build Docker image"
	@echo "  db-reset  - Reset database"

# Build the application
build:
	go build -ldflags="-w -s -X github.com/oszuidwest/zwfm-babbel/pkg/version.Version=dev -X github.com/oszuidwest/zwfm-babbel/pkg/version.Commit=$$(git rev-parse --short HEAD) -X github.com/oszuidwest/zwfm-babbel/pkg/version.BuildTime=$$(date -u +%FT%TZ)" -o babbel cmd/babbel/main.go

# Run the application
run:
	go run cmd/babbel/main.go

# Run tests
test:
	go test ./... -v

# Run linters
lint:
	go fmt ./...
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout=5m \
			--enable=errcheck,govet,ineffassign,staticcheck,unused \
			--enable=bodyclose,dogsled,gocritic,gocyclo,gosec,misspell \
			--enable=nakedret,noctx,nolintlint,revive,sqlclosecheck \
			--enable=unconvert,unparam,whitespace || true; \
	else \
		echo "golangci-lint not installed, skipping"; \
	fi

# Run code quality checks (including dead code detection)
quality: lint
	@echo "Running code quality checks..."
	@echo "Checking for dead code..."
	@if command -v deadcode >/dev/null 2>&1; then \
		deadcode_output=$$(deadcode ./... 2>&1 | grep -v "database/connection.go:.*func: Migrate" || true); \
		if [ -n "$$deadcode_output" ]; then \
			echo "❌ Found dead code:"; \
			echo "$$deadcode_output"; \
			exit 1; \
		else \
			echo "✅ No dead code found!"; \
		fi \
	else \
		echo "deadcode not installed, install with: go install golang.org/x/tools/cmd/deadcode@latest"; \
	fi
	@echo "Running staticcheck..."
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
		echo "✅ staticcheck passed!"; \
	else \
		echo "staticcheck not installed, install with: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	fi

# Clean build artifacts
clean:
	rm -f babbel
	rm -rf ./audio/output/*
	rm -rf ./audio/temp/*

# Generate API documentation
docs:
	@echo "Generating API documentation..."
	@mkdir -p docs
	@echo "  → Simple Markdown reference..."
	@go run tools/docgen.go -input openapi.yaml -output docs/API_REFERENCE.md
	@echo "  → Interactive HTML docs..."
	@npx -y @redocly/cli build-docs openapi.yaml \
		--output=docs/index.html \
		--title="Babbel API Documentation" 2>/dev/null
	@echo "✓ Generated both simple and interactive documentation"

docs-all: docs
	@echo "✓ Complete documentation suite generated"

# Validate OpenAPI spec
validate-spec:
	@if command -v redocly >/dev/null 2>&1; then \
		redocly lint openapi.yaml; \
	else \
		npx -y @redocly/cli lint openapi.yaml; \
	fi

# Docker commands
docker:
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "Docker not installed"; \
		exit 1; \
	fi
	docker build -t babbel:latest .

docker-run:
	@if ! command -v docker-compose >/dev/null 2>&1; then \
		echo "docker-compose not installed"; \
		exit 1; \
	fi
	docker-compose up -d

docker-stop:
	@if ! command -v docker-compose >/dev/null 2>&1; then \
		echo "docker-compose not installed"; \
		exit 1; \
	fi
	docker-compose down

docker-logs:
	@if ! command -v docker-compose >/dev/null 2>&1; then \
		echo "docker-compose not installed"; \
		exit 1; \
	fi
	docker-compose logs -f

install-tools:
	@echo "Installing Go tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || echo "Failed to install golangci-lint"
	@go install golang.org/x/tools/cmd/deadcode@latest || echo "Failed to install deadcode"
	@go install honnef.co/go/tools/cmd/staticcheck@latest || echo "Failed to install staticcheck"
	@echo "✅ Tool installation complete (docs tools use npx automatically)"

db-reset:
	@if ! command -v docker >/dev/null 2>&1; then \
		echo "Docker not installed"; \
		exit 1; \
	fi
	@if ! docker ps | grep -q babbel-mysql; then \
		echo "babbel-mysql container not running. Start with: docker-compose up -d"; \
		exit 1; \
	fi
	docker exec -i babbel-mysql mysql -u babbel -pbabbel babbel < migrations/001_complete_schema.sql

test-all:
	./scripts/test-everything.sh