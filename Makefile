.PHONY: help build run test test-integration clean docs docker

help:
	@echo "Babbel Commands:"
	@echo "  build     - Build the application" 
	@echo "  run       - Run the application"
	@echo "  test      - Run tests"
	@echo "  test-all  - Run integration tests"
	@echo "  test-integration - Run Go integration tests against compose MySQL"
	@echo "  lint      - Run linters"
	@echo "  quality   - Run quality checks"
	@echo "  docs-all  - Generate documentation"
	@echo "  docker    - Build Docker image"
	@echo "  db-reset  - Reset database"

# Development
build:
	go build -ldflags="-w -s -X github.com/oszuidwest/zwfm-babbel/pkg/version.Version=dev -X github.com/oszuidwest/zwfm-babbel/pkg/version.Commit=$$(git rev-parse --short HEAD) -X github.com/oszuidwest/zwfm-babbel/pkg/version.BuildTime=$$(date -u +%FT%TZ)" -o babbel cmd/babbel/main.go

run:
	go run cmd/babbel/main.go

test:
	go test ./... -v

test-integration:
	@command -v docker >/dev/null || { echo "Docker not installed"; exit 1; }
	docker compose up -d mysql
	docker compose stop babbel
	@echo "Waiting for MySQL to be healthy..."
	@i=0; until docker compose ps mysql | grep -q healthy; do \
		i=$$((i+1)); \
		if [ $$i -ge 60 ]; then echo "MySQL not healthy after 60s"; exit 1; fi; \
		sleep 1; \
	done
	$(MAKE) db-reset
	BABBEL_TEST_DB_DSN='babbel:babbel@tcp(127.0.0.1:3306)/babbel?charset=utf8mb4&parseTime=True&loc=Local' \
		go test -tags=integration ./internal/...

# Quality
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

quality: lint
	@echo "Running unit tests..."
	@go test -race -shuffle=on ./...
	@echo "✅ Unit tests passed!"
	@echo "Running code quality checks..."
	@echo "Checking for dead code..."
	@deadcode_output=$$(go tool deadcode ./...); \
	if [ -n "$$deadcode_output" ]; then \
		echo "❌ Found dead code:"; \
		echo "$$deadcode_output"; \
		exit 1; \
	else \
		echo "✅ No dead code found!"; \
	fi
	@echo "Running staticcheck..."
	@go tool staticcheck ./...
	@echo "✅ staticcheck passed!"

clean:
	rm -f babbel
	rm -rf ./audio/output/*
	rm -rf ./audio/temp/*

# Documentation
docs:
	@echo "Generating API documentation..."
	@mkdir -p docs
	@echo "  → Simple Markdown reference..."
	@go run tools/docgen.go -input openapi.yaml -output docs/API_REFERENCE.md
	@echo "  → Interactive HTML docs..."
	@npx -y @redocly/cli@2.0.1 build-docs openapi.yaml \
		--output=docs/index.html \
		--title="Babbel API Documentation" 2>/dev/null
	@echo "✓ Generated both simple and interactive documentation"

docs-all: docs
	@echo "✓ Complete documentation suite generated"

validate-spec:
	@if command -v redocly >/dev/null 2>&1; then \
		redocly lint openapi.yaml; \
	else \
		npx -y @redocly/cli@2.0.1 lint openapi.yaml; \
	fi

# Docker
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
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.0 || echo "Failed to install golangci-lint"
	@echo "✅ Tool installation complete (deadcode and staticcheck use go.mod tool directives; govulncheck is pinned in CI)"

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
	@if ! command -v node >/dev/null 2>&1; then \
		echo "Node.js not installed"; \
		exit 1; \
	fi
	@if [ ! -f package.json ]; then \
		echo "package.json not found"; \
		exit 1; \
	fi
	@if [ ! -d node_modules ]; then \
		echo "Installing Node.js dependencies..."; \
		npm install; \
	fi
	npm test
