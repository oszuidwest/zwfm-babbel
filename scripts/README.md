# Scripts

This directory contains utility scripts for the Babbel project.

## Testing

Tests run with Go (`make test`, `make test-integration`) and the Node.js integration suite (`npm test`). See the main README for testing instructions.

### Running Tests

```bash
make test               # Go unit tests
make test-integration   # Go integration tests against the Compose MySQL
npm ci                  # once, installs Jest and the other Node.js tools
npm run test:unit       # Node.js unit tests, no Docker
npm test                # Node.js integration suite (also: make test-all)
npm run test:auth       # One integration suite; see package.json for the others
```

`npm test` and the single suites such as `npm run test:auth` run
`docker compose down -v`, and `make test-integration` reloads
`migrations/001_complete_schema.sql`. All of them wipe the database of the
`docker-compose.yml` stack, so do not run them on a stack with data you want
to keep.

### Requirements

- Go, see `go.mod`
- Node.js >= 24.9.0
- Docker and Docker Compose
- FFmpeg

The Node.js test suite automatically handles:
- Docker container management
- Database setup and migrations
- Test data generation
- Comprehensive API testing
- Cleanup after tests
