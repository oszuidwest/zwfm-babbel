# Babbel API Test Suite

Comprehensive Jest-based integration test suite for the Babbel API, providing full coverage of all endpoints and functionality.

## Quick Start

```bash
# Install dependencies
npm install

# Run all tests (starts Docker, runs tests, cleans up)
npm test

# Run tests without Docker setup (containers already running)
npm run test:quick

# Run specific test suite
npm run test:stations
npm run test:tts

# Run with Jest options
npm run test:quick -- --verbose
```

## Usage

```bash
# Full test suite with Docker orchestration
npm test

# Individual suites (requires running containers)
npm run test:auth          # Authentication tests
npm run test:permissions   # Permission/RBAC tests
npm run test:stations      # Station CRUD tests
npm run test:voices        # Voice management tests
npm run test:station-voices # Station-voice relationship tests
npm run test:stories       # Story tests with file uploads
npm run test:tts           # Text-to-speech endpoint tests
npm run test:bulletins     # Bulletin generation tests
npm run test:cleanup       # Bulletin file cleanup tests
npm run test:automation    # Public automation endpoint tests
npm run test:users         # User management tests
npm run test:validation    # Input validation and security tests

# Skip Docker setup (alias for test:quick)
npm run test:no-docker
```

## Test Structure

```
tests/
├── jest.config.js            # Jest configuration (sequential, 60s timeout)
├── jest.testSequencer.js     # Enforces test execution order
├── jest.globalSetup.js       # Docker orchestration (start containers)
├── jest.globalTeardown.js    # Cleanup (cookies, optional Docker stop)
├── jest.setupAfterEnv.js     # Per-file setup (auth, globals, custom matchers)
├── fixtures/                 # Test data fixtures
│   ├── test-data.sql         # SQL with test users, stations, voices, stories
│   ├── load-fixtures.js      # Script to load test data
│   └── README.md             # Fixture documentation
├── lib/
│   ├── ApiHelper.js          # HTTP client with shared cookie-jar sessions
│   ├── ResourceManager.js    # FK-ordered resource tracking and cleanup
│   ├── TestHelpers.js        # Test data creation utilities
│   ├── generators/           # Declarative test generators
│   │   ├── CrudTestGenerator.js       # CRUD operation tests
│   │   ├── QueryTestGenerator.js      # Query parameter tests
│   │   ├── ValidationTestGenerator.js # Field validation tests
│   │   └── index.js
│   └── schemas/              # Resource definitions for generators
│       ├── stations.schema.js
│       ├── voices.schema.js
│       ├── users.schema.js
│       ├── stories.schema.js
│       ├── station-voices.schema.js
│       └── bulletins.schema.js
├── auth/
│   ├── auth.test.js          # Authentication tests
│   └── permissions.test.js   # Permission/RBAC tests
├── stations/
│   └── stations.test.js      # Station CRUD and query tests
├── voices/
│   └── voices.test.js        # Voice management tests
├── station-voices/
│   └── station-voices.test.js # Station-voice relationship tests
├── stories/
│   └── stories.test.js       # Story tests with file uploads
├── tts/
│   └── tts.test.js           # Text-to-speech endpoint tests
├── bulletins/
│   ├── bulletins.test.js     # Bulletin generation tests
│   └── bulletin-cleanup.test.js # Purged bulletin behavior tests
├── automation/
│   └── automation.test.js    # Public automation endpoint tests
├── users/
│   └── users.test.js         # User management tests
└── validation/
    └── validation.test.js    # Input validation and security tests
```

## Test Execution Order

Tests run sequentially (`maxWorkers: 1`) in dependency order enforced by a custom sequencer:

```
auth → permissions → stations → voices → station-voices → stories →
tts → bulletins → bulletin-cleanup → automation → users → validation
```

Later tests depend on data created by earlier ones. Individual suites can be run in isolation when Docker is already running.

## Test Generators

Three generators produce standardized tests from declarative schema configurations:

| Generator | Purpose | Tests Generated |
|-----------|---------|-----------------|
| `CrudTestGenerator` | Create, Read, Update, Delete operations | ~14 per resource |
| `QueryTestGenerator` | Search, sort, filter, pagination, field selection | ~25 per resource |
| `ValidationTestGenerator` | Required fields, type validation, boundaries, unique constraints | ~15 per resource |

Resources with full generator coverage: stations, voices, users, station-voices. Stories and bulletins use partial generator coverage plus manual business logic tests.

## Test Coverage

| Suite | Tests | Type |
|-------|-------|------|
| auth | 16 | Manual (domain-specific) |
| permissions | 19 | Manual (RBAC-specific) |
| stations | 86 | Full (CRUD + Query + Validation) |
| voices | 56 | Full (CRUD + Query + Validation) |
| station-voices | 88 | Full (CRUD + Query + Validation) |
| stories | 70 | Partial (Query) + manual |
| tts | 7 | Manual (TTS validation chain) |
| bulletins | 42 | Partial (Query) + manual |
| bulletin-cleanup | 7 | Manual (purge behavior) |
| automation | 12 | Manual (public endpoint) |
| users | 87 | Full (CRUD + Query + Validation) |
| validation | 18 | Manual (security tests) |
| **Total** | **508** | |

### Coverage Areas

- Authentication and session management
- Role-based access control (admin, editor, viewer)
- CRUD operations for all resources
- Modern query parameters (search, sort, filter, pagination, field selection)
- File uploads (stories, jingles) and audio processing
- Text-to-speech generation via ElevenLabs
- Bulletin generation and caching
- Bulletin file cleanup and purge behavior
- Public automation endpoint
- Input validation and boundary testing
- SQL injection, XSS, and path traversal prevention
- RFC 9457 error response format compliance

## Environment Variables

```bash
# API Configuration
API_BASE=http://localhost:8080    # API base URL

# MySQL Configuration (matching docker-compose defaults)
MYSQL_USER=babbel
MYSQL_PASSWORD=babbel
MYSQL_DATABASE=babbel

# Docker Control
JEST_SKIP_DOCKER=true            # Skip Docker setup/teardown
JEST_STOP_DOCKER=true            # Stop containers after tests

# TTS Testing
BABBEL_TEST_TTS_ENABLED=true             # Enable TTS validation chain tests
BABBEL_TEST_TTS_REAL_API=true            # Enable real ElevenLabs API tests
BABBEL_TEST_ELEVENLABS_VOICE_ID=your-voice-id
```

## Contributing

When adding new tests:

1. Create a `.test.js` file following the AAA pattern (Arrange, Act, Assert)
2. Use `when...then` test naming convention
3. Use `global.api`, `global.helpers`, and `global.resources` for shared functionality
4. Track created resources with `global.resources.track()` for automatic cleanup
5. For new resources, create a schema in `tests/lib/schemas/` and use generators
6. Add the test file to `jest.testSequencer.js` in the correct position
7. Add an npm script in `package.json`

## License

MIT - See main repository LICENSE file
