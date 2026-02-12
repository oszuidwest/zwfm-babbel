# Babbel API Test Suite

Comprehensive Node.js test suite for the Babbel API, providing full coverage of all endpoints and functionality.

## Quick Start

```bash
# Install dependencies
npm install

# Optional: Load test fixtures for richer test data
node fixtures/load-fixtures.js

# Run all tests
node run-all.js

# Run specific test suite
node auth/test-auth.js
node stations/test-stations.js

# Run multiple suites
node run-all.js auth stations

# Skip Docker/DB setup (quick mode)
node run-all.js --quick
```

## Usage

```bash
# Run all tests
npm test

# Run specific test suite
npm run test:auth          # Authentication tests
npm run test:permissions   # Permission/RBAC tests
npm run test:stations      # Station CRUD tests
npm run test:voices        # Voice management tests
npm run test:stories       # Story tests with file uploads
npm run test:tts           # Text-to-speech endpoint tests
npm run test:bulletins     # Bulletin generation tests
npm run test:users         # User management tests
npm run test:validation    # Comprehensive validation tests

# Command line options
node run-all.js --help
node run-all.js auth stations  # Run specific suites
```

## Test Structure

```
tests/
├── run-all.js              # Main test orchestrator
├── fixtures/               # Test data fixtures
│   ├── test-data.sql       # SQL with test users, stations, voices, stories
│   ├── load-fixtures.js    # Script to load test data
│   └── README.md           # Fixture documentation
├── lib/
│   ├── BaseTest.js         # Base class with common functionality
│   ├── assertions.js       # Assertion utilities
│   └── docker-utils.js     # Docker management utilities
├── auth/
│   ├── test-auth.js        # Authentication tests
│   └── test-permissions.js # Permission/RBAC tests
├── stations/
│   └── test-stations.js    # Station CRUD tests
├── voices/
│   └── test-voices.js      # Voice management tests
├── station-voices/
│   └── test-station-voices.js # Station-voice relationship tests
├── stories/
│   └── test-stories.js     # Story tests with file uploads
├── tts/
│   └── test-tts.js         # Text-to-speech endpoint tests
├── bulletins/
│   └── test-bulletins.js   # Bulletin generation tests
├── users/
│   └── test-users.js       # User management tests
└── validation/
    └── validation-tests.js # Comprehensive validation tests
```

## Test Framework Features

- ✅ **Native JSON Handling**: Full JSON parsing and validation
- ✅ **Cross-Platform**: Works on Windows, macOS, and Linux
- ✅ **Async/Await**: Modern JavaScript patterns
- ✅ **Cookie Management**: Session persistence across tests
- ✅ **Colored Output**: Clear test results with color coding
- ✅ **Auto Cleanup**: Resources cleaned up automatically
- ✅ **83 Total Tests**: Complete migration from bash with enhancements

## 📊 Test Coverage

### Authentication & Authorization
- ✅ Login/logout functionality
- ✅ Session management and persistence
- ✅ Role-based access control (admin, editor, viewer)
- ✅ Permission inheritance and restrictions

### CRUD Operations
- ✅ **Stations**: Create, read, update, delete, search, pagination
- ✅ **Voices**: Full CRUD with soft delete support
- ✅ **Stories**: File uploads, scheduling, weekday selection
- ✅ **Users**: Management, suspension, role changes
- ✅ **Bulletins**: Generation, caching, audio processing

### Validation Testing
- ✅ Required field validation
- ✅ Data type validation
- ✅ Boundary testing (min/max values)
- ✅ Pattern validation (emails, usernames)
- ✅ Unique constraint testing
- ✅ SQL injection prevention
- ✅ XSS sanitization
- ✅ Path traversal protection
- ✅ Business rule validation

### File Handling
- ✅ Multipart form data uploads
- ✅ Audio file validation (WAV format)
- ✅ Jingle file management
- ✅ File download verification

## 🔧 Environment Variables

```bash
# API Configuration
API_BASE=http://localhost:8080    # API base URL

# MySQL Configuration
MYSQL_USER=babbel
MYSQL_PASSWORD=babbel
MYSQL_DATABASE=babbel

# Docker Configuration
DOCKER_COMPOSE_FILE=docker-compose.yml
```

## Cookie Management

Tests use Netscape cookie format (compatible with curl):
```
# Netscape HTTP Cookie File
localhost	TRUE	/	FALSE	1755352032	babbel_session	<session-token>
```

Cookie file location: `test_cookies.txt`

## Troubleshooting

### Tests failing with 401 Unauthorized
```bash
# Run auth tests first to establish session
node auth/test-auth.js
```

### Docker connection issues
```bash
# Check container status
docker-compose ps

# Rebuild if needed
docker-compose down -v
docker-compose up -d
```

### Database connection errors
```bash
# Check MySQL is ready
docker-compose logs mysql

# Verify database exists
docker-compose exec mysql mysql -u babbel -pbabbel -e "SHOW DATABASES;"
```

## Test Results

Current test coverage:
- **Authentication**: 6 tests
- **Permissions**: 4 tests
- **Stations**: 7 tests
- **Voices**: 6 tests
- **Station-Voices**: 7 tests
- **Stories**: 10 tests
- **TTS**: 7 tests
- **Bulletins**: 11 tests
- **Users**: 19 tests
- **Validation**: 6 tests
- **Total**: 83 tests across all suites

## Contributing

When adding new tests:

1. Extend `BaseTest` class for consistency
2. Use `async/await` patterns
3. Follow naming convention: `testFeatureName()`
4. Add to appropriate test suite
5. Update `run-all.js` if adding new suite
6. Ensure cleanup of created test data

## License

MIT - See main repository LICENSE file
