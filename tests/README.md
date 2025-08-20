# Babbel API Test Suite

This directory contains comprehensive test suites for the Babbel API, available in both **Node.js** (recommended) and **Bash** implementations.

## 🚀 Node.js Implementation (Recommended)

The Node.js implementation provides improved reliability, better JSON handling, and cross-platform compatibility.

### Installation

```bash
npm install
```

### Usage

```bash
# Run all tests
npm test

# Run specific test suite
npm run test:auth          # Authentication tests
npm run test:permissions   # Permission/RBAC tests
npm run test:stations      # Station CRUD tests
npm run test:voices        # Voice management tests
npm run test:stories       # Story tests with file uploads
npm run test:bulletins     # Bulletin generation tests
npm run test:users         # User management tests
npm run test:validation    # Comprehensive validation tests

# Quick mode (skip Docker/database setup)
npm run test:quick

# Command line options
node tests/run-all.js --help
node tests/run-all.js auth stations  # Run specific suites
```

### Node.js Test Structure

```
tests/
├── run-all.js              # Main test orchestrator
├── package.json            # Dependencies and scripts
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
├── bulletins/
│   └── test-bulletins.js   # Bulletin generation tests
├── users/
│   └── test-users.js       # User management tests
└── validation/
    └── validation-tests.js # Comprehensive validation tests (178 tests)
```

### Benefits of Node.js Implementation

- ✅ **Better JSON Handling**: Native JSON parsing and validation
- ✅ **Cross-Platform**: Works on Windows, macOS, and Linux
- ✅ **Improved Reliability**: Proper error handling and timeouts
- ✅ **IDE Support**: Full IntelliSense, debugging, and syntax highlighting
- ✅ **Maintainability**: Object-oriented design with inheritance
- ✅ **Test Coverage**: 178+ validation tests, comprehensive CRUD testing

## 📜 Bash Implementation (Legacy)

The original bash implementation is still available for compatibility.

### Usage

```bash
# Run all tests
./run-all.sh

# Run specific test suite
./run-all.sh auth        # Run only authentication tests
./run-all.sh stations    # Run only station tests

# Quick mode (skip Docker/DB setup)
./run-all.sh --quick auth

# List available test suites
./run-all.sh --list
```

### Bash Test Structure

```
tests/
├── run-all.sh                 # Main orchestrator
├── lib/
│   ├── common.sh              # Shared functions, variables
│   ├── auth.sh                # Authentication helpers
│   └── assertions.sh          # Test assertion functions
├── auth/
│   ├── test-auth.sh           # Authentication tests
│   └── test-permissions.sh    # Permission tests
├── stations/
│   └── test-stations.sh       # Station CRUD tests
├── voices/
│   └── test-voices.sh         # Voice management tests
├── station-voices/
│   └── test-station-voices.sh # Station-voice tests
├── stories/
│   └── test-stories.sh        # Story management tests
├── bulletins/
│   └── test-bulletins.sh      # Bulletin generation tests
├── users/
│   └── test-users.sh          # User management tests
└── validation/
    └── test-validation.sh     # Validation tests wrapper
```

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

### Validation Testing (178 tests)
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

## 🍪 Cookie Management

Both implementations use Netscape cookie format (compatible with curl):
```
# Netscape HTTP Cookie File
localhost	TRUE	/	FALSE	1755352032	babbel_session	<session-token>
```

Cookie file location: `test_cookies.txt`

## 🐛 Troubleshooting

### Tests failing with 401 Unauthorized
```bash
# Run auth tests first to establish session
npm run test:auth
# or
./auth/test-auth.sh
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

## 📈 Test Results

Typical test run results:
- **Authentication**: 56 tests, 95% pass rate
- **Permissions**: 200+ tests, 98% pass rate  
- **Stations**: 67 tests, 100% pass rate
- **Validation**: 178 tests, 85% pass rate
- **Overall**: 800+ tests across all suites

## 🔄 Migration Guide

### From Bash to Node.js

1. Install Node.js dependencies: `npm install`
2. Use npm scripts instead of shell scripts
3. Same test coverage and scenarios
4. Compatible cookie file format
5. Identical output format

### Key Differences

| Feature | Bash | Node.js |
|---------|------|---------|
| JSON Parsing | String manipulation | Native JSON |
| File Uploads | curl -F | FormData API |
| Async Operations | Background processes | Promises/async-await |
| Error Handling | Set -e, trap | Try-catch blocks |
| Cross-Platform | Linux/macOS only | Windows/Linux/macOS |

## 🤝 Contributing

When adding new tests:

1. **Node.js**: Extend `BaseTest` class, implement `run()` method
2. **Bash**: Source `lib/common.sh`, follow existing patterns
3. Add test suite to orchestrator (`run-all.js` or `run-all.sh`)
4. Update this README with coverage information
5. Ensure cleanup of created test data

## 📄 License

MIT - See main repository LICENSE file