# Test Scripts

## test-everything.sh

Comprehensive integration test that validates the entire Babbel API workflow.

### Usage

```bash
./scripts/test-everything.sh
```

### What it does

1. **Setup**: Starts Docker containers and resets database
2. **Audio**: Generates test jingle and story files
3. **API**: Tests all endpoints including authentication and RBAC
4. **Bulletins**: Creates and validates audio bulletins for all stations
5. **Cleanup**: Verifies all expected files are generated

### Requirements

- Docker and Docker Compose
- FFmpeg
- curl
- Python 3

### Exit codes

- `0`: All tests passed
- `1`: Test failure or setup error

No flags or options required - runs complete test suite automatically.