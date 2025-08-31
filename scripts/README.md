# Scripts

This directory contains utility scripts for the Babbel project.

## Testing

All testing is now handled through the Node.js test suite. See the main README for testing instructions.

### Running Tests

```bash
# Run all tests
make test-all
# or
npm test

# Run specific test suite
npm test:auth
npm test:stations
npm test:voices
# etc.
```

### Requirements

- Node.js >= 24.0.0
- Docker and Docker Compose
- FFmpeg

The Node.js test suite automatically handles:
- Docker container management
- Database setup and migrations
- Test data generation
- Comprehensive API testing
- Cleanup after tests