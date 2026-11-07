# Test Fixtures

This directory contains test data fixtures for the Babbel API tests.

## Files

- `dev-admin.sql` - The `admin` / `admin` login for development and tests. `docker-compose.yml` and `make db-reset` load it. Never load it in production
- `test-data.sql` - SQL file with test users, stations, voices, stories, and bulletins
- `load-fixtures.js` - Script to load fixtures into the database

## Test Data Included

### Users
- `admin` / `admin` - System administrator (created by `dev-admin.sql`)
- `editor_user` / `testpass123` - Editor role
- `viewer_user` / `testpass123` - Viewer role  
- `suspended_user` / `testpass123` - Suspended editor (soft deleted)

### Stations
- Test Station FM (5 stories max, 2.0s pause)
- Radio Test (4 stories max, 1.5s pause)
- Demo Station (3 stories max, 2.5s pause)

### Voices
- Test Voice Male
- Test Voice Female
- Demo Announcer
- Weekend Voice
- Morning Voice

### Stories
- Breaking News Test (all days)
- Weather Update Test (weekdays only)
- Traffic Report Test (Mon/Wed/Fri)
- Sports Update Test (weekends only)
- Morning News Test (weekdays)
- Weekend Special Test (weekends)
- Archived Story Test (soft deleted)
- Future Story Test (scheduled for 2030)

### Station-Voice Relationships
Pre-configured relationships between stations and voices

### Bulletins
Sample bulletins for testing bulletin history features

## Usage

### Load Fixtures Manually

```bash
node tests/fixtures/load-fixtures.js
```

`load-fixtures.js` uses the Docker container named by `MYSQL_CONTAINER` (default
`babbel-mysql`) when it is running.
If Docker cannot be inspected or that container is absent, it connects directly
to MySQL using `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, and
`MYSQL_DATABASE` (defaults: `localhost`, `babbel`, `babbel`, `babbel`).

This script does not load `dev-admin.sql`. The tests need that login, so on a
database you did not create with `docker-compose.yml` or `make db-reset`, load it
once, on the same target as the script. Without the container:

```bash
mysql -h "${MYSQL_HOST:-localhost}" -u "${MYSQL_USER:-babbel}" -p "${MYSQL_DATABASE:-babbel}" < tests/fixtures/dev-admin.sql
```

With the container:

```bash
docker exec -i "${MYSQL_CONTAINER:-babbel-mysql}" mysql -u "${MYSQL_USER:-babbel}" "-p${MYSQL_PASSWORD:-babbel}" "${MYSQL_DATABASE:-babbel}" < tests/fixtures/dev-admin.sql
```

### In Tests

The test fixtures provide a known state for testing. Tests can:
1. Use the pre-existing test data
2. Create additional data as needed
3. Clean up their own created data

## Important Notes

1. **Not Required**: Tests can run without fixtures - they create their own data
2. **Idempotent**: The fixture SQL uses `INSERT IGNORE` and `UPDATE` to be re-runnable
3. **Test Isolation**: Each test should clean up data it creates
4. **Known Passwords**: All test users use `testpass123` for consistency

## When to Use Fixtures

Use fixtures when:
- Testing with pre-existing data relationships
- Testing pagination with multiple records
- Testing filters and search with varied data
- Running integration tests

Don't use fixtures when:
- Running unit tests
- Testing data creation from scratch
- Tests need complete control over data state
