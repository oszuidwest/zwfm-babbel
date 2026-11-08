# Test Fixtures

`dev-admin.sql` adds the `admin` / `admin` login for development and tests. `docker-compose.yml` and `make db-reset` load it. Never load it in production.

The tests create the rest of their data themselves and clean it up.

## Load the admin login by hand

On a database you did not create with `docker-compose.yml` or `make db-reset`, load it once. Without the container:

```bash
mysql -h "${MYSQL_HOST:-localhost}" -u "${MYSQL_USER:-babbel}" -p "${MYSQL_DATABASE:-babbel}" < tests/fixtures/dev-admin.sql
```

With the container:

```bash
docker exec -i "${MYSQL_CONTAINER:-babbel-mysql}" mysql -u "${MYSQL_USER:-babbel}" "-p${MYSQL_PASSWORD:-babbel}" "${MYSQL_DATABASE:-babbel}" < tests/fixtures/dev-admin.sql
```
