# Migrations

`001_complete_schema.sql` is the consolidated snapshot: it drops and recreates
every table and is the only file fresh databases load (Docker Compose init and
`make db-reset`). When a new migration ships, fold its schema into `001` as
well, so the snapshot stays complete and re-applying it can never leave stale
tables behind.

Migrations `002` and up are deltas for existing databases. After a numbered
delta migration has shipped on `main`, do not edit it; add a new numbered
migration with the required `ALTER TABLE` or data changes instead.

Apply `009_bulletin_jobs.sql` once to existing databases before deploying a
Babbel version that serves asynchronous bulletin jobs. It uses `CREATE TABLE
IF NOT EXISTS`, so it is a no-op on databases created from the current `001`
snapshot.

Deploy Knabbel UI PR 65 first, then deploy the Babbel app, and finally apply
`010_drop_unsupported_eleven_v3_settings.sql`, which removes `similarity_boost`,
`style`, and `speed` after the app no longer reads them.

Apply `011_oidc_identity.sql` once to existing databases before deploying the
issuer/subject-based OIDC login code. Fresh databases load only the updated
`001` snapshot. Stop old application instances during the upgrade so they
cannot continue resolving identities by email. The new nullable identity
columns preserve legacy accounts and the unique index compares issuer and
subject byte-for-byte, including case and trailing spaces.

On first login, an existing passwordless account is linked only if the token
has a non-empty email and `email_verified: true`, exactly one active or
suspended legacy account matches, and both identity columns are still NULL.
Suspended accounts are rejected. Password-based accounts are never adopted.
Ambiguous matches require administrator intervention. The conditional update
prevents concurrent identities from overwriting a link.

An absent `email_verified` claim is not proof of email ownership. This also
applies to Entra ID providers that omit the claim: login creates a separate
viewer account instead of inheriting a legacy account's permissions. Before
such a user's first login, an administrator can verify their identity with
the provider and explicitly populate both identity columns on the correct
legacy row. Do the same for legacy accounts without email. Never infer these
links from a blank email or a display name. If a new viewer row already owns
the pair, resolve that duplicate account before assigning the pair elsewhere.
