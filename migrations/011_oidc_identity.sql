-- Required for OIDC login; see README.md for deployment prerequisites.
-- VARBINARY preserves case and trailing bytes in opaque identity claims.
ALTER TABLE users
    ADD COLUMN oidc_issuer VARBINARY(512) NULL,
    ADD COLUMN oidc_subject VARBINARY(255) NULL,
    ADD UNIQUE INDEX idx_users_oidc_identity (oidc_issuer, oidc_subject);
