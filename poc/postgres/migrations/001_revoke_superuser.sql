-- Migration 001: Revoke superuser from vault_dba and grant scoped pg_signal_backend
-- Required for least-privilege compliance (Finding 1 & 2)

ALTER ROLE vault_dba NOSUPERUSER CREATEROLE;
GRANT pg_signal_backend TO vault_dba;
\c appdb;
GRANT app_reader TO vault_dba WITH ADMIN OPTION;
GRANT legacy_user TO vault_dba WITH ADMIN OPTION;
