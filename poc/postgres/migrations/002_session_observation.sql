-- Observe backend start time so containment remains bound to a captured session
-- after Vault drops the login role. This does not grant table access.
GRANT pg_read_all_stats TO vault_dba;
