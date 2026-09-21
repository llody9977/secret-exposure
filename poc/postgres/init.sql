-- Create Control Database and User
CREATE USER control_user WITH PASSWORD :'control_db_password';
CREATE DATABASE controldb OWNER control_user;

-- Create App Database and Vault DBA User (scoped privileges, non-superuser per ASSESSMENT Finding #2)
CREATE USER vault_dba WITH CREATEROLE PASSWORD :'vault_db_admin_password';
GRANT pg_signal_backend TO vault_dba;
CREATE DATABASE appdb OWNER vault_dba;

-- Connect to appdb and initialize schema
\c appdb;

CREATE TABLE IF NOT EXISTS legacy_records (
    id SERIAL PRIMARY KEY,
    item_name TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS integrated_records (
    id SERIAL PRIMARY KEY,
    metric_name TEXT NOT NULL,
    metric_val NUMERIC NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO legacy_records (item_name) VALUES ('inventory_alpha'), ('inventory_beta');
INSERT INTO integrated_records (metric_name, metric_val) VALUES ('system_load', 1.45), ('memory_usage_pct', 62.8);

-- Create shared role for dynamic users
CREATE ROLE app_reader;
GRANT app_reader TO vault_dba WITH ADMIN OPTION;
GRANT SELECT, INSERT, UPDATE ON legacy_records, integrated_records TO app_reader;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_reader;

-- Create legacy_user managed by Vault static role
CREATE USER legacy_user WITH PASSWORD :'legacy_db_initial_password';
GRANT legacy_user TO vault_dba WITH ADMIN OPTION;
GRANT app_reader TO legacy_user;
GRANT ALL PRIVILEGES ON legacy_records TO legacy_user;
