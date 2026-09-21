import os
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

DATABASE_URL = os.getenv("DATABASE_URL")

def get_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is required")
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS services (
        id VARCHAR(64) PRIMARY KEY,
        name VARCHAR(128) NOT NULL,
        owner_group VARCHAR(64) NOT NULL,
        fallback_group VARCHAR(64) NOT NULL,
        operational_contact VARCHAR(128) NOT NULL,
        environment VARCHAR(32) NOT NULL,
        classification VARCHAR(32) NOT NULL,
        business_criticality VARCHAR(32) NOT NULL,
        application_category VARCHAR(32) NOT NULL,
        target_resource VARCHAR(256) NOT NULL,
        requested_permissions JSONB NOT NULL,
        consumer_list JSONB NOT NULL,
        lifetime_policy VARCHAR(64) NOT NULL,
        replacement_mode VARCHAR(64) NOT NULL,
        expected_restart_behavior VARCHAR(128) NOT NULL,
        recovery_procedure_id VARCHAR(64) NOT NULL,
        exception_status JSONB,
        revision INT NOT NULL DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS intakes (
        id VARCHAR(64) PRIMARY KEY,
        service_id VARCHAR(64) NOT NULL,
        requester_id VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL,
        payload JSONB NOT NULL,
        approver_id VARCHAR(64),
        approved_at TIMESTAMPTZ,
        revision INT NOT NULL DEFAULT 1,
        idempotency_key VARCHAR(128) UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS credentials (
        id VARCHAR(64) PRIMARY KEY,
        service_id VARCHAR(64) NOT NULL REFERENCES services(id),
        credential_id VARCHAR(64) NOT NULL UNIQUE,
        issuer_type VARCHAR(32) NOT NULL,
        issuer_ref VARCHAR(256) NOT NULL,
        credential_type VARCHAR(32) NOT NULL,
        permissions_summary VARCHAR(256) NOT NULL,
        lifetime_seconds INT NOT NULL,
        rotation_mechanism VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL,
        current_version_id VARCHAR(64),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS credential_versions (
        id VARCHAR(64) PRIMARY KEY,
        credential_id VARCHAR(64) NOT NULL,
        version_id VARCHAR(64) NOT NULL UNIQUE,
        hmac_fingerprint VARCHAR(160) NOT NULL,
        canonical_version VARCHAR(32) NOT NULL DEFAULT 'v1',
        status VARCHAR(32) NOT NULL,
        metadata JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS incidents (
        id VARCHAR(64) PRIMARY KEY,
        finding_id VARCHAR(64) NOT NULL,
        service_id VARCHAR(64) REFERENCES services(id),
        credential_version_id VARCHAR(64),
        correlation_status VARCHAR(32) NOT NULL,
        triage_status VARCHAR(32) NOT NULL,
        containment_status VARCHAR(32) NOT NULL,
        recovery_status VARCHAR(32) NOT NULL,
        investigation_status VARCHAR(32) NOT NULL,
        case_status VARCHAR(32) NOT NULL,
        assigned_owner VARCHAR(64),
        decision_action VARCHAR(32),
        decision_reason TEXT,
        decided_by VARCHAR(64),
        decided_at TIMESTAMPTZ,
        recovery_disposition VARCHAR(64),
        investigation_limitations TEXT,
        recurrence_owner VARCHAR(64),
        closed_by VARCHAR(64),
        closed_at TIMESTAMPTZ,
        contained_at TIMESTAMPTZ,
        recovered_at TIMESTAMPTZ,
        revision INT NOT NULL DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS operations (
        id VARCHAR(64) PRIMARY KEY,
        idempotency_key VARCHAR(128) UNIQUE NOT NULL,
        incident_id VARCHAR(64) REFERENCES incidents(id),
        credential_version_id VARCHAR(64),
        action VARCHAR(32) NOT NULL,
        status VARCHAR(32) NOT NULL,
        policy_revision INT NOT NULL DEFAULT 1,
        target VARCHAR(256) NOT NULL,
        params JSONB,
        execution_identity VARCHAR(64),
        attempts INT NOT NULL DEFAULT 0,
        interrupted BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS evidence_events (
        id SERIAL PRIMARY KEY,
        run_id VARCHAR(64) NOT NULL,
        scenario_id VARCHAR(32) NOT NULL,
        incident_id VARCHAR(64),
        operation_id VARCHAR(64),
        actor VARCHAR(64) NOT NULL,
        action VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL,
        service_id VARCHAR(64),
        credential_version_id VARCHAR(64),
        source_revision VARCHAR(64) NOT NULL,
        component_versions JSONB NOT NULL,
        redacted_result JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS candidate_references (
        id VARCHAR(64) PRIMARY KEY,
        candidate_val TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS gitlab_pipelines (
        id VARCHAR(64) PRIMARY KEY,
        project_id VARCHAR(64) NOT NULL,
        ref VARCHAR(64) NOT NULL,
        commit_sha VARCHAR(64) NOT NULL,
        status VARCHAR(32) NOT NULL,
        stages JSONB NOT NULL,
        scan_findings JSONB,
        incident_id VARCHAR(64),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE incidents ADD COLUMN IF NOT EXISTS candidate_ref VARCHAR(64);
    ALTER TABLE incidents ADD COLUMN IF NOT EXISTS validation_status VARCHAR(32) DEFAULT 'inconclusive';

    CREATE TABLE IF NOT EXISTS scan_attempts (
        id VARCHAR(64) PRIMARY KEY,
        service_id VARCHAR(64) NOT NULL REFERENCES services(id),
        run_id VARCHAR(64) NOT NULL,
        scheduled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        due_at TIMESTAMPTZ NOT NULL,
        completed_at TIMESTAMPTZ,
        outcome VARCHAR(16),
        detector_version VARCHAR(128),
        CHECK (outcome IS NULL OR outcome IN ('clean','findings','error'))
    );

    -- Dynamic migrations for enterprise schema additions
    ALTER TABLE services ADD COLUMN IF NOT EXISTS network_exposure VARCHAR(32) DEFAULT 'internal_facing';
    ALTER TABLE services ADD COLUMN IF NOT EXISTS data_classification VARCHAR(32) DEFAULT 'Restricted';
    ALTER TABLE services ADD COLUMN IF NOT EXISTS auto_rotation_support BOOLEAN DEFAULT TRUE;
    ALTER TABLE services ADD COLUMN IF NOT EXISTS secret_manager_ref VARCHAR(256);
    ALTER TABLE services ADD COLUMN IF NOT EXISTS secondary_credential_configured BOOLEAN DEFAULT FALSE;
    ALTER TABLE services ADD COLUMN IF NOT EXISTS gitlab_repo_url VARCHAR(256);
    ALTER TABLE gitlab_pipelines ADD COLUMN IF NOT EXISTS remediated_by_pipeline_id VARCHAR(64);
    ALTER TABLE gitlab_pipelines ADD COLUMN IF NOT EXISTS remediation_details JSONB;
    ALTER TABLE credential_versions ALTER COLUMN hmac_fingerprint TYPE VARCHAR(160);
    """)

    cur.execute("UPDATE candidate_references SET candidate_val = '[removed during restricted-store migration]', expires_at = LEAST(expires_at, NOW()) WHERE candidate_val <> '[removed during restricted-store migration]'")
    conn.commit()
    cur.close()
    conn.close()
