import os
import sys
import uuid
import json
import time
import subprocess
import requests
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

POC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request, Response, status, Header, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from models import (
    IntakeCreate, IntakeApprove, FindingEvent, IncidentDecision,
    OperationExecute, IncidentClose, DecisionAction, ApplicationCategory
)
from database import get_connection, init_db
from hmac_service import compute_fingerprint, verify_fingerprint
from adapters.registry import LocalRegistryAdapter
from adapters.validator import ValidatorAdapter
from auth import (authenticate_request, require_permission, login, get_principal, Principal,
                  local_demo_accounts, login_as_local_demo)
import orchestrator
import candidate_store

app = FastAPI(title="Credential Lifecycle Control Plane", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000", "http://127.0.0.1:8000",
        "http://localhost:8001", "http://localhost:8002", "http://localhost:8003",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Auth-Token", "X-Run-Id"],
)

registry_adapter = LocalRegistryAdapter(get_connection)
validator_adapter = ValidatorAdapter()

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "control-plane", "timestamp": datetime.now(timezone.utc).isoformat()}

# --- AUTHENTICATION (REQ009, REQ025) ---

@app.post("/api/auth/token")
def issue_token(body: Dict[str, Any], request: Request):
    principal_id = body.get("principal_id") or body.get("username") or ""
    try:
        token = login(str(principal_id), str(body.get("password") or ""))
    except HTTPException:
        audit_auth_failure(request, "login_rejected")
        raise
    principal = get_principal(principal_id)
    return {"access_token": token, "token_type": "bearer", "principal_id": principal.id, "role": principal.role}


@app.get("/api/auth/demo-accounts")
def list_demo_accounts():
    return {"accounts": local_demo_accounts()}


@app.post("/api/auth/demo-login")
def issue_demo_token(body: Dict[str, Any], request: Request):
    principal_id = str(body.get("principal_id") or "")
    try:
        token = login_as_local_demo(principal_id)
    except HTTPException:
        audit_auth_failure(request, "demo_login_rejected")
        raise
    principal = get_principal(principal_id)
    return {"access_token": token, "token_type": "bearer", "principal_id": principal.id, "role": principal.role}


def audit_auth_failure(request: Request, action: str):
    # Record no supplied token, password, or unverified identity.
    import logging
    logging.getLogger("auth.audit").warning("%s path=%s", action, request.url.path)
    try:
        orchestrator.record_evidence(request.headers.get("X-Run-Id", "interactive_auth"),
                                     request.headers.get("X-Scenario-Id", "authentication"),
                                     "unauthenticated", action, "rejected",
                                     redacted_result={"path": request.url.path})
    except Exception:
        logging.getLogger("auth.audit").error("Authentication evidence store unavailable")


@app.middleware("http")
async def enforce_api_boundary(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path not in {"/api/health", "/api/auth/token", "/api/auth/demo-accounts", "/api/auth/demo-login"}:
        try:
            principal = authenticate_request(request, require_auth=True)
            request.state.principal = principal
            if path.startswith(("/api/gitlab/", "/api/demo/")) and request.method != "GET":
                if principal.role != "admin":
                    raise HTTPException(status_code=403, detail="Administrator permission required")
            elif path == "/api/apps/integrated/renew" and not principal.has_permission("operation:execute"):
                raise HTTPException(status_code=403, detail="Operation permission required")
            elif request.method == "GET" and not (principal.has_permission("service:read") or principal.has_permission("incident:read")):
                raise HTTPException(status_code=403, detail="Read permission required")
        except HTTPException as exc:
            audit_auth_failure(request, "access_rejected")
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return await call_next(request)

@app.middleware("http")
async def correlate_evidence(request: Request, call_next):
    from evidence_context import current_run_id, current_scenario_id
    import re
    run_id = request.headers.get("X-Run-Id") or f"interactive_{uuid.uuid4().hex}"
    scenario_id = request.headers.get("X-Scenario-Id") or "interactive"
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", scenario_id):
        return JSONResponse(status_code=400, content={"detail": "Invalid evidence correlation identifier"})
    run_token = current_run_id.set(run_id)
    scenario_token = current_scenario_id.set(scenario_id)
    try:
        return await call_next(request)
    finally:
        current_run_id.reset(run_token)
        current_scenario_id.reset(scenario_token)

# --- INTAKES (REQ008, REQ009, REQ034) ---

@app.post("/api/intakes", status_code=201)
def create_intake(req: IntakeCreate, request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("intake:create"):
        raise HTTPException(
            status_code=403,
            detail=f"Principal '{principal.id}' with role '{principal.role}' is not authorized to create intakes"
        )
    requester_id = principal.id
    run_id = request.headers.get("X-Run-Id", "run_default")
    idempotency_key = req.idempotency_key or str(uuid.uuid4())

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM intakes WHERE idempotency_key = %s", (idempotency_key,))
    existing = cur.fetchone()
    if existing:
        cur.close()
        conn.close()
        return dict(existing)

    intake_id = f"intake-{uuid.uuid4().hex[:8]}"

    payload = req.model_dump(mode="json")

    cur.execute("""
        INSERT INTO intakes (id, service_id, requester_id, status, payload, revision, idempotency_key)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (intake_id, req.service_id, requester_id, "submitted", json.dumps(payload), 1, idempotency_key))

    res = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    orchestrator.record_evidence(run_id, "A01", requester_id, "create_intake", "submitted",
                                service_id=req.service_id, redacted_result={"intake_id": intake_id})
    return dict(res)

@app.get("/api/intakes")
def list_intakes():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM intakes ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/intakes/{id}/approve")
def approve_intake(id: str, req: IntakeApprove, request: Request):
    # Server-enforced authentication (REQ009, REQ025)
    principal = authenticate_request(request)
    if not principal.has_permission("intake:approve"):
        raise HTTPException(
            status_code=403,
            detail=f"Principal '{principal.id}' with role '{principal.role}' is not authorized to approve intakes"
        )

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM intakes WHERE id = %s", (id,))
    intake = cur.fetchone()
    if not intake:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail=f"Intake {id} not found")

    run_id = request.headers.get("X-Run-Id", "run_default")
    payload = intake["payload"]

    # Requester self-approval denial (REQ009, Scenario A03)
    if intake["requester_id"] == principal.id or intake["requester_id"] == req.approver_id:
        cur.close()
        conn.close()
        orchestrator.record_evidence(run_id, "A03", principal.id, "self_approval_attempt", "rejected",
                                    redacted_result={"intake_id": id, "reason": "Self-approval forbidden"})
        raise HTTPException(status_code=403, detail="Requester cannot approve their own intake request")

    # Forged approver header/body check (REQ009, Scenario A03)
    if principal.id != req.approver_id:
        cur.close()
        conn.close()
        orchestrator.record_evidence(run_id, "A03", principal.id, "forged_approver_attempt", "rejected",
                                    redacted_result={"intake_id": id, "forged_actor": principal.id, "declared_approver": req.approver_id})
        raise HTTPException(status_code=403, detail="Approver identity mismatch / forgery detected")

    # Genuine group-based ownership check (REQ009)
    # Principal must belong to the service owner_group or fallback_group, or have admin role
    service_owner = payload.get("owner_group", "")
    service_fallback = payload.get("fallback_group", "")
    if not (principal.is_member_of(service_owner) or principal.is_member_of(service_fallback)):
        cur.close()
        conn.close()
        orchestrator.record_evidence(run_id, "A03", principal.id, "wrong_owner_approval_attempt", "rejected",
                                    redacted_result={"intake_id": id, "principal_groups": list(principal.groups), "required_owner": service_owner})
        raise HTTPException(status_code=403, detail=f"Principal '{principal.id}' is not a member of owner group '{service_owner}' or fallback group '{service_fallback}'")

    if intake["revision"] != req.expected_revision:
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Record revision conflict")

    cur.execute("""
        UPDATE intakes
        SET status = 'approved', approver_id = %s, approved_at = NOW(), revision = revision + 1
        WHERE id = %s
        RETURNING *
    """, (principal.id, id))
    updated = cur.fetchone()

    # Also register service into services table
    raw_exposure = payload.get("network_exposure", "Internal")
    norm_exposure = "Public" if str(raw_exposure).lower() in ["public", "external_facing", "internet_facing"] else "Internal"
    cur.execute("""
        INSERT INTO services (id, name, owner_group, fallback_group, operational_contact,
                             environment, classification, business_criticality, application_category,
                             target_resource, requested_permissions, consumer_list, lifetime_policy,
                             replacement_mode, expected_restart_behavior, recovery_procedure_id,
                             exception_status, revision, network_exposure, data_classification,
                             auto_rotation_support, secret_manager_ref, secondary_credential_configured, gitlab_repo_url)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            target_resource = EXCLUDED.target_resource,
            application_category = EXCLUDED.application_category,
            consumer_list = EXCLUDED.consumer_list,
            owner_group = EXCLUDED.owner_group,
            fallback_group = EXCLUDED.fallback_group,
            network_exposure = EXCLUDED.network_exposure,
            data_classification = EXCLUDED.data_classification,
            auto_rotation_support = EXCLUDED.auto_rotation_support,
            secret_manager_ref = EXCLUDED.secret_manager_ref,
            secondary_credential_configured = EXCLUDED.secondary_credential_configured,
            gitlab_repo_url = EXCLUDED.gitlab_repo_url,
            revision = services.revision + 1,
            updated_at = NOW()
    """, (
        payload["service_id"], payload["service_name"], payload["owner_group"],
        payload["fallback_group"], payload["operational_contact"], payload["environment"],
        payload["classification"], payload["business_criticality"], payload["application_category"],
        payload["target_resource"], json.dumps(payload["requested_permissions"]),
        json.dumps(payload["consumer_list"]), payload["lifetime_policy"], payload["replacement_mode"],
        payload["expected_restart_behavior"], payload["recovery_procedure_id"],
        json.dumps(payload.get("exception_status")), 1,
        norm_exposure,
        payload.get("data_classification", "Restricted"),
        payload.get("auto_rotation_support", True),
        payload.get("secret_manager_ref") or f"secret/data/services/{payload['service_id']}",
        payload.get("secondary_credential_configured", False),
        payload.get("gitlab_repo_url") or f"https://gitlab.internal/platform/{payload['service_id']}"
    ))

    conn.commit()
    cur.close()
    conn.close()

    orchestrator.record_evidence(run_id, "A03", principal.id, "approve_intake", "approved",
                                service_id=payload["service_id"], redacted_result={"intake_id": id})
    return dict(updated)

@app.post("/api/intakes/{id}/provision")
def provision_intake(id: str, request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("intake:provision"):
        raise HTTPException(
            status_code=403,
            detail=f"Principal '{principal.id}' with role '{principal.role}' is not authorized to provision intakes"
        )
    run_id = request.headers.get("X-Run-Id", "run_default")
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM intakes WHERE id = %s", (id,))
    intake = cur.fetchone()
    if not intake:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Intake not found")

    if intake["status"] != "approved":
        cur.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Intake must be approved before provisioning")

    payload = intake["payload"]
    service_id = payload["service_id"]
    cred_id = f"cred-{service_id}"
    version_id = f"v1-{uuid.uuid4().hex[:6]}"
    provision_operation_id = "op-prov-" + uuid.uuid4().hex[:16]

    # The core provisions only the three explicitly configured local services.
    # Arbitrary intake does not imply that a database role or identity exists.
    category = payload['application_category']
    expected = {'svc-legacy':'legacy', 'svc-integrated':'integrated', 'svc-spiffe':'spiffe'}
    expected_target = 'spiffe-service:8443' if category == 'spiffe' else 'postgres:5432/appdb'
    if expected.get(service_id) != category or payload['target_resource'] != expected_target:
        conn.close()
        raise HTTPException(status_code=422, detail='No approved local issuer profile exists for this service')
    try:
        token = orchestrator.get_vault_token()
        raw_secret = None
        metadata = {}
        if category == 'legacy':
            actual = orchestrator._static_credentials('legacy-app-role', token)
            raw_secret = actual['password']
            if validator_adapter.validate_credential(payload['target_resource'], actual['username'], raw_secret)['status'] != 'active':
                raise ValueError('Issued static credential failed target authentication')
            issuer_ref, credential_type = 'database/static-roles/legacy-app-role', 'database_static'
            metadata = {'username':actual['username']}
        elif category == 'integrated':
            response = requests.get(f'{orchestrator.issuer_adapter.vault_addr}/v1/database/roles/integrated-role',
                                    headers={'X-Vault-Token':token}, verify=orchestrator.issuer_adapter.ca_cert, timeout=5)
            response.raise_for_status()
            issuer_ref, credential_type = 'database/roles/integrated-role', 'database_dynamic'
            version_id = None  # the broker registers each actual issued instance
        else:
            response = requests.get('http://identity-authority:8445/caller',
                                    headers={'Authorization':f"Bearer {os.environ['IDENTITY_AUTHORITY_TOKEN']}"}, timeout=10)
            response.raise_for_status()
            if response.json().get('issuance_blocked'):
                raise ValueError('Workload registration is disabled')
            issuer_ref, credential_type = 'spiffe://lab.local/workload/caller', 'x509_svid'
            version_id = None
        cur.execute("""INSERT INTO credentials (id,service_id,credential_id,issuer_type,issuer_ref,credential_type,
            permissions_summary,lifetime_seconds,rotation_mechanism,status,current_version_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'active',%s)
            ON CONFLICT (credential_id) DO UPDATE SET issuer_ref=EXCLUDED.issuer_ref,
                credential_type=EXCLUDED.credential_type, current_version_id=COALESCE(EXCLUDED.current_version_id,credentials.current_version_id)
        """, (cred_id,service_id,cred_id,'spire' if category=='spiffe' else 'vault',issuer_ref,credential_type,
              ','.join(payload['requested_permissions']),3600,'vault_coordinated' if category!='spiffe' else 'svid_renewal',version_id))
        if raw_secret:
            cur.execute("""INSERT INTO credential_versions(id,credential_id,version_id,hmac_fingerprint,canonical_version,status,metadata)
                VALUES (%s,%s,%s,%s,'v1','active',%s)""",
                        ('cv-'+uuid.uuid4().hex,cred_id,version_id,compute_fingerprint(raw_secret,'v1'),json.dumps(metadata)))
        cur.execute("""INSERT INTO operations (id,idempotency_key,action,status,target,execution_identity,params)
                    VALUES (%s,%s,'provision','completed',%s,%s,%s)""",
                    (provision_operation_id,'provision:'+id,service_id,principal.id,json.dumps({'intake_id':id})))
        cur.execute("UPDATE intakes SET status='provisioned' WHERE id=%s", (id,))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        raise HTTPException(status_code=502, detail='Issuer provisioning or verification failed; no active registration committed') from exc
    finally:
        cur.close()
        conn.close()
    orchestrator.record_evidence(run_id,'A04',principal.id,'provision_service','provisioned',service_id=service_id,
                                credential_version_id=version_id,redacted_result={'credential_id':cred_id})
    return {'status':'provisioned','operation_id':provision_operation_id,'service_id':service_id,'credential_id':cred_id,'current_version_id':version_id}

@app.get("/api/services/{id}")
def get_service(id: str):
    svc = registry_adapter.get_service(id)
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    return svc

@app.get("/api/services")
def list_services():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT DISTINCT ON (name) *
        FROM services
        ORDER BY name, updated_at DESC, created_at DESC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/services/{id}/unblock-issuance")
def unblock_service_issuance(id: str, request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("operation:execute"):
        raise HTTPException(status_code=403, detail="Unauthorized")
    svc = registry_adapter.get_service(id)
    if id != 'svc-integrated' or not svc or svc['application_category'] != 'integrated':
        raise HTTPException(status_code=422, detail='No supported integrated workload recovery for this service')
    if not orchestrator.issuer_adapter.unblock_workload_issuance(token=orchestrator.get_vault_token()):
        raise HTTPException(status_code=502, detail='Issuer recovery authorization failed')
    admin_headers = {'Authorization':'Bearer '+os.environ['INTEGRATED_ADMIN_TOKEN']}
    response = requests.post('http://integrated-app:8002/block_issuance?blocked=false',headers=admin_headers,timeout=5)
    response.raise_for_status()
    replacement = requests.post('http://integrated-app:8002/replace',headers=admin_headers,timeout=10)
    replacement.raise_for_status()
    business = requests.get('http://integrated-app:8002/workload',timeout=5)
    business.raise_for_status()
    conn = get_connection()
    with conn.cursor() as cur:
        cur.execute("UPDATE incidents SET recovery_status='healthy', recovered_at=NOW(), revision=revision+1 WHERE service_id=%s AND containment_status='verified' AND case_status='open'", (id,))
    conn.commit(); conn.close()
    orchestrator.record_evidence(request.headers.get('X-Run-Id','run_default'),'A11',principal.id,
                                'authorize_workload_recovery','healthy',service_id=id,
                                redacted_result={'replacement_registered':True,'business_health':True})
    return {'status':'unblocked','service_id':id,'recovery':'healthy'}

@app.post("/api/findings", status_code=201)
def receive_finding(event: FindingEvent, request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("finding:create"):
        raise HTTPException(
            status_code=403,
            detail=f"Principal '{principal.id}' with role '{principal.role}' is not authorized to submit findings"
        )
    run_id = request.headers.get("X-Run-Id", "run_default")
    conn = get_connection()
    cur = conn.cursor()

    # Advisory lock to serialize duplicate concurrent findings on event_id (Scenario A20)
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (event.event_id,))

    # Replay protection / duplicate detection (REQ029, REQ034, Scenario A20)
    cur.execute("SELECT * FROM incidents WHERE finding_id = %s", (event.event_id,))
    existing_incident = cur.fetchone()
    if existing_incident:
        conn.commit()
        cur.close()
        conn.close()
        return {
            "status": "duplicate_accepted",
            "incident_id": existing_incident["id"],
            "case_status": existing_incident["case_status"]
        }

    # Resolve candidate secret from reference or fingerprint
    candidate_secret = None
    if event.candidate_ref:
        try:
            candidate_secret = candidate_store.get(event.candidate_ref, principal.id, run_id)
        except ValueError:
            candidate_secret = None

    # Resolve credential version via HMAC fingerprint lookup (REQ012, REQ029)
    matched_version = None
    target_service_id = None
    correlation_status = "unmatched"

    if event.fingerprint:
        cur.execute("SELECT * FROM credential_versions WHERE hmac_fingerprint = %s ORDER BY created_at DESC", (event.fingerprint,))
        matched_version = cur.fetchone()
    elif candidate_secret:
        calculated_fp = compute_fingerprint(candidate_secret, "v1")
        cur.execute("SELECT * FROM credential_versions WHERE hmac_fingerprint = %s ORDER BY created_at DESC", (calculated_fp,))
        matched_version = cur.fetchone()

    if matched_version:
        correlation_status = "matched"
        # Resolve credential and service
        cur.execute("SELECT * FROM credentials WHERE credential_id = %s", (matched_version["credential_id"],))
        cred = cur.fetchone()
        if cred:
            target_service_id = cred["service_id"]
    elif event.claimed_service_hint:
        # Untrusted hint: resolve strictly against authoritative registry (REQ029, Scenario A16)
        authoritative = registry_adapter.get_service(event.claimed_service_hint)
        if authoritative:
            target_service_id = authoritative["id"]
            correlation_status = "ambiguous"

    # Resolve owner
    owner_info = registry_adapter.resolve_owner(target_service_id) if target_service_id else {"owner_group": "security_fallback", "type": "fallback"}
    assigned_owner = owner_info["owner_group"]

    # Initial Validation check (REQ030)
    validation_status = "inconclusive"
    if candidate_secret and target_service_id:
        svc = registry_adapter.get_service(target_service_id)
        if svc:
            username = (matched_version.get("metadata") or {}).get("username", "legacy_user") if matched_version else "legacy_user"
            val_res = validator_adapter.validate_credential(svc["target_resource"], username, candidate_secret)
            validation_status = val_res["status"]

    incident_id = f"inc-{uuid.uuid4().hex[:8]}"

    cur.execute("""
        INSERT INTO incidents (id, finding_id, service_id, credential_version_id,
                              correlation_status, triage_status, containment_status,
                              recovery_status, investigation_status, case_status,
                              assigned_owner, revision, candidate_ref, validation_status)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (
        incident_id, event.event_id, target_service_id,
        matched_version["version_id"] if matched_version else None,
        correlation_status, "pending", "pending", "pending", "open", "open",
        assigned_owner, 1, event.candidate_ref, validation_status
    ))
    new_incident = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    orchestrator.record_evidence(run_id, "A06", principal.id, "finding_received", "open",
                                incident_id=incident_id, service_id=target_service_id,
                                credential_version_id=matched_version["version_id"] if matched_version else None,
                                redacted_result={"finding_id": event.event_id, "correlation": correlation_status, "assigned_owner": assigned_owner})

    return dict(new_incident)

@app.post("/api/incidents/{id}/decisions")
def record_decision(id: str, dec: IncidentDecision, request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("incident:decide"):
        raise HTTPException(
            status_code=403,
            detail=f"Principal '{principal.id}' with role '{principal.role}' lacks permission to record decisions"
        )
    actor = principal.id if principal.id != "anonymous" else dec.actor

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM incidents WHERE id = %s FOR UPDATE", (id,))
    incident = cur.fetchone()
    if not incident:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Incident not found")

    if principal.role not in ('admin','operator'):
        svc = registry_adapter.get_service(incident['service_id']) if incident.get('service_id') else None
        permitted_groups = {incident.get('assigned_owner')}
        if svc:
            permitted_groups.update({svc.get('owner_group'),svc.get('fallback_group')})
        if not principal.groups.intersection(permitted_groups):
            conn.close()
            raise HTTPException(status_code=403, detail='Decision actor is not assigned to this service or fallback group')
    if incident["revision"] != dec.expected_revision:
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Incident record revision conflict")

    cur.execute("""
        UPDATE incidents
        SET triage_status = 'decided', decision_action = %s, decision_reason = %s,
            decided_by = %s, decided_at = NOW(), revision = revision + 1, updated_at = NOW()
        WHERE id = %s
        RETURNING *
    """, (dec.action.value, dec.reason, actor, id))
    updated_inc = cur.fetchone()

    # Create corresponding operation with derived idempotency key (REQ034)
    policy_rev = 1
    idempotency_key = orchestrator.generate_idempotency_key(id, incident.get("credential_version_id"), dec.action.value, policy_rev)

    cur.execute("SELECT * FROM operations WHERE idempotency_key = %s", (idempotency_key,))
    existing_op = cur.fetchone()
    if not existing_op:
        op_id = f"op-{uuid.uuid4().hex[:8]}"

        # Resolve immutable lease and target metadata from the matched issued version.
        op_params = {}
        if dec.action.value == "revoke":
            c_ver_id = incident.get("credential_version_id")
            if c_ver_id:
                cur.execute("SELECT metadata FROM credential_versions WHERE version_id = %s", (c_ver_id,))
                cv_row = cur.fetchone()
                if cv_row and cv_row.get("metadata") and cv_row["metadata"].get("lease_id"):
                    op_params = cv_row["metadata"]
                else:
                    op_params = {"missing_lease_metadata": True}
            else:
                op_params = {"missing_lease_metadata": True}

        op_params["candidate_ref"] = incident.get("candidate_ref")
        cur.execute("""
            INSERT INTO operations (id, idempotency_key, incident_id, credential_version_id,
                                   action, status, policy_revision, target, execution_identity, params)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING *
        """, (op_id, idempotency_key, id, incident.get("credential_version_id"), dec.action.value,
              "pending", policy_rev, incident.get("service_id") or "target", actor, json.dumps(op_params)))
        op = cur.fetchone()
    else:
        op = existing_op

    conn.commit()
    cur.close()
    conn.close()

    run_id = request.headers.get("X-Run-Id", "run_default")
    orchestrator.record_evidence(run_id, "A06", actor, "triage_decision", "decided",
                                incident_id=id, operation_id=op["id"], service_id=incident.get("service_id"),
                                redacted_result={"action": dec.action.value, "reason": dec.reason})

    return {
        "incident": dict(updated_inc),
        "operation": dict(op)
    }

def validate_and_close_incident(
    incident_id: str,
    actor: str,
    recovery_disposition: str,
    investigation_limitations: str,
    recurrence_owner: str,
    expected_revision: Optional[int] = None,
    run_id: str = "run_default"
) -> Dict[str, Any]:
    """
    Single unified validator and closure function across all entry points.
    Enforces that containment is verified or genuine not_applicable with approved exception,
    and requires all four mandatory closure fields. Does not forge verified status.
    """
    if not incident_id:
        raise HTTPException(status_code=400, detail="Missing incident_id")

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
    incident = cur.fetchone()
    if not incident:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Incident not found")

    if expected_revision is not None and incident["revision"] != expected_revision:
        cur.close()
        conn.close()
        raise HTTPException(status_code=409, detail="Incident revision conflict")

    # Preconditions for closure (REQ031, REQ033, Scenario A18).
    # 1. Containment must be verified, or not_applicable with approved evidence
    c_status = incident.get("containment_status")
    if c_status != "verified":
        cur.close()
        conn.close()
        raise HTTPException(
            status_code=422,
            detail=f"Cannot close incident: containment status is '{c_status}', but 'verified' is required before closure."
        )

    # 2. Recovery disposition must be provided
    if not recovery_disposition or not recovery_disposition.strip():
        cur.close()
        conn.close()
        raise HTTPException(status_code=422, detail="Cannot close incident: missing recovery disposition")

    # 3. Investigation limitations must be provided
    if not investigation_limitations or not investigation_limitations.strip():
        cur.close()
        conn.close()
        raise HTTPException(status_code=422, detail="Cannot close incident: missing investigation limitations")

    # 4. Recurrence owner must be assigned
    if not recurrence_owner or not recurrence_owner.strip():
        cur.close()
        conn.close()
        raise HTTPException(status_code=422, detail="Cannot close incident: missing recurrence owner")

    # Recovery status must be healthy, or accepted_risk for approved exceptions.
    r_status = incident.get("recovery_status")
    if r_status not in ("healthy", "degraded"):
        # Degraded recovery is closable only with an explicit human disposition.
        cur.close()
        conn.close()
        raise HTTPException(status_code=422, detail=f"Cannot close incident: recovery status is '{r_status}'")

    cur.execute("""
        UPDATE incidents
        SET case_status = 'closed', investigation_status = 'complete_with_limitations',
            recovery_disposition = %s, investigation_limitations = %s,
            recurrence_owner = %s, closed_by = %s, closed_at = NOW(),
            revision = revision + 1, updated_at = NOW()
        WHERE id = %s
        RETURNING *
    """, (recovery_disposition, investigation_limitations, recurrence_owner, actor, incident_id))
    closed = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()

    orchestrator.record_evidence(run_id, "A18", actor, "close_incident", "closed",
                                incident_id=incident_id, service_id=incident.get("service_id"),
                                redacted_result={"disposition": recovery_disposition, "owner": recurrence_owner})
    return dict(closed)

def mark_incident_closed_at_workflow_level(incident_id: str, actor: str = "secops_workflow", disposition: str = "resolved_via_workflow", limitations: str = "Pipeline audit completed", recurrence_owner: str = "owner_dave", run_id: str = "run_default"):
    # Pipelines may submit evidence; they cannot supply the human investigation.
    # A permitted user must explicitly review and close through /close.
    return None

@app.post("/api/operations/{id}/execute")
def execute_operation_endpoint(id: str, req: OperationExecute, request: Request,
                               simulate_interruption: bool = False, simulate_restart_failure: bool = False,
                               pause_after_issuer_effect: bool = False):
    principal = authenticate_request(request)
    if not principal.has_permission("operation:execute"):
        raise HTTPException(
            status_code=403,
            detail=f"Principal '{principal.id}' with role '{principal.role}' is not authorized to execute operations"
        )
    run_id = request.headers.get("X-Run-Id", "run_default")
    execution_identity = principal.id if principal.id != "anonymous" else req.execution_identity
    result = orchestrator.execute_operation(
        operation_id=id,
        execution_identity=execution_identity,
        simulate_interruption=simulate_interruption,
        simulate_restart_failure=simulate_restart_failure,
        run_id=run_id,
        pause_after_issuer_effect=pause_after_issuer_effect
    )
    return result

@app.get("/api/operations/{id}")
def get_operation(id: str):
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM operations WHERE id=%s", (id,))
        operation = cur.fetchone()
        if not operation:
            raise HTTPException(status_code=404, detail="Operation not found")
        return dict(operation)
    finally:
        cur.close(); conn.close()

@app.post("/api/incidents/{id}/close")
def close_incident(id: str, req: IncidentClose, request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("incident:close"):
        raise HTTPException(
            status_code=403,
            detail=f"Principal '{principal.id}' with role '{principal.role}' lacks permission to close incidents"
        )
    run_id = request.headers.get("X-Run-Id", "run_default")
    actor = principal.id if principal.id != "anonymous" else req.actor
    return validate_and_close_incident(
        incident_id=id,
        actor=actor,
        recovery_disposition=req.recovery_disposition,
        investigation_limitations=req.investigation_limitations,
        recurrence_owner=req.recurrence_owner,
        expected_revision=req.expected_revision,
        run_id=run_id
    )

@app.get("/api/incidents/{id}")
def get_incident(id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents WHERE id = %s FOR UPDATE", (id,))
    inc = cur.fetchone()
    cur.close()
    conn.close()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return dict(inc)

@app.get("/api/incidents")
def list_incidents():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM incidents ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/incidents/{id}/evidence")
def get_incident_evidence(id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence_events WHERE incident_id = %s ORDER BY created_at ASC", (id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

# --- METRICS (REQ040, REQ041, Scenario A24) ---

@app.post("/api/scan-attempts", status_code=201)
def schedule_scan(body: Dict[str, Any], request: Request):
    principal = authenticate_request(request)
    if principal.role != 'admin':
        raise HTTPException(status_code=403, detail='Only the local scheduler administrator can create expected scans')
    try:
        due = datetime.fromisoformat(body['due_at'].replace('Z','+00:00'))
        if due.tzinfo is None:
            raise ValueError('timezone required')
        if due < datetime.now(timezone.utc)-timedelta(minutes=5):
            raise ValueError('cannot backdate scheduled scans')
    except (KeyError, ValueError, TypeError):
        raise HTTPException(status_code=422, detail='due_at must be a current or future timezone-aware timestamp')
    scan_id = 'scan-'+uuid.uuid4().hex
    conn=get_connection(); cur=conn.cursor()
    try:
        cur.execute('SELECT id FROM services WHERE id=%s',(body.get('service_id'),))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail='Registered service required')
        from evidence_context import current_run_id
        cur.execute('INSERT INTO scan_attempts(id,service_id,run_id,due_at) VALUES (%s,%s,%s,%s)',
                    (scan_id,body['service_id'],current_run_id.get(),due))
        conn.commit()
    finally:
        cur.close();conn.close()
    orchestrator.record_evidence(current_run_id.get(),'A24',principal.id,'scan_scheduled','pending',
        service_id=body['service_id'],redacted_result={'scan_id':scan_id,'due_at':due.isoformat()})
    return {'id':scan_id}

@app.post("/api/scan-attempts/{scan_id}/complete")
def complete_scan(scan_id: str, body: Dict[str, Any], request: Request):
    principal=authenticate_request(request)
    if principal.role not in ('scanner','admin'):
        raise HTTPException(status_code=403,detail='Scanner permission required')
    if body.get('outcome') not in ('clean','findings','error') or not body.get('detector_version'):
        raise HTTPException(status_code=422,detail='Explicit scan outcome and detector version required')
    conn=get_connection();cur=conn.cursor()
    try:
        cur.execute('SELECT * FROM scan_attempts WHERE id=%s FOR UPDATE',(scan_id,)); row=cur.fetchone()
        if not row:
            raise HTTPException(status_code=404,detail='Scheduled scan not found')
        if row['outcome']:
            if row['outcome'] != body['outcome'] or row['detector_version'] != body['detector_version']:
                raise HTTPException(status_code=409,detail='Completed scan outcome is immutable')
            return {'status':'already_recorded'}
        cur.execute('UPDATE scan_attempts SET outcome=%s,detector_version=%s,completed_at=NOW() WHERE id=%s',
                    (body['outcome'],body['detector_version'],scan_id));conn.commit()
    finally:
        cur.close();conn.close()
    orchestrator.record_evidence(row['run_id'],'A24',principal.id,'scan_completed',body['outcome'],
        service_id=row['service_id'],redacted_result={'scan_id':scan_id,'detector_version':body['detector_version']})
    return {'status':'recorded'}

@app.post("/api/services/{service_id}/owner")
def update_service_owner(service_id: str, body: Dict[str, Any], request: Request):
    principal=authenticate_request(request)
    if principal.role != 'admin':
        raise HTTPException(status_code=403,detail='Owner registry administrator required')
    owner=body.get('owner_group')
    if not isinstance(owner,str) or len(owner)>64:
        raise HTTPException(status_code=422,detail='owner_group must be a string; empty explicitly means unresolved')
    conn=get_connection();cur=conn.cursor()
    try:
        cur.execute('UPDATE services SET owner_group=%s,revision=revision+1,updated_at=NOW() WHERE id=%s RETURNING revision', (owner,service_id))
        row=cur.fetchone()
        if not row:
            raise HTTPException(status_code=404,detail='Service not found')
        conn.commit()
    finally:
        cur.close();conn.close()
    from evidence_context import current_run_id
    orchestrator.record_evidence(current_run_id.get(),'A24',principal.id,'owner_changed','unresolved' if not owner else 'assigned',service_id=service_id,
        redacted_result={'owner_group':owner,'revision':row['revision']})
    return {'owner_group':owner,'revision':row['revision']}

@app.get("/api/metrics")
def get_metrics():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM intakes")
    total_intakes = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) FROM intakes WHERE status = 'provisioned'")
    provisioned_intakes = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE created_at >= NOW() - INTERVAL '24 hours'")
    total_incidents = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE case_status = 'open'")
    open_incidents = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE assigned_owner = 'security_fallback'")
    fallback_ownership_count = cur.fetchone()["count"]

    cur.execute("SELECT COUNT(*) FROM incidents WHERE containment_status = 'verified'")
    verified_containments = cur.fetchone()["count"]

    # An immutable scheduled attempt supplies the denominator, even if the
    # owner disappears or no scanner result ever arrives. Findings are not scans.
    cur.execute("""SELECT COUNT(*) AS expected,
        COUNT(*) FILTER (WHERE outcome IN ('clean','findings')) AS completed,
        COUNT(*) FILTER (WHERE outcome='error') AS errors,
        COUNT(*) FILTER (WHERE outcome IS NULL) AS missing
        FROM scan_attempts WHERE due_at <= NOW() AND due_at >= NOW()-INTERVAL '24 hours'""")
    scans = cur.fetchone()
    expected_scans, actual_scans, missing_scans = scans['expected'], scans['completed'], scans['missing']
    cur.execute("SELECT EXTRACT(EPOCH FROM (NOW()-MAX(created_at))) AS age FROM evidence_events")
    freshness = cur.fetchone()['age']
    cur.execute("""SELECT COUNT(*) AS count FROM incidents i LEFT JOIN services s ON i.service_id=s.id
        WHERE i.created_at >= NOW()-INTERVAL '24 hours'
          AND (i.assigned_owner='security_fallback' OR s.id IS NULL OR s.owner_group='')""")
    fallback_ownership_count = cur.fetchone()['count']
    cur.execute("SELECT EXTRACT(EPOCH FROM (NOW()-MIN(created_at))) AS age FROM incidents WHERE case_status='open'")
    oldest_open = cur.fetchone()['age']

    # Compute observed median containment and recovery times using explicit transition timestamps
    cur.execute("""
        SELECT EXTRACT(EPOCH FROM (contained_at - created_at)) AS duration
        FROM incidents
        WHERE containment_status = 'verified' AND contained_at IS NOT NULL AND contained_at >= created_at
          AND created_at >= NOW() - INTERVAL '24 hours'
    """)
    containment_durations = [float(r["duration"]) for r in cur.fetchall() if r["duration"] is not None]
    if containment_durations:
        s_dur = sorted(containment_durations)
        n = len(s_dur)
        median_ttc = round((s_dur[n // 2] if n % 2 != 0 else (s_dur[n // 2 - 1] + s_dur[n // 2]) / 2), 1)
    else:
        median_ttc = None

    cur.execute("""
        SELECT EXTRACT(EPOCH FROM (recovered_at - created_at)) AS duration
        FROM incidents
        WHERE recovery_status = 'healthy' AND recovered_at IS NOT NULL AND recovered_at >= created_at
          AND created_at >= NOW() - INTERVAL '24 hours'
    """)
    recovery_durations = [float(r["duration"]) for r in cur.fetchall() if r["duration"] is not None]
    if recovery_durations:
        s_dur = sorted(recovery_durations)
        n = len(s_dur)
        median_ttr = round((s_dur[n // 2] if n % 2 != 0 else (s_dur[n // 2 - 1] + s_dur[n // 2]) / 2), 1)
    else:
        median_ttr = None

    cur.close()
    conn.close()

    return {
        "scope": "credential_laboratory_core",
        "interval": "last_24h",
        "evidence_freshness_seconds": float(freshness) if freshness is not None else None,
        "metrics": {
            "intake_completeness_pct": round((provisioned_intakes / max(1, total_intakes)) * 100, 1),
            "owner_resolution_coverage_pct": round(((total_incidents - fallback_ownership_count) / max(1, total_incidents)) * 100, 1),
            "scan_coverage": {
                "expected": expected_scans,
                "completed": actual_scans,
                "missing": missing_scans,
                "errors": scans["errors"],
                "coverage_pct": round((actual_scans / max(1, expected_scans)) * 100, 1)
            },
            "open_cases": open_incidents,
            "unresolved_ownership_count": fallback_ownership_count,
            "oldest_open_case_seconds": float(oldest_open) if oldest_open is not None else None,
            "total_cases": total_incidents,
            "verified_containment_count": verified_containments,
            "containment_sample_size": len(containment_durations),
            "recovery_sample_size": len(recovery_durations),
            "median_time_to_containment_seconds": median_ttc if median_ttc is not None else "unknown",
            "median_time_to_recovery_seconds": median_ttr if median_ttr is not None else "unknown"
        }
    }

# --- INTERNAL CANDIDATE & FINGERPRINT ENDPOINTS ---

@app.post("/api/internal/store-candidate")
def store_candidate(req: Dict[str, str], request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("internal:store"):
        raise HTTPException(status_code=403, detail="Unauthorized to store candidate secrets")

    val = req.get("candidate_val")
    if not val:
        raise HTTPException(status_code=400, detail="Missing candidate_val")
    ref_id = candidate_store.put(val)
    return {"candidate_ref": ref_id}

@app.post("/api/internal/register-fingerprint")
def register_fingerprint(req: Dict[str, Any], request: Request):
    principal = authenticate_request(request)
    if not principal.has_permission("internal:register"):
        raise HTTPException(status_code=403, detail="Unauthorized to register fingerprints")

    service_id = req["service_id"]
    if principal.role == "internal" and service_id != "svc-integrated":
        raise HTTPException(status_code=403, detail="Service identity cannot register another service")
    version_id = req["version_id"]
    raw_secret = req["raw_secret"]
    canonical_ver = req.get("canonical_version", "v1")
    metadata = req.get("metadata") or {}
    fp = compute_fingerprint(raw_secret, canonical_ver)

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT credential_id FROM credentials WHERE service_id = %s LIMIT 1", (service_id,))
    cred_row = cur.fetchone()
    if not cred_row:
        conn.close()
        raise HTTPException(status_code=409, detail="Approved provisioning must precede issued-instance registration")
    cred_id = cred_row["credential_id"]
    if principal.role == 'internal':
        allowed_keys = {'lease_id','username','target_resource'}
        if set(metadata) != allowed_keys or not metadata['lease_id'].startswith('database/creds/integrated-role/') or 'dyn-' + uuid.uuid5(uuid.NAMESPACE_URL, metadata['lease_id']).hex != version_id or metadata['target_resource'] != 'postgres:5432/appdb':
            conn.close()
            raise HTTPException(status_code=422, detail='Invalid integrated lease metadata')
        validity = validator_adapter.validate_credential(metadata['target_resource'], metadata['username'], raw_secret)
        if validity['status'] != 'active':
            conn.close()
            raise HTTPException(status_code=422, detail='Issued candidate did not authenticate at registered target')
    cur.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))', ('version:'+version_id,))
    cur.execute('SELECT * FROM credential_versions WHERE version_id=%s FOR UPDATE', (version_id,))
    existing = cur.fetchone()
    if existing and (existing['hmac_fingerprint'] != fp or existing['credential_id'] != cred_id or existing['metadata'] != metadata):
        conn.close()
        raise HTTPException(status_code=409, detail='Issued version history is immutable')

    row_id = "cv-" + uuid.uuid5(uuid.NAMESPACE_URL, f"{service_id}-{version_id}").hex
    cur.execute("""
        INSERT INTO credential_versions (id, credential_id, version_id, hmac_fingerprint, canonical_version, status, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (version_id) DO NOTHING
    """, (row_id, cred_id, version_id, fp, canonical_ver, "active", json.dumps(metadata)))
    cur.execute('UPDATE credentials SET current_version_id=%s WHERE credential_id=%s', (version_id, cred_id))
    conn.commit()
    cur.close()
    conn.close()
    return {"status": "registered", "fingerprint": fp}

@app.post("/api/internal/reconcile-static-legacy")
def reconcile_static_legacy(request: Request):
    """Reconcile the sole approved legacy static role without exposing it.

    This is intentionally administrator-only. It reads the issuer directly,
    proves the returned credential still authenticates at the fixed target, and
    records one current version while retiring every prior active version for the
    same credential. It is for restart/recovery reconciliation, not issuance.
    """
    principal = authenticate_request(request)
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator permission required")
    token = orchestrator.get_vault_token()
    actual = orchestrator._static_credentials("legacy-app-role", token)
    if validator_adapter.validate_credential("postgres:5432/appdb", actual["username"], actual["password"])["status"] != "active":
        raise HTTPException(status_code=502, detail="Issuer credential did not authenticate at the registered target")
    version_id = "reconcile-" + uuid.uuid4().hex[:12]
    conn = get_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT credential_id FROM credentials WHERE service_id=%s AND credential_type='database_static' FOR UPDATE", ("svc-legacy",))
        credential = cur.fetchone()
        if not credential:
            raise HTTPException(status_code=409, detail="Approved legacy credential registration is required")
        cred_id = credential["credential_id"]
        fingerprint = compute_fingerprint(actual["password"], "v1")
        cur.execute("SELECT version_id,hmac_fingerprint FROM credential_versions WHERE credential_id=%s AND version_id=(SELECT current_version_id FROM credentials WHERE credential_id=%s) FOR UPDATE", (cred_id, cred_id))
        current_version = cur.fetchone()
        if current_version and current_version["hmac_fingerprint"] == fingerprint:
            version_id = current_version["version_id"]
            changed = False
        else:
            cur.execute("UPDATE credential_versions SET status='revoked', revoked_at=COALESCE(revoked_at,NOW()) WHERE credential_id=%s AND status='active'", (cred_id,))
            cur.execute("INSERT INTO credential_versions (id,credential_id,version_id,hmac_fingerprint,canonical_version,status,metadata) VALUES (%s,%s,%s,%s,'v1','active',%s)",
                        ("cv-" + uuid.uuid4().hex, cred_id, version_id, fingerprint, json.dumps({"username": actual["username"], "reconciled_by": principal.id})))
            cur.execute("UPDATE credentials SET current_version_id=%s WHERE credential_id=%s", (version_id, cred_id))
            changed = True
        conn.commit()
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        raise HTTPException(status_code=502, detail="Static credential reconciliation failed") from exc
    finally:
        cur.close()
        conn.close()
    orchestrator.record_evidence(request.headers.get("X-Run-Id", "run_default"), "A21", principal.id,
                                "static_credential_reconciled", "verified", credential_version_id=version_id,
                                service_id="svc-legacy", redacted_result={"issuer_verified": True, "changed": changed})
    return {"status": "reconciled", "credential_version_id": version_id, "changed": changed}

@app.get("/api/evidence")
def list_evidence(run_id: Optional[str] = None):
    conn = get_connection()
    cur = conn.cursor()
    if run_id:
        cur.execute("SELECT * FROM evidence_events WHERE run_id = %s ORDER BY created_at ASC", (run_id,))
    else:
        cur.execute("SELECT * FROM evidence_events ORDER BY created_at ASC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [dict(r) for r in rows]

# --- INTERACTIVE TESTING DEMO TRIGGERS FOR UI ---
def run_scoped_demo(scenarios: str):
    """Run scenarios in the control container with short-lived scoped tokens.

    The child receives no account passwords or bootstrap credential file. Tokens
    are minted only after the authenticated admin reaches this endpoint and are
    used solely for this one local scenario process.
    """
    from auth import create_access_token
    identities = ("alice", "bob", "owner_dave", "sec_officer", "sec_responder",
                  "lead_responder", "secops_admin", "gitleaks", "scanner_svc", "anomaly_monitor")
    env = os.environ.copy()
    env["SCENARIO_BEARER_TOKENS"] = json.dumps({identity: create_access_token(identity) for identity in identities})
    env["CONTROL_URL"] = "http://control-api:8000"
    cmd = [sys.executable, os.path.join(POC_DIR, "scripts", "run_scenarios.py"), "--scenario", scenarios]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=env)
    output = proc.stdout + proc.stderr
    if proc.returncode:
        raise HTTPException(status_code=502, detail={"scenario": scenarios, "output": output[-4000:]})
    return {"status": "ok", "scenario": scenarios, "output": output[-4000:]}

@app.post("/api/demo/legacy")
def trigger_demo_legacy():
    return run_scoped_demo("A06")

@app.post("/api/demo/integrated")
def trigger_demo_integrated():
    return run_scoped_demo("A09,A10")

@app.post("/api/demo/identity")
def trigger_demo_identity():
    return run_scoped_demo("A12,A14")

@app.post("/api/demo/suite")
def trigger_demo_suite():
    return run_scoped_demo("A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12,A13,A14,A15,A16,A17,A18,A19,A20,A21,A22,A23,A24,A25,A26")

# --- LOCAL PIPELINE WORKFLOW SIMULATOR ---
from gitlab_simulator import GitLabSimulator, GITLAB_INTERNAL_URL, gl_token
gitlab_sim = GitLabSimulator()

@app.post("/api/gitlab/push")
def gitlab_push(req: Dict[str, Any]):
    project_id = req.get("project_id", "svc-legacy")
    commit_sha = req.get("commit_sha", uuid.uuid4().hex[:10])
    commit_message = req.get("commit_message", "feat: update database integration settings")
    diff_content = req.get("diff_content", "")
    branch = req.get("branch", "main")
    secret_type = req.get("secret_type")

    # If user explicitly requested an active secret simulation, fetch live active Vault password
    if secret_type == "active" or req.get("use_active_secret"):
        try:
            v_token = orchestrator.get_vault_token()
            v_resp = requests.get(
                f"{orchestrator.issuer_adapter.vault_addr}/v1/database/static-creds/legacy-app-role",
                headers={"X-Vault-Token": v_token},
                verify=orchestrator.issuer_adapter.ca_cert,
                timeout=5
            )
            if v_resp.status_code == 200:
                active_pwd = v_resp.json().get("data", {}).get("password")
                if active_pwd:
                    diff_content = (
                        f"diff --git a/config/database.yml b/config/database.yml\n"
                        f'+  password: "{active_pwd}"\n'
                    )
                    commit_message = f"feat(config): leak verified active database credentials [live-creds {uuid.uuid4().hex[:4]}]"
        except Exception as ex:
            print(f"[WARN] Failed fetching active secret from Vault: {ex}")
    elif secret_type == "invalid":
        test_token = f"LAB_SEC_EXP_TEST_{uuid.uuid4().hex[:8]}"
        diff_content = f'diff --git a/config/database.yml b/config/database.yml\n+  password: "{test_token}"\n'
        commit_message = f"feat(config): add static test key {test_token}"

    result = gitlab_sim.trigger_pipeline(project_id, commit_sha, commit_message, diff_content, branch)
    return result

@app.get("/api/gitlab/pipelines")
def gitlab_pipelines():
    return gitlab_sim.list_pipelines()

@app.get("/api/gitlab/pipelines/{id}")
def gitlab_pipeline_detail(id: str):
    res = gitlab_sim.get_pipeline(id)
    if not res:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    return res

@app.post("/api/gitlab/pipelines/{id}/revoke-credential")
@app.post("/api/gitlab/pipelines/{id}/reject")
@app.post("/api/gitlab/pipelines/{id}/approve-revocation")
def gitlab_reject_pipeline(id: str, request: Request):
    """Reject deployment: cancel manual deploy job in SAME pipeline; remediation/rotation is handled by SecOps outside the pipeline"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM gitlab_pipelines WHERE id = %s", (id,))
    pipe = cur.fetchone()
    if not pipe:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Pipeline not found")

    pipe_info = gitlab_sim.get_pipeline(id) or {}
    cmdb_ctx = pipe_info.get("cmdb_context") or {}
    validation = pipe_info.get("validation") or {}
    val_status = pipe.get("validation_status") or validation.get("status", "unknown")

    incident_id = pipe.get("incident_id") or pipe_info.get("incident_id")
    if not incident_id and (pipe.get("scan_findings") or []):
        findings = pipe["scan_findings"]
        cmdb_hint = pipe.get("project_id", "svc-legacy")
        incident_id = gitlab_sim._create_pipeline_incident(id, cmdb_hint, findings[0], cmdb_ctx)
        cur.execute("UPDATE gitlab_pipelines SET incident_id = %s WHERE id = %s", (incident_id, id))
        conn.commit()

    # 1. If incident exists, record rejection in audit trail
    if incident_id:
        cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
        inc = cur.fetchone()
        if inc:
            dec = IncidentDecision(
                actor="secops_auditor",
                action=DecisionAction.RECORD_EXCEPTION,
                reason=f"Pipeline {id} deployment rejected at manual gate. Commit {pipe['commit_sha']} halted. Remediation/rotation delegated to SecOps outside pipeline.",
                expected_revision=inc["revision"]
            )
            dec_res = record_decision(incident_id, dec, request)
            op_id = dec_res.get("operation", {}).get("id")
            if op_id:
                try:
                    orchestrator.execute_operation(op_id, execution_identity="gitlab_runner_secops")
                except Exception as ex:
                    print(f"[WARN] Error executing reject operation {op_id}: {ex}")

            # Auto-close incident since action was performed at workflow level
            mark_incident_closed_at_workflow_level(
                incident_id=incident_id,
                actor="secops_auditor",
                disposition="rejected_at_pipeline_gate",
                recurrence_owner=inc.get("assigned_owner") or "owner_dave"
            )

    # 2. Extract deploy_job_id from pipe_info stages if available and cancel it in GitLab
    deploy_job_id = None
    stages = pipe_info.get("stages") or pipe.get("stages") or []
    if len(stages) >= 3 and stages[2].get("job_id"):
        deploy_job_id = stages[2]["job_id"]

    gitlab_sim.cancel_manual_job(job_id=deploy_job_id, pipeline_id=id)

    # 3. Update database record: pipeline rejected / canceled
    if len(stages) >= 3:
        stages[1]["status"] = "rejected"
        stages[2]["status"] = "blocked"

    cur.execute("UPDATE gitlab_pipelines SET status = 'rejected', stages = %s, updated_at = NOW() WHERE id = %s",
                (json.dumps(stages), id))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "status": "rejected_and_halted",
        "pipeline_id": id,
        "deploy_job_id": deploy_job_id,
        "incident_id": incident_id,
        "validation_status": val_status,
        "message": f"Pipeline #{id} rejected. Deployment canceled in GitLab. Remediation delegated to SecOps outside pipeline."
    }

@app.post("/api/gitlab/pipelines/{id}/approve")
@app.post("/api/gitlab/pipelines/{id}/approve-false-positive")
def gitlab_approve_pipeline(id: str, request: Request):
    """Approve deployment: unblock and execute deploy-job in the SAME pipeline via GitLab Job Play API"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM gitlab_pipelines WHERE id = %s", (id,))
    pipe = cur.fetchone()
    if not pipe:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Pipeline not found")

    pipe_info = gitlab_sim.get_pipeline(id) or {}
    cmdb_ctx = pipe_info.get("cmdb_context") or {}
    validation = pipe_info.get("validation") or {}
    val_status = pipe.get("validation_status") or validation.get("status", "unknown")

    incident_id = pipe.get("incident_id") or pipe_info.get("incident_id")
    if not incident_id and (pipe.get("scan_findings") or []):
        findings = pipe["scan_findings"]
        cmdb_hint = pipe.get("project_id", "svc-legacy")
        incident_id = gitlab_sim._create_pipeline_incident(id, cmdb_hint, findings[0], cmdb_ctx)
        cur.execute("UPDATE gitlab_pipelines SET incident_id = %s WHERE id = %s", (incident_id, id))
        conn.commit()

    if incident_id:
        cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
        inc = cur.fetchone()
        if inc:
            if val_status == "active":
                dec_action = DecisionAction.RECORD_EXCEPTION
                dec_reason = f"Pipeline {id} allowed to proceed by operator (low impact / risk exception recorded). Deployment unblocked in SAME pipeline."
            else:
                dec_action = DecisionAction.SUPPRESS_FALSE_POSITIVE
                dec_reason = f"Pipeline {id} approved as false-positive by operator. Deployment unblocked in SAME pipeline."

            dec = IncidentDecision(
                actor="secops_auditor",
                action=dec_action,
                reason=dec_reason,
                expected_revision=inc["revision"]
            )
            dec_res = record_decision(incident_id, dec, request)
            op_id = dec_res.get("operation", {}).get("id")
            if op_id:
                try:
                    orchestrator.execute_operation(op_id, execution_identity="gitlab_runner_secops")
                except Exception as ex:
                    print(f"[WARN] Error executing approve operation {op_id}: {ex}")

            # Auto-close incident since action was performed at workflow level
            mark_incident_closed_at_workflow_level(
                incident_id=incident_id,
                actor="secops_auditor",
                disposition="risk_accepted_exception" if val_status == "active" else "suppressed_false_positive",
                recurrence_owner=inc.get("assigned_owner") or "owner_dave"
            )

    # 1. Fetch current live pipeline and find deploy job id
    stages = pipe_info.get("stages") or pipe.get("stages") or []
    deploy_job_id = None
    if len(stages) >= 3 and stages[2].get("job_id"):
        deploy_job_id = stages[2]["job_id"]

    # 2. Trigger native GitLab job play API on the SAME pipeline
    play_res = {}
    if deploy_job_id:
        play_res = gitlab_sim.play_manual_job(deploy_job_id)

    # 3. Update pipeline DB status to approved / running
    if len(stages) >= 3:
        stages[1]["status"] = "allowed_unrotated" if val_status == "active" else "approved_false_positive"
        stages[2]["status"] = "running"

    cur.execute("UPDATE gitlab_pipelines SET status = 'passed', stages = %s, updated_at = NOW() WHERE id = %s",
                (json.dumps(stages), id))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "status": "approved_and_played",
        "pipeline_id": id,
        "job_id": deploy_job_id,
        "play_response": play_res,
        "incident_id": incident_id,
        "validation_status": val_status,
        "message": f"Pipeline #{id} allowed to proceed! Deploy job #{deploy_job_id} unblocked and executing in the SAME pipeline."
    }

@app.post("/api/gitlab/pipelines/{id}/allow-unrotated")
@app.post("/api/gitlab/pipelines/{id}/allow-without-rotation")
def gitlab_allow_unrotated_pipeline(id: str, request: Request):
    """Allow valid credential to proceed without rotation (low impact / emergency risk acceptance) in the SAME pipeline"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM gitlab_pipelines WHERE id = %s", (id,))
    pipe = cur.fetchone()
    if not pipe:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Pipeline not found")

    pipe_info = gitlab_sim.get_pipeline(id) or {}
    cmdb_ctx = pipe_info.get("cmdb_context") or {}
    incident_id = pipe.get("incident_id") or pipe_info.get("incident_id")
    if not incident_id and (pipe.get("scan_findings") or []):
        findings = pipe["scan_findings"]
        cmdb_hint = pipe.get("project_id", "svc-legacy")
        incident_id = gitlab_sim._create_pipeline_incident(id, cmdb_hint, findings[0], cmdb_ctx)
        cur.execute("UPDATE gitlab_pipelines SET incident_id = %s WHERE id = %s", (incident_id, id))
        conn.commit()

    if incident_id:
        cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
        inc = cur.fetchone()
        if inc:
            dec = IncidentDecision(
                actor="secops_auditor",
                action=DecisionAction.RECORD_EXCEPTION,
                reason=f"Pipeline {id} allowed without immediate secret rotation by SecOps (low impact / risk exception recorded).",
                expected_revision=inc["revision"]
            )
            dec_res = record_decision(incident_id, dec, request)
            op_id = dec_res["operation"]["id"]
            orchestrator.execute_operation(op_id, execution_identity="gitlab_runner_secops")

            # Auto-close incident since action was performed at workflow level
            mark_incident_closed_at_workflow_level(
                incident_id=incident_id,
                actor="secops_auditor",
                disposition="risk_accepted_exception",
                recurrence_owner=inc.get("assigned_owner") or "owner_dave"
            )

    stages = pipe_info.get("stages") or pipe.get("stages") or []
    deploy_job_id = None
    if len(stages) >= 3 and stages[2].get("job_id"):
        deploy_job_id = stages[2]["job_id"]

    play_res = {}
    if deploy_job_id:
        play_res = gitlab_sim.play_manual_job(deploy_job_id)

    if len(stages) >= 3:
        stages[1]["status"] = "allowed_unrotated"
        stages[2]["status"] = "running"

    cur.execute("UPDATE gitlab_pipelines SET status = 'passed', stages = %s, updated_at = NOW() WHERE id = %s",
                (json.dumps(stages), id))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "status": "allowed_and_played",
        "pipeline_id": id,
        "job_id": deploy_job_id,
        "play_response": play_res,
        "incident_id": incident_id,
        "message": f"Pipeline #{id} allowed without rotation (risk accepted). Deploy job #{deploy_job_id} unblocked in SAME pipeline."
    }

@app.post("/api/gitlab/pipelines/{id}/rotate-and-deploy")
def gitlab_rotate_and_deploy_pipeline(id: str, request: Request):
    """Integrated rotation flow: Rotate credential in Vault, refresh service, and unblock deploy in the SAME pipeline"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM gitlab_pipelines WHERE id = %s", (id,))
    pipe = cur.fetchone()
    if not pipe:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Pipeline not found")

    pipe_info = gitlab_sim.get_pipeline(id) or {}
    cmdb_ctx = pipe_info.get("cmdb_context") or {}
    incident_id = pipe.get("incident_id") or pipe_info.get("incident_id")
    if not incident_id and (pipe.get("scan_findings") or []):
        findings = pipe["scan_findings"]
        cmdb_hint = pipe.get("project_id", "svc-legacy")
        incident_id = gitlab_sim._create_pipeline_incident(id, cmdb_hint, findings[0], cmdb_ctx)
        cur.execute("UPDATE gitlab_pipelines SET incident_id = %s WHERE id = %s", (incident_id, id))
        conn.commit()

    op_id = None
    exec_res = {}
    if incident_id:
        cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
        inc = cur.fetchone()
        if inc:
            dec = IncidentDecision(
                actor="secops_auditor",
                action=DecisionAction.ROTATE,
                reason=f"Pipeline {id} auto-remediated via integrated rotation: Vault static credential rotated, app reloaded, and deployment unblocked in SAME pipeline.",
                expected_revision=inc["revision"]
            )
            dec_res = record_decision(incident_id, dec, request)
            op_id = dec_res["operation"]["id"]
            exec_res = orchestrator.execute_operation(op_id, execution_identity="gitlab_runner_secops")

            # Auto-close incident since action was performed at workflow level
            mark_incident_closed_at_workflow_level(
                incident_id=incident_id,
                actor="secops_auditor",
                disposition="mitigated_and_rotated",
                recurrence_owner=inc.get("assigned_owner") or "owner_dave"
            )

    # Fetch live pipeline and find deploy job id
    stages = pipe_info.get("stages") or pipe.get("stages") or []
    deploy_job_id = None
    if len(stages) >= 3 and stages[2].get("job_id"):
        deploy_job_id = stages[2]["job_id"]

    play_res = {}
    if deploy_job_id:
        play_res = gitlab_sim.play_manual_job(deploy_job_id)

    if len(stages) >= 3:
        stages[1]["status"] = "mitigated_rotated"
        stages[2]["status"] = "running"

    cur.execute("UPDATE gitlab_pipelines SET status = 'passed', stages = %s, updated_at = NOW() WHERE id = %s",
                (json.dumps(stages), id))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "status": "rotated_and_played",
        "pipeline_id": id,
        "job_id": deploy_job_id,
        "play_response": play_res,
        "incident_id": incident_id,
        "operation_id": op_id,
        "containment": exec_res.get("containment"),
        "recovery": exec_res.get("recovery"),
        "interruption_ms": exec_res.get("interruption_ms", 0),
        "message": f"Credential successfully rotated in Vault! Deploy job #{deploy_job_id} unblocked and executing in SAME pipeline #{id}."
    }

@app.post("/api/gitlab/pipelines/{id}/remediate-git")
def gitlab_remediate_git_endpoint(id: str, req: Optional[Dict[str, Any]] = None):
    """Remediate Git repository by scrubbing the secret in GitLab SaaS / CE via Commits API"""
    req = req or {}
    action = req.get("action", "clean") # "clean" or "delete"

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM gitlab_pipelines WHERE id = %s", (id,))
    pipe = cur.fetchone()
    if not pipe:
        cur.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Pipeline not found")

    branch = pipe.get("ref", "main")
    git_res = gitlab_sim.remediate_git_file(branch=branch, file_path="config/database.yml", action=action, original_pipeline_id=id)

    pipe_info = gitlab_sim.get_pipeline(id)
    val_status = ((pipe_info or {}).get("validation") or {}).get("status", "unknown")

    stages = pipe["stages"]
    stages[1]["status"] = "file_purged" if action == "delete" else "sanitized_clean"
    stages[2]["status"] = "passed"
    new_status = "passed"

    cur.execute("UPDATE gitlab_pipelines SET status = %s, stages = %s, updated_at = NOW() WHERE id = %s",
                (new_status, json.dumps(stages), id))
    conn.commit()
    cur.close()
    conn.close()

    return {
        "status": "git_remediated_and_unblocked",
        "action": action,
        "pipeline_id": id,
        "new_pipeline_id": git_res.get("new_pipeline_id"),
        "new_pipeline_iid": git_res.get("new_pipeline_iid"),
        "new_pipeline_url": git_res.get("new_pipeline_url"),
        "new_commit_sha": git_res.get("new_commit_sha"),
        "validation_status": val_status,
        "git_remediation": git_res,
        "message": f"SecOps Bot pushed clean commit to GitLab. Fresh pipeline #{git_res.get('new_pipeline_id')} running in GitLab!"
    }

from fastapi.responses import HTMLResponse

# --- GITLAB ENTERPRISE WEB CONSOLE ---
@app.get("/gitlab", response_class=HTMLResponse)
@app.get("/gitlab/login", response_class=HTMLResponse)
def gitlab_web_ui(project: str = "svc-legacy"):
    pipelines = gitlab_sim.list_pipelines()
    pipe_rows = ""
    for p in pipelines:
        status_color = "#15803d" if p["status"] == "passed" else "#b91c1c"
        pipe_rows += f"""<tr>
            <td><code>{p['id']}</code></td>
            <td><strong>{p['project_id']}</strong></td>
            <td><code>{p['commit_sha'][:8]}</code></td>
            <td><span style="background:#f1f5f9; padding:2px 8px; border-radius:4px; font-weight:700; color:{status_color};">{p['status'].upper()}</span></td>
            <td>{' '.join([f"<span style='background:#f8fafc; border:1px solid #e2e8f0; padding:2px 6px; border-radius:4px;'>{s['name']}: {s['status']}</span>" for s in p['stages']])}</td>
        </tr>"""
    if not pipe_rows:
        pipe_rows = '<tr><td colspan="5" style="color:#64748b; text-align:center; padding:1.5rem;">No active pipeline executions. Push a commit from the portal to trigger.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GitLab Enterprise CI/CD Console</title>
  <style>
    body {{ background: #ffffff !important; color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 2rem; margin: 0; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #e2e8f0; padding-bottom: 1rem; margin-bottom: 1.5rem; }}
    .logo {{ display: flex; align-items: center; gap: 0.5rem; font-size: 1.3rem; font-weight: 700; color: #e24329; }}
    .user-pill {{ background: #f8fafc; border: 1px solid #cbd5e1; padding: 0.3rem 0.8rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; }}
    .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-bottom: 1.5rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; margin-top: 1rem; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 0.6rem 0.8rem; text-align: left; }}
    th {{ background: #f8fafc; color: #475569; font-weight: 600; }}
    code {{ background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }}
    .btn {{ background: #e24329; color: #fff; border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; font-size: 0.85rem; }}
    .btn:hover {{ background: #c0341d; }}
    .btn-outline {{ background: #fff; color: #0f172a; border: 1px solid #cbd5e1; }}
    .btn-outline:hover {{ background: #f1f5f9; }}
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🦊 GitLab Enterprise CI/CD Portal</div>
    <div style="display:flex; gap:0.75rem; align-items:center;">
      <span class="user-pill">Logged in as: <strong>secops_auditor</strong> (Role: Maintainer)</span>
      <a href="/" class="btn btn-outline">← Back to Enterprise Control Portal</a>
    </div>
  </div>

  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <div>
        <h2 style="margin:0; font-size:1.15rem;">Project: <code>platform/{project}</code></h2>
        <p style="margin:0.25rem 0 0 0; color:#64748b; font-size:0.85rem;">Continuous Integration, Gitleaks Security Gating & Automated Revocation Pipeline</p>
      </div>
      <div style="display:flex; gap:0.5rem;">
        <button class="btn" onclick="triggerPush(true)">🚨 Push Leaked Secret Commit</button>
        <button class="btn btn-outline" onclick="triggerPush(false)">✓ Push Clean Commit</button>
      </div>
    </div>

    <table>
      <thead>
        <tr><th>Pipeline ID</th><th>Project</th><th>Commit</th><th>Status</th><th>Stages (Build / Scan / Deploy)</th></tr>
      </thead>
      <tbody>
        {pipe_rows}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h3 style="margin-top:0;">Credentials & Access Metadata</h3>
    <ul>
      <li><strong>Web Login:</strong> Active session granted for <code>secops_auditor</code> / <code>gitlab_runner_secops</code></li>
      <li><strong>Repository URL:</strong> <code>http://localhost:8000/gitlab/platform/{project}</code></li>
      <li><strong>Webhook / API Push Endpoint:</strong> <code>POST http://localhost:8000/api/gitlab/push</code></li>
      <li><strong>Security Analyzer Engine:</strong> <code>Gitleaks v8.24.0 (Pre-Receive & CI Runner Diff Hook)</code></li>
    </ul>
  </div>

  <script>
    async function triggerPush(withLeak) {{
      const res = await fetch('/api/gitlab/push', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          project_id: '{project}',
          diff_content: withLeak ? 'diff --git a/app.py b/app.py\\n+DB_SECRET = "LAB_SEC_EXP_TEST123"\\n' : 'diff --git a/app.py b/app.py\\n+# clean update\\n'
        }})
      }});
      if (res.ok) window.location.reload();
    }}
  </script>
</body>
</html>"""

# --- ONBOARDED CREDENTIALS & SECRETS INVENTORY ---
@app.get("/api/credentials")
def list_credentials():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.*, s.name as service_name, s.owner_group, s.data_classification, s.network_exposure, s.auto_rotation_support,
               s.secret_manager_ref, s.gitlab_repo_url, cv.hmac_fingerprint
        FROM credentials c
        LEFT JOIN services s ON c.service_id = s.id
        LEFT JOIN credential_versions cv ON c.current_version_id = cv.version_id
        ORDER BY c.created_at DESC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

# --- DATABASE ACTIVE CONNECTIONS ENDPOINT ---
@app.get("/api/database/connections")
def get_database_connections():
    """Query live active PostgreSQL connections from pg_stat_activity"""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT pid, usename, client_addr::text, client_port, application_name, state,
               backend_start::text, query_start::text
        FROM pg_stat_activity
        WHERE usename IS NOT NULL
        ORDER BY backend_start DESC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {
        "database": "appdb",
        "host": "postgres:5432",
        "total_connections": len(rows),
        "connections": rows
    }

# --- SPIFFE PROXY ENDPOINTS (CORS-friendly for frontend) ---
@app.get("/api/spiffe/call")
def proxy_spiffe_call():
    """Proxy authorized mTLS call to spiffe-caller container"""
    try:
        r = requests.get("http://lab-spiffe-caller:8003/call", timeout=5)
        return Response(content=r.content, status_code=r.status_code, media_type="application/json")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with lab-spiffe-caller: {e}")

@app.get("/api/spiffe/call_forbidden")
def proxy_spiffe_call_forbidden():
    """Proxy forbidden operation call to spiffe-caller container"""
    try:
        r = requests.get("http://lab-spiffe-caller:8003/call_forbidden", timeout=5)
        return Response(content=r.content, status_code=r.status_code, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with lab-spiffe-caller: {e}")

@app.get("/api/spiffe/svid_info")
def proxy_spiffe_svid_info():
    """Proxy SVID info request to spiffe-caller container"""
    try:
        r = requests.get("http://lab-spiffe-caller:8003/svid_info", timeout=5)
        return Response(content=r.content, status_code=r.status_code, media_type="application/json")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with lab-spiffe-caller: {e}")

# --- APPLICATION HEALTH PROXY ENDPOINTS ---
@app.get("/api/apps/legacy/health")
def proxy_legacy_health():
    """Proxy health check to legacy app container"""
    try:
        r = requests.get("http://lab-legacy-app:8001/health", timeout=5)
        return Response(content=r.content, status_code=r.status_code, media_type="application/json")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with lab-legacy-app: {e}")

@app.get("/api/apps/integrated/health")
def proxy_integrated_health():
    """Proxy health check to integrated app container"""
    try:
        r = requests.get("http://lab-integrated-app:8002/health", timeout=5)
        return Response(content=r.content, status_code=r.status_code, media_type="application/json")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with lab-integrated-app: {e}")

@app.post("/api/apps/integrated/renew")
def proxy_integrated_renew():
    """Proxy lease renewal to integrated app container"""
    try:
        r = requests.post("http://lab-integrated-app:8002/renew", timeout=5)
        return Response(content=r.content, status_code=r.status_code, media_type="application/json")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to communicate with lab-integrated-app: {e}")

# /api/lab/access REMOVED — exposed bootstrap credentials without authentication (ASSESSMENT Finding #2)

# --- LOCAL PIPELINE STATUS ENDPOINT ---
@app.get("/api/gitlab/runner/status")
def get_gitlab_runner_status():
    """Query live runner status from GitLab CE API"""
    try:
        r = requests.get(
            f"{GITLAB_INTERNAL_URL}/api/v4/runners/all",
            headers={"PRIVATE-TOKEN": gl_token()},
            timeout=5
        )
        if r.ok:
            runners = r.json()
            runner = runners[0] if runners else None
            runner_detail = None
            if runner and runner.get("id"):
                r_detail = requests.get(
                    f"{GITLAB_INTERNAL_URL}/api/v4/runners/{runner['id']}",
                    headers={"PRIVATE-TOKEN": gl_token()},
                    timeout=5
                )
                if r_detail.ok:
                    runner_detail = r_detail.json()

            target_runner = runner_detail or runner
            return {
                "status": "online" if target_runner and target_runner.get("online") else "offline",
                "runner": target_runner,
                "all_runners": runners,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        else:
            return {"status": "error", "error": f"GitLab returned HTTP {r.status_code}", "detail": r.text}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# --- STATIC UI ---
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "Credential Lifecycle Laboratory Control Plane API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
