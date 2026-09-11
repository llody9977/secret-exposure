import os
import json
import time
import hashlib
import psycopg2
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from database import get_connection
from adapters.issuer import VaultSecretIssuerAdapter
from adapters.validator import ValidatorAdapter
from adapters.identity import SpireIdentityAdapter

POC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUPERVISOR_URL = os.getenv("SUPERVISOR_URL", "http://supervisor:8080")
SUPERVISOR_SECRET = os.getenv("SUPERVISOR_SECRET", "")
INTEGRATED_ADMIN_TOKEN = os.getenv("INTEGRATED_ADMIN_TOKEN", "")

def _resolve_source_revision() -> str:
    env_rev = os.getenv("SOURCE_REVISION")
    if env_rev and env_rev != "git_dynamic":
        return env_rev
    try:
        import subprocess
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=POC_DIR)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    # Try reading from repo root if mounted or host git metadata
    for git_head_path in [
        os.path.join(POC_DIR, ".git", "refs", "heads", "main"),
        os.path.join(os.path.dirname(POC_DIR), ".git", "refs", "heads", "main"),
        os.path.join(POC_DIR, "SOURCE_REVISION"),
    ]:
        if os.path.exists(git_head_path):
            try:
                with open(git_head_path, "r") as f:
                    c = f.read().strip()
                    if c:
                        return c
            except Exception:
                pass
    return "unknown"

SOURCE_REVISION = _resolve_source_revision()

issuer_adapter = VaultSecretIssuerAdapter()
validator_adapter = ValidatorAdapter()
identity_adapter = SpireIdentityAdapter()

def record_evidence(run_id: str, scenario_id: str, actor: str, action: str, status: str,
                    incident_id: Optional[str] = None, operation_id: Optional[str] = None,
                    service_id: Optional[str] = None, credential_version_id: Optional[str] = None,
                    redacted_result: Optional[Dict[str, Any]] = None):
    from evidence_context import current_run_id, current_scenario_id
    import uuid
    run_id = current_run_id.get() or (run_id if run_id != 'run_default' else 'interactive-' + uuid.uuid4().hex[:16])
    scenario_id = current_scenario_id.get() or scenario_id
    conn = get_connection()
    cur = conn.cursor()
    component_versions = {
        "vault": "1.18.5",
        "spire": "1.11.2",
        "postgresql": "17.11",
        "gitleaks": "8.24.0"
    }
    cur.execute("""
        INSERT INTO evidence_events
        (run_id, scenario_id, incident_id, operation_id, actor, action, status,
         service_id, credential_version_id, source_revision, component_versions, redacted_result)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        run_id, scenario_id, incident_id, operation_id, actor, action, status,
        service_id, credential_version_id, SOURCE_REVISION,
        json.dumps(component_versions), json.dumps(redacted_result or {})
    ))
    conn.commit()
    cur.close()
    conn.close()

def generate_idempotency_key(incident_id: str, cred_version_id: Optional[str], action: str, policy_rev: int) -> str:
    raw = f"{incident_id}:{cred_version_id or 'none'}:{action}:{policy_rev}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def get_vault_token():
    token = os.getenv("VAULT_ADMIN_TOKEN")
    if token:
        return token
    # Priority: Dedicated restricted Control Plane AppRole credential
    for approle_path in ["/poc/.bootstrap/control_approle.json", os.path.join(POC_DIR, ".bootstrap", "control_approle.json")]:
        if os.path.exists(approle_path):
            try:
                with open(approle_path, "r") as f:
                    data = json.load(f)
                import requests
                url = f"{issuer_adapter.vault_addr}/v1/auth/approle/login"
                resp = requests.post(url, json={"role_id": data["role_id"], "secret_id": data["secret_id"]}, verify=issuer_adapter.ca_cert, timeout=5)
                if resp.status_code == 200:
                    return resp.json()["auth"]["client_token"]
            except Exception:
                pass
    raise RuntimeError("No valid Vault credentials found for Control Plane. AppRole authentication required; root token fallback is disabled per ASSESSMENT Finding #2.")


def _json(value):
    return json.loads(value) if isinstance(value, str) else (value or {})


def _static_credentials(role, token):
    import requests
    response = requests.get(f'{issuer_adapter.vault_addr}/v1/database/static-creds/{role}',
                            headers={'X-Vault-Token': token}, verify=issuer_adapter.ca_cert, timeout=10)
    response.raise_for_status()
    data = response.json()['data']
    if not data.get('password') or not data.get('username'):
        raise ValueError('Issuer returned incomplete static credentials')
    return data


def execute_operation(operation_id: str, execution_identity: str, simulate_interruption: bool = False,
                      simulate_restart_failure: bool = False, run_id: str = 'run_default',
                      pause_after_issuer_effect: bool = False) -> Dict[str, Any]:
    """Persist intent before effects and keep a credential-scoped session lock across commits.

    A lost worker releases the advisory lock automatically. The next request
    resumes the recorded phase; no side effect is repeated based on status alone.
    """
    import requests
    import candidate_store
    from hmac_service import compute_fingerprint, verify_fingerprint
    conn = get_connection()
    cur = conn.cursor()
    lock_key = None
    op = incident = None
    params = {}
    scenario = 'A06'

    def checkpoint(phase, **updates):
        params.update(updates)
        params['phase'] = phase
        cur.execute("UPDATE operations SET params=%s, updated_at=NOW() WHERE id=%s", (json.dumps(params), operation_id))
        conn.commit()

    def finish(containment, recovery, details, status='completed'):
        cur.execute("""UPDATE incidents SET containment_status=%s, recovery_status=%s,
            contained_at=CASE WHEN %s='verified' THEN COALESCE(contained_at,NOW()) ELSE contained_at END,
            recovered_at=CASE WHEN %s='healthy' THEN COALESCE(recovered_at,NOW()) ELSE recovered_at END,
            revision=revision+1, updated_at=NOW() WHERE id=%s""",
                    (containment, recovery, containment, recovery, op['incident_id']))
        cur.execute("UPDATE operations SET status=%s, interrupted=FALSE, updated_at=NOW() WHERE id=%s", (status, operation_id))
        conn.commit()
        result = dict(status=status, containment=containment, recovery=recovery, operation_id=operation_id, **details)
        record_evidence(run_id, scenario, execution_identity, 'operation_verification', containment,
                        incident_id=op['incident_id'], operation_id=operation_id,
                        service_id=incident.get('service_id'), credential_version_id=op.get('credential_version_id'), redacted_result=result)
        return result

    try:
        cur.execute('SELECT * FROM operations WHERE id=%s', (operation_id,))
        op = cur.fetchone()
        if not op:
            raise ValueError('Operation not found')
        # Scope by durable credential, not incident or operation. Two incidents
        # affecting one credential cannot rotate concurrently.
        cur.execute('SELECT credential_id FROM credential_versions WHERE version_id=%s', (op.get('credential_version_id'),))
        version_row = cur.fetchone()
        lock_key = 'credential:' + (version_row['credential_id'] if version_row else op['target'])
        cur.execute('SELECT pg_try_advisory_lock(hashtextextended(%s,0)) AS acquired', (lock_key,))
        if not cur.fetchone()['acquired']:
            lock_key = None
            return {'status': 'busy', 'operation_id': operation_id}
        cur.execute('SELECT * FROM operations WHERE id=%s FOR UPDATE', (operation_id,))
        op = cur.fetchone()
        if op['status'] == 'completed':
            return {'status': 'already_completed', 'operation_id': operation_id}
        params = _json(op.get('params'))
        cur.execute('SELECT * FROM incidents WHERE id=%s', (op['incident_id'],))
        incident = cur.fetchone()
        if not incident or incident['triage_status'] != 'decided' or incident['decision_action'] != op['action']:
            raise ValueError('Operation has no matching approved incident decision')
        if op['attempts'] >= 3:
            raise ValueError('Retry limit reached; operator review and a new approved recovery decision required')
        cur.execute("UPDATE operations SET status='running', execution_identity=%s, attempts=attempts+1 WHERE id=%s AND status IN ('pending','running','failed')", (execution_identity, operation_id))
        if cur.rowcount != 1:
            raise ValueError('Invalid operation state transition')
        conn.commit()
        cur.execute('SELECT * FROM services WHERE id=%s', (incident.get('service_id'),))
        service = cur.fetchone()
        action = op['action']
        scenario = {'rotate':'A06','revoke':'A10','isolate':'A14','record_exception':'A08','suppress_false_positive':'A18'}.get(action,'A06')

        if action == 'record_exception':
            exception = (service or {}).get('exception_status') or {}
            required = ('owner', 'residual_authority', 'compensating_control', 'exit_condition')
            if not all(exception.get(k) for k in required):
                raise ValueError('An exception requires owner, residual authority, compensating control and exit condition')
            # Risk acceptance is a decision, not evidence that exposed access ended.
            return finish('partial', 'degraded', {'exception_recorded': True, 'requires_recurrence_work': True})
        if action == 'suppress_false_positive':
            if incident.get('validation_status') not in ('invalid',) or incident.get('correlation_status') == 'matched':
                raise ValueError('Suppression requires independent noncredential evidence; unavailable validation or historical exposure cannot be suppressed')
            # A typed reason alone cannot supply independent evidence.
            raise ValueError('No independent false-positive evidence attached; case remains open')
        if action == 'isolate':
            if not service or service['id'] != 'svc-spiffe' or service['application_category'] != 'spiffe':
                raise ValueError('Isolation requires the approved local SPIFFE service')
            cur.execute("SELECT * FROM credentials WHERE service_id=%s AND credential_type='x509_svid'", (service['id'],))
            identity_credential = cur.fetchone()
            if not identity_credential or identity_credential['issuer_ref'] != 'spiffe://lab.local/workload/caller':
                raise ValueError('Approved caller identity registration is required')
            # Target denial is tested independently; SPIRE issuance evidence must
            # also be supplied by the identity adapter before full containment.
            result = identity_adapter.contain_workload()
            return finish('verified' if result.get('verified') else 'partial', 'degraded', result)
        if action not in ('rotate', 'revoke') or not service:
            raise ValueError('Unsupported action or unresolved authoritative service')
        cur.execute('SELECT * FROM credential_versions WHERE version_id=%s', (op.get('credential_version_id'),))
        version = cur.fetchone()
        if not version:
            raise ValueError('Exact exposed credential version is required')
        cur.execute('SELECT * FROM credentials WHERE credential_id=%s', (version['credential_id'],))
        credential = cur.fetchone()
        if not credential or credential['service_id'] != service['id']:
            raise ValueError('Credential target relationship mismatch')
        token = get_vault_token()
        target = service['target_resource']
        candidate_ref = params.get('candidate_ref') or incident.get('candidate_ref')
        if not candidate_ref:
            raise ValueError('Actual exposed candidate reference is required; no dummy probe is permitted')
        old_password = candidate_store.get(candidate_ref, execution_identity, run_id, operation_id)
        if not verify_fingerprint(old_password, version['hmac_fingerprint'], version['canonical_version']):
            raise ValueError('Candidate does not match the approved exposed version')

        if action == 'rotate':
            if service['id'] != 'svc-legacy' or target != 'postgres:5432/appdb' or credential['issuer_ref'] != 'database/static-roles/legacy-app-role' or credential['credential_type'] != 'database_static':
                raise ValueError('Rotation requires a registered static database credential')
            role = credential['issuer_ref'].split('/')[-1]
            current = _static_credentials(role, token)
            username = current['username']
            phase = params.get('phase')
            effect_performed_here = False
            if not phase:
                if credential.get('current_version_id') != version['version_id']:
                    raise ValueError('Historical finding cannot rotate the current version')
                if not verify_fingerprint(current['password'], version['hmac_fingerprint'], version['canonical_version']):
                    raise ValueError('Issuer credential differs from approved version; fresh correlation and approval required')
                if validator_adapter.validate_credential(target, username, old_password)['status'] != 'active':
                    raise ValueError('Actual old candidate did not authenticate before rotation')
                if not current.get('last_vault_rotation'):
                    raise ValueError('Issuer rotation baseline unavailable')
                checkpoint('rotation_intent', pre_rotation_ts=current['last_vault_rotation'],
                           pre_fingerprint=version['hmac_fingerprint'], pre_authenticated=True,
                           candidate_ref=candidate_ref, username=username)
            if params['phase'] in ('rotation_intent', 'issuer_effect_barrier'):
                if compute_fingerprint(current['password'], version['canonical_version']) == params['pre_fingerprint']:
                    # Baseline still current: persisted intent did not take effect.
                    issuer_adapter.rotate_static_role(role, token)
                    effect_performed_here = True
                    if pause_after_issuer_effect:
                        # A21 uses this durable barrier to prove a crash after
                        # the issuer mutation but before local completion or the
                        # simulated interruption response is recorded.
                        checkpoint('issuer_effect_barrier', issuer_effect_observed=True)
                        time.sleep(60)
                    if simulate_interruption:
                        cur.execute("UPDATE operations SET interrupted=TRUE WHERE id=%s", (operation_id,))
                        conn.commit()
                        record_evidence(run_id, 'A21', execution_identity, 'operation_interrupted', 'interrupted', operation_id=operation_id,
                                        incident_id=op['incident_id'], redacted_result={'side_effect_occurred': True, 'phase': 'rotation_intent'})
                        return {'status':'interrupted', 'operation_id':operation_id}
                    current = _static_credentials(role, token)
                # A different observed version must be later than this operation's
                # persisted baseline and reject the actual preauthenticated secret.
                changed = current.get('last_vault_rotation') and current['last_vault_rotation'] != params['pre_rotation_ts']
                old_rejected = validator_adapter.validate_credential(target, username, old_password)['status'] == 'invalid'
                if not changed or not old_rejected or current['password'] == old_password:
                    raise ValueError('Issuer transition could not be reconciled against this operation baseline')
                if not effect_performed_here and not op.get('interrupted'):
                    # The only persisted phase is the pre-effect intent.  Mark an
                    # interruption only after independent issuer and credential
                    # checks show that the prior process completed its side effect.
                    cur.execute("UPDATE operations SET interrupted=TRUE WHERE id=%s", (operation_id,))
                    conn.commit()
                    op['interrupted'] = True
                    record_evidence(run_id, 'A21', execution_identity, 'operation_reconciled', 'reconciled',
                                    operation_id=operation_id, incident_id=op['incident_id'],
                                    redacted_result={'phase': 'rotation_intent', 'issuer_state_changed': True,
                                                     'old_credential_rejected': True})
                checkpoint('rotated', post_fingerprint=compute_fingerprint(current['password'], version['canonical_version']),
                           post_rotation_ts=current['last_vault_rotation'], old_credential_rejected=True)
            if compute_fingerprint(current['password'], version['canonical_version']) != params['post_fingerprint']:
                raise ValueError('Issuer changed again after this operation; recovery requires review')
            # Render atomically with restrictive mode, then independently observe
            # process generation and harmless application transaction after restart.
            path = os.path.join(POC_DIR, '.bootstrap', 'legacy-creds', 'db-creds.json')
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            temp = path + '.tmp'
            fd = os.open(temp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(dict(current, generation_id=operation_id), f)
                f.flush(); os.fsync(f.fileno())
            os.replace(temp, path)
            response = requests.post(f'{SUPERVISOR_URL}/restart/legacy-app',
                                     params={'fail':str(simulate_restart_failure).lower()},
                                     headers={'Authorization':f'Bearer {SUPERVISOR_SECRET}'}, timeout=45)
            response.raise_for_status()
            restart = response.json()
            old_rejected = validator_adapter.validate_credential(target, username, old_password)['status'] == 'invalid'
            replacement_valid = validator_adapter.validate_credential(target, username, current['password'])['status'] == 'active'
            business = requests.get('http://legacy-app:8001/data', timeout=5)
            healthy = restart.get('healthy') and restart.get('process_restarted') and restart.get('generation_id') == operation_id and replacement_valid and business.status_code == 200
            # Retain lineage exactly once and update current version only after the issuer changed.
            new_version = 'rot-' + operation_id
            cur.execute("INSERT INTO credential_versions (id,credential_id,version_id,hmac_fingerprint,canonical_version,status,metadata) VALUES (%s,%s,%s,%s,%s,'active',%s) ON CONFLICT (version_id) DO NOTHING",
                        ('cv-'+operation_id, version['credential_id'], new_version, params['post_fingerprint'], version['canonical_version'], json.dumps({'username':username, 'operation_id':operation_id})))
            cur.execute("UPDATE credential_versions SET status='revoked', revoked_at=COALESCE(revoked_at,NOW()) WHERE version_id=%s", (version['version_id'],))
            cur.execute('UPDATE credentials SET current_version_id=%s WHERE credential_id=%s', (new_version, version['credential_id']))
            checkpoint('recovery_verified' if healthy else 'rotated')
            return finish('verified' if old_rejected else 'partial', 'healthy' if healthy else 'failed',
                          {'pre_authenticated':True, 'old_credential_rejected':old_rejected,
                           'replacement_authenticated':replacement_valid, 'process_restarted':restart.get('process_restarted',False),
                           'interruption_ms':restart.get('interruption_ms'),
                           'external_reconciled':not effect_performed_here},
                          'completed' if healthy and old_rejected else 'failed')

        if service['id'] != 'svc-integrated' or target != 'postgres:5432/appdb' or credential['credential_type'] != 'database_dynamic' or credential['issuer_ref'] != 'database/roles/integrated-role':
            raise ValueError('Revocation requires the approved integrated database credential')
        metadata = _json(version.get('metadata'))
        lease_id, username = metadata.get('lease_id'), metadata.get('username')
        if not lease_id or not lease_id.startswith('database/creds/integrated-role/') or not username or metadata.get('target_resource') != target:
            raise ValueError('Exact exposed lease metadata is missing or mismatched')
        if not params.get('phase'):
            if validator_adapter.validate_credential(target, username, old_password)['status'] != 'active':
                raise ValueError('Exposed dynamic candidate did not authenticate before containment')
            checkpoint('revoke_intent', lease_id=lease_id, username=username, candidate_ref=candidate_ref, pre_authenticated=True,
                       target_sessions=issuer_adapter.capture_target_sessions(username))
        if not issuer_adapter.block_workload_issuance('integrated-app-policy', token):
            raise ValueError('Issuer enforcement failed; lease was not revoked')
        # The issuer policy readback and a real request with compromised workload
        # identity must both show denial, not merely the application's local flag.
        blocked = requests.post('http://integrated-app:8002/block_issuance', params={'blocked':'true'},
                                headers={'Authorization':f'Bearer {INTEGRATED_ADMIN_TOKEN}'}, timeout=5)
        blocked.raise_for_status()
        deny_probe = requests.post('http://integrated-app:8002/issuance/probe',
                                   headers={'Authorization':f'Bearer {INTEGRATED_ADMIN_TOKEN}'}, timeout=10)
        deny_probe.raise_for_status()
        issuance_denied = deny_probe.json().get('issuer_denied') is True
        if not issuance_denied:
            raise ValueError('Compromised identity still obtains credentials at issuer')
        if not issuer_adapter.lease_absent(lease_id, token):
            if not issuer_adapter.revoke_lease(lease_id, token):
                raise ValueError('Vault lease revocation failed')
        checkpoint('revoked', issuance_denied=True)
        # Observe the actual preexisting connection independently from fresh login.
        held = requests.get('http://integrated-app:8002/sessions/held/query', timeout=5)
        survived = held.status_code == 200 and held.json().get('status') == 'active'
        held_proven = held.status_code == 200 and held.json().get('status') in ('active','terminated') and held.json().get('username') == username
        terminated = issuer_adapter.terminate_captured_sessions(params.get('target_sessions', []))
        active_sessions = issuer_adapter.count_captured_sessions(params.get('target_sessions', []))
        after = requests.get('http://integrated-app:8002/sessions/held/query', timeout=5)
        held_terminated = (after.status_code == 200 and after.json().get('username') == username
                           and (after.json().get('status') == 'terminated' or
                                (after.json().get('connection_closed') is True and active_sessions == 0 and terminated > 0)))
        login_denied = validator_adapter.validate_credential(target, username, old_password)['status'] == 'invalid'
        verified = issuer_adapter.lease_absent(lease_id, token) and login_denied and active_sessions == 0 and held_proven and held_terminated
        cur.execute("UPDATE credential_versions SET status='revoked', revoked_at=COALESCE(revoked_at,NOW()) WHERE version_id=%s", (version['version_id'],))
        # Compromised workload intentionally remains blocked until a separately
        # authorized recovery, so recovery cannot be labeled healthy here.
        return finish('verified' if verified else 'partial', 'degraded',
                      {'lease_revoked':True, 'login_denied':login_denied, 'active_sessions':active_sessions,
                       'sessions_terminated':terminated, 'held_session_survived_revocation':survived,
                       'held_session_terminated':held_terminated, 'session_probe_success':held_proven,
                       'issuance_denied':issuance_denied}, 'completed' if verified else 'failed')
    except Exception as exc:
        conn.rollback()
        if op and incident:
            # Fail visibly, retain phase for bounded authoritative resume, redact diagnostics.
            known_contained = params.get('old_credential_rejected') is True
            return finish('verified' if known_contained else 'failed', 'failed',
                          {'error':str(exc) if isinstance(exc, ValueError) else type(exc).__name__,
                           'resume_phase':params.get('phase'), 'retry_limit':3}, 'failed')
        raise
    finally:
        if lock_key:
            try:
                cur.execute('SELECT pg_advisory_unlock(hashtextextended(%s,0))', (lock_key,))
                conn.commit()
            except Exception:
                conn.rollback()
        cur.close()
        conn.close()
