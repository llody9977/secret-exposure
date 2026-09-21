import os
import sys
import time
import json
import requests
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
import threading
import hmac
import uuid
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

VAULT_ADDR = os.getenv("VAULT_ADDR", "https://vault:8200")
VAULT_CACERT = os.getenv("VAULT_CACERT", "/certs/ca.pem")
CONTROL_API_URL = os.getenv("CONTROL_API_URL", "http://control-api:8000")
APP_DB_HOST = os.getenv("APP_DB_HOST", "postgres")
APP_DB_PORT = int(os.getenv("APP_DB_PORT", "5432"))
APP_DB_NAME = os.getenv("APP_DB_NAME", "appdb")
ROLE_NAME = os.getenv("DYNAMIC_ROLE_NAME", "integrated-role")

app = FastAPI(title="Integrated Application")

from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def index_ui():
    valid = time.time() < state.lease_expires_at
    rem = max(0, round(state.lease_expires_at - time.time(), 1))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Integrated Application - Vault Leased</title>
  <style>
    body {{ background: #ffffff !important; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 2rem; margin: 0; }}
    .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; max-width: 800px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1.5rem; }}
    h1 {{ color: #0f172a; margin-top: 0; font-size: 1.5rem; border-bottom: 2px solid #f1f5f9; padding-bottom: 0.5rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }}
    .badge-success {{ background: #dcfce7; color: #15803d; }}
    .badge-danger {{ background: #fee2e2; color: #b91c1c; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.875rem; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #f8fafc; font-weight: 600; }}
    code {{ background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.85rem; color: #0f172a; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>🚀 Modern Vault-Integrated App (Port 8002)</h1>
    <p>Operational mode: <strong>Dynamic Ephemeral Leases via HashiCorp Vault</strong></p>
    <table>
      <tr><th>Current Lease ID</th><td><code>{'Registered active lease' if state.current_lease_id else 'No active lease'}</code></td></tr>
      <tr><th>Lease Validity</th><td>{f'<span class="badge badge-success">Valid ({rem}s remaining)</span>' if valid else '<span class="badge badge-danger">Expired / Renewing</span>'}</td></tr>
      <tr><th>Database User</th><td><code>{state.current_username or 'N/A'}</code></td></tr>
      <tr><th>Renewal Count</th><td>{state.renewal_count}</td></tr>
      <tr><th>Issuance Blocked</th><td>{'Yes' if state.issuance_blocked else 'No'}</td></tr>
    </table>
  </div>
  <div class="card">
    <h2>REST API Endpoints</h2>
    <ul>
      <li><a href="/health"><code>/health</code></a> - Dynamic lease health check</li>
      <li><a href="/workload"><code>/workload</code></a> - Execute live transactional query</li>
      <li><a href="/status"><code>/status</code></a> - Detailed lease state</li>
      <li><code>POST /renew</code> - Renew active Vault dynamic lease</li>
      <li><code>POST /replace</code> - Force replacement of dynamic credentials</li>
    </ul>
  </div>
</body>
</html>"""

class AppState:
    def __init__(self):
        self.vault_token = os.getenv("VAULT_TOKEN", "")
        self.approle_id = os.getenv("APPROLE_ROLE_ID", "")
        self.approle_secret = os.getenv("APPROLE_SECRET_ID", "")
        approle_file = os.getenv("APPROLE_FILE", "/poc/.bootstrap/integrated_approle.json")
        if not self.approle_id and os.path.exists(approle_file):
            try:
                with open(approle_file, "r") as f:
                    d = json.load(f)
                    self.approle_id = d.get("role_id")
                    self.approle_secret = d.get("secret_id")
            except Exception as e:
                print(f"Failed to read approle file: {e}", flush=True)
        self.current_lease_id = None
        self.current_username = None
        self.current_password = None
        self.current_fingerprint = None
        self.current_version_id = None
        self.lease_expires_at = 0
        self.renewal_count = 0
        self.issuance_blocked = False
        self.held_connection = None
        self.held_username = None
        self.held_terminated = False
        self.pool = None
        self.pool_generation = 0

state = AppState()

def get_ca():
    if not VAULT_CACERT or not os.path.exists(VAULT_CACERT):
        raise FileNotFoundError(f"Missing CA certificate at {VAULT_CACERT}. Failing closed to prevent insecure communication.")
    return VAULT_CACERT

def authenticate_vault():
    if state.vault_token:
        return state.vault_token
    approle_file = os.getenv("APPROLE_FILE", "/poc/.bootstrap/integrated_approle.json")
    if not state.approle_id and os.path.exists(approle_file):
        try:
            with open(approle_file, "r") as f:
                data = json.load(f)
                state.approle_id = data.get("role_id")
                state.approle_secret = data.get("secret_id")
        except Exception:
            pass
    if state.approle_id and state.approle_secret:
        url = f"{VAULT_ADDR}/v1/auth/approle/login"
        resp = requests.post(url, json={"role_id": state.approle_id, "secret_id": state.approle_secret}, verify=get_ca(), timeout=5)
        resp.raise_for_status()
        state.vault_token = resp.json()["auth"]["client_token"]
        return state.vault_token
    raise RuntimeError("No Vault credentials configured")

def obtain_dynamic_credentials():
    if state.issuance_blocked:
        raise RuntimeError("Issuance blocked for this workload due to active containment policy")

    token = authenticate_vault()
    url = f"{VAULT_ADDR}/v1/database/creds/{ROLE_NAME}"
    resp = requests.get(url, headers={"X-Vault-Token": token}, verify=get_ca(), timeout=5)
    resp.raise_for_status()
    data = resp.json()

    lease_id = data["lease_id"]
    lease_duration = data["lease_duration"]
    username = data["data"]["username"]
    password = data["data"]["password"]

    # Do not advertise readiness until the immutable issued instance is registered.
    reg_resp = requests.post(f"{CONTROL_API_URL}/api/internal/register-fingerprint", json={
        "service_id": "svc-integrated", "version_id": "dyn-" + uuid.uuid5(uuid.NAMESPACE_URL, lease_id).hex, "raw_secret": password,
        "canonical_version": "v1", "metadata": {"lease_id":lease_id, "username":username,
        "target_resource":f"{APP_DB_HOST}:{APP_DB_PORT}/{APP_DB_NAME}"}},
        headers={"Authorization":f"Bearer {os.environ['INTERNAL_SERVICE_TOKEN']}"}, timeout=5)
    if not reg_resp.ok:
        # An unregistered lease is not a usable credential. Revoke on failure.
        requests.put(f"{VAULT_ADDR}/v1/sys/leases/revoke", headers={"X-Vault-Token":token},
                     json={"lease_id":lease_id}, verify=get_ca(), timeout=5)
        reg_resp.raise_for_status()
    state.current_lease_id = lease_id
    state.current_username = username
    state.current_password = password
    state.current_fingerprint = reg_resp.json()["fingerprint"]
    state.current_version_id = "dyn-" + uuid.uuid5(uuid.NAMESPACE_URL, lease_id).hex
    state.lease_expires_at = time.time() + lease_duration
    state.renewal_count = 0
    replacement_pool = ThreadedConnectionPool(1, 4, host=APP_DB_HOST,port=APP_DB_PORT,dbname=APP_DB_NAME,
                                              user=username,password=password,connect_timeout=3)
    old_pool = state.pool
    state.pool = replacement_pool
    state.pool_generation += 1
    if old_pool:
        old_pool.closeall()


def get_db_conn():
    if not state.current_username or not state.current_password:
        obtain_dynamic_credentials()
    try:
        return psycopg2.connect(
            host=APP_DB_HOST,
            port=APP_DB_PORT,
            dbname=APP_DB_NAME,
            user=state.current_username,
            password=state.current_password,
            connect_timeout=3
        )
    except psycopg2.OperationalError:
        if not state.issuance_blocked:
            obtain_dynamic_credentials()
            return psycopg2.connect(
                host=APP_DB_HOST,
                port=APP_DB_PORT,
                dbname=APP_DB_NAME,
                user=state.current_username,
                password=state.current_password,
                connect_timeout=3
            )
        raise

@app.on_event("startup")
def startup():
    try:
        obtain_dynamic_credentials()
    except Exception:
        pass  # readiness remains failed until registration and issuance succeed
    def maintain_lease():
        while True:
            time.sleep(2)
            if state.issuance_blocked:
                continue
            try:
                if not state.current_lease_id:
                    obtain_dynamic_credentials()
                elif state.lease_expires_at - time.time() < 30:
                    try:
                        renew()
                    except Exception:
                        obtain_dynamic_credentials()
            except Exception:
                # Never mark the failed refresh healthy. Health probes exercise DB.
                pass
    threading.Thread(target=maintain_lease,daemon=True).start()

@app.get("/health")
def health():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        return {
            "status": "healthy",
            "lease_valid": time.time() < state.lease_expires_at,
            "remaining_seconds": max(0, round(state.lease_expires_at - time.time(), 1)),
            "renewal_count": state.renewal_count,
            "issuance_blocked": state.issuance_blocked
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database check failed: {e}")

@app.get("/workload")
def workload():
    if state.pool is None:
        obtain_dynamic_credentials()
    pool = state.pool
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, metric_name, metric_val FROM integrated_records ORDER BY id LIMIT 5")
            rows = cur.fetchall()
        conn.rollback()
        return [{"id":r[0],"metric_name":r[1],"metric_val":r[2]} for r in rows]
    finally:
        pool.putconn(conn)

@app.get("/status")
def status():
    return {
        "service": "integrated-app",
        "has_credentials": state.current_username is not None,
        "username": state.current_username,
        "lease_id": state.current_lease_id,
        "fingerprint": state.current_fingerprint,
        "version_id":state.current_version_id,
        "pool_generation":state.pool_generation,
        "target_resource": f"{APP_DB_HOST}:{APP_DB_PORT}/{APP_DB_NAME}",
        "remaining_seconds": max(0, round(state.lease_expires_at - time.time(), 1)),
        "renewal_count": state.renewal_count,
        "issuance_blocked": state.issuance_blocked,
        "held_session_active": state.held_connection is not None and not state.held_connection.closed
    }

@app.post("/renew")
def renew():
    if not state.current_lease_id:
        raise HTTPException(status_code=400, detail="No active lease to renew")
    token = authenticate_vault()
    url = f"{VAULT_ADDR}/v1/sys/leases/renew"
    resp = requests.put(url, headers={"X-Vault-Token": token}, json={"lease_id": state.current_lease_id, "increment": 3600}, verify=get_ca(), timeout=5)
    resp.raise_for_status()
    data = resp.json()
    duration = data.get("lease_duration", 3600)
    state.lease_expires_at = time.time() + duration
    state.renewal_count += 1
    return {"status": "renewed", "lease_id": state.current_lease_id, "duration": duration, "count": state.renewal_count}

@app.post("/replace")
def replace():
    try:
        obtain_dynamic_credentials()
        return {"status": "replaced", "lease_id": state.current_lease_id}
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))

@app.post("/block_issuance")
def block_issuance(request: Request, blocked: bool = True):
    require_admin(request)
    state.issuance_blocked = blocked
    if not blocked:
        # A containment policy may have changed at the issuer while this process
        # held a token.  Recovery must obtain a new AppRole token rather than
        # silently reusing the token that was active during the denial state.
        state.vault_token = None
    return {"status": "updated", "issuance_blocked": state.issuance_blocked}

@app.post("/sessions/hold")
def hold_session():
    # Keep a live database connection open for Scenario A10
    if state.held_connection and not state.held_connection.closed:
        state.held_connection.close()
    state.held_connection = get_db_conn()
    state.held_username = state.current_username
    state.held_terminated = False
    cur = state.held_connection.cursor()
    cur.execute("SELECT pg_backend_pid()")
    pid = cur.fetchone()[0]
    return {"status": "holding", "backend_pid": pid}

@app.get("/sessions/held/query")
def query_held_session():
    if state.held_terminated:
        return {"status":"terminated", "username":state.held_username}
    if not state.held_connection:
        return {"status":"inconclusive", "reason":"No preexisting session was established"}
    try:
        cur = state.held_connection.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return {"status":"active", "username":state.held_username}
    except psycopg2.Error as exc:
        # PostgreSQL admin termination or a closed connection after that error
        # is evidence; generic query/network errors do not prove termination.
        if exc.pgcode in ("57P01", "57P02") or "terminating connection due to administrator command" in str(exc):
            state.held_terminated = True
            state.held_connection.close()
            return {"status":"terminated", "username":state.held_username}
        return {"status":"inconclusive", "username":state.held_username, "reason":type(exc).__name__,
                "connection_closed":bool(state.held_connection.closed)}


def require_admin(request):
    expected = os.environ.get('INTEGRATED_ADMIN_TOKEN', '')
    if not expected or not hmac.compare_digest(request.headers.get('Authorization',''), 'Bearer '+expected):
        raise HTTPException(status_code=401, detail='Authenticated workload administration required')

@app.middleware('http')
async def administrative_auth(request, call_next):
    if request.method != 'GET' or request.url.path == '/status':
        try:
            require_admin(request)
        except HTTPException as exc:
            from fastapi.responses import JSONResponse
            return JSONResponse({'detail':exc.detail}, status_code=exc.status_code)
    return await call_next(request)

@app.post('/exposure')
def exposure(request: Request):
    require_admin(request)
    if not state.current_password:
        raise HTTPException(status_code=409, detail='No issued candidate available')
    response = requests.post(f'{CONTROL_API_URL}/api/internal/store-candidate',
                             headers={'Authorization':f"Bearer {os.environ['INTERNAL_SERVICE_TOKEN']}"},
                             json={'candidate_val':state.current_password}, timeout=5)
    response.raise_for_status()
    return {'candidate_ref':response.json()['candidate_ref'], 'fingerprint':state.current_fingerprint,
            'version_id':state.current_version_id}

@app.post('/issuance/probe')
def issuance_probe(request: Request):
    require_admin(request)
    response = requests.get(f'{VAULT_ADDR}/v1/database/creds/{ROLE_NAME}',
                            headers={'X-Vault-Token':authenticate_vault()}, verify=get_ca(), timeout=5)
    if response.status_code == 403:
        return {'issuer_denied': True}
    if response.status_code == 200:
        lease = response.json().get('lease_id')
        if lease:
            requests.put(f'{VAULT_ADDR}/v1/sys/leases/revoke', headers={'X-Vault-Token':state.vault_token},
                         json={'lease_id':lease}, verify=get_ca(), timeout=5)
        return {'issuer_denied':False}
    raise HTTPException(status_code=503, detail='Issuer probe inconclusive')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
