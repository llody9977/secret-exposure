import os
import sys
import json
import time
import hashlib
import uuid
import hmac
from datetime import datetime, timezone
import psycopg2
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

CONFIG_FILE = os.getenv("CONFIG_FILE", "/secrets/db-creds.json")
APP_DB_HOST = os.getenv("APP_DB_HOST", "postgres")
APP_DB_PORT = int(os.getenv("APP_DB_PORT", "5432"))
APP_DB_NAME = os.getenv("APP_DB_NAME", "appdb")

print(f"[{datetime.now(timezone.utc).isoformat()}] Legacy app starting. Loading credentials from {CONFIG_FILE}...", flush=True)

if not os.path.exists(CONFIG_FILE):
    print(f"FATAL: Configuration file {CONFIG_FILE} does not exist!", file=sys.stderr, flush=True)
    sys.exit(1)

try:
    with open(CONFIG_FILE, "r") as f:
        creds = json.load(f)
        DB_USER = creds["username"]
        DB_PASSWORD = creds["password"]
except Exception as e:
    print(f"FATAL: Failed to read {CONFIG_FILE}: {e}", file=sys.stderr, flush=True)
    sys.exit(1)

# Test startup connection
try:
    startup_conn = psycopg2.connect(
        host=APP_DB_HOST,
        port=APP_DB_PORT,
        dbname=APP_DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        connect_timeout=5
    )
    cur = startup_conn.cursor()
    cur.execute("SELECT 1")
    cur.close()
    startup_conn.close()
    STARTUP_SUCCESS = True
    STARTUP_ERROR = None
    print(f"[{datetime.now(timezone.utc).isoformat()}] Connected to {APP_DB_NAME} as {DB_USER}.", flush=True)
except Exception as e:
    STARTUP_SUCCESS = False
    STARTUP_ERROR = str(e)
    print(f"[{datetime.now(timezone.utc).isoformat()}] Connection failed at startup: {e}", file=sys.stderr, flush=True)

START_TIME = time.time()
PROCESS_ID = uuid.uuid4().hex
FAILURE_MARKER = "/tmp/legacy-recovery-failure"
GENERATION_ID = creds.get("generation_id", "bootstrap")
app = FastAPI(title="Legacy Application")

from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
def index_ui():
    user_hash = hashlib.sha256(DB_USER.encode()).hexdigest()[:8]
    sec_active = getattr(app.state, "secondary_active", False)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Legacy Application - Portal</title>
  <style>
    body {{ background: #ffffff !important; color: #1e293b; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 2rem; margin: 0; }}
    .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 1.5rem; max-width: 800px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 1.5rem; }}
    h1 {{ color: #0f172a; margin-top: 0; font-size: 1.5rem; border-bottom: 2px solid #f1f5f9; padding-bottom: 0.5rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: 600; font-size: 0.75rem; }}
    .badge-success {{ background: #dcfce7; color: #15803d; }}
    .badge-warn {{ background: #fef3c7; color: #b45309; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.875rem; }}
    th, td {{ border: 1px solid #e2e8f0; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #f8fafc; font-weight: 600; }}
    code {{ background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.85rem; color: #0f172a; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>📦 Legacy Application Service (Port 8001)</h1>
    <p>Operational mode: <strong>Static credential loaded at process startup</strong></p>
    <table>
      <tr><th>Active DB User</th><td><code>{DB_USER}</code> (SHA: {user_hash})</td></tr>
      <tr><th>Startup Status</th><td>{"Connected at startup" if STARTUP_SUCCESS else "Startup connection failed"}</td></tr>
      <tr><th>Config File</th><td><code>{CONFIG_FILE}</code></td></tr>
      <tr><th>Secondary Slot Active</th><td>{f'<span class="badge badge-warn">Yes (Hot-Swapped)</span>' if sec_active else '<span class="badge badge-success">No (Primary Active)</span>'}</td></tr>
    </table>
  </div>
  <div class="card">
    <h2>REST API Endpoints</h2>
    <ul>
      <li><a href="/health"><code>/health</code></a> - Health status and uptime</li>
      <li><a href="/data"><code>/data</code></a> - Read application data from database</li>
      <li><a href="/config_meta"><code>/config_meta</code></a> - Inspect credential slot status</li>

    </ul>
  </div>
</body>
</html>"""

def get_db():
    return psycopg2.connect(
        host=APP_DB_HOST,
        port=APP_DB_PORT,
        dbname=APP_DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        connect_timeout=3
    )

@app.get("/health")
def health():
    if os.path.exists(FAILURE_MARKER):
        raise HTTPException(status_code=503, detail="Lab restart failure active; authorized recovery restart required")
    if not STARTUP_SUCCESS:
        raise HTTPException(status_code=503, detail=f"Database startup failed: {STARTUP_ERROR}")
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        return {
            "status": "healthy",
            "uptime_seconds": round(time.time() - START_TIME, 2),
            "user": DB_USER,
            "connected_at": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database probe failed: {e}")

@app.get("/data")
def read_data():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, item_name, updated_at FROM legacy_records ORDER BY id LIMIT 5")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"id": r[0], "item_name": r[1], "updated_at": str(r[2])} for r in rows]

@app.get("/config_meta")
def config_meta():
    user_hash = hashlib.sha256(DB_USER.encode()).hexdigest()[:8]
    return {
        "config_file": CONFIG_FILE,
        "user_hash": user_hash,
        "startup_time": START_TIME,
        "process_id": PROCESS_ID,
        "generation_id": GENERATION_ID,
        "secondary_credential_active": getattr(app.state, "secondary_active", False)
    }

@app.post("/control/exit")
def control_exit(request: Request, fail: bool = False):
    expected = os.environ.get('LEGACY_CONTROL_TOKEN','')
    if not expected or not hmac.compare_digest(request.headers.get('Authorization',''), 'Bearer '+expected):
        raise HTTPException(status_code=401, detail='Authorized supervisor required')
    if fail:
        with open(FAILURE_MARKER,'w') as marker:
            marker.write('restart failure exercise')
    elif os.path.exists(FAILURE_MARKER):
        os.unlink(FAILURE_MARKER)
    print(f"Process restart requested (fail={fail}). Exiting...", flush=True)
    def do_exit():
        time.sleep(0.2)
        os._exit(1 if fail else 0)
    import threading
    threading.Thread(target=do_exit).start()
    return {"status": "exiting", "exit_code": 1 if fail else 0}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
