#!/usr/bin/env python3
import os
import sys
import json
import time
import secrets
import hashlib
from pathlib import Path
import subprocess
import requests

POC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(POC_DIR, "certs")
BOOTSTRAP_DIR = os.path.join(POC_DIR, ".bootstrap")
CA_CERT = os.getenv("VAULT_CACERT") or (os.path.join(CERTS_DIR, "ca.pem") if os.path.exists(os.path.join(CERTS_DIR, "ca.pem")) else "/certs/ca.pem")
VAULT_ADDR = os.getenv("VAULT_ADDR", "https://127.0.0.1:8200")
COMPOSE_FILE = os.path.join(POC_DIR, "docker-compose.yml")
PROJECT_NAME = os.getenv("PROJECT_NAME", "poc")

os.makedirs(BOOTSTRAP_DIR, exist_ok=True)

ENV_FILE = os.path.join(POC_DIR, ".env")


def env_value(name):
    """Read a generated deployment secret without exposing it in command output."""
    if name in os.environ:
        return os.environ[name]
    if os.path.exists(ENV_FILE):
        for line in Path(ENV_FILE).read_text().splitlines():
            if line.startswith(name + "="):
                return line.split("=", 1)[1]
    raise RuntimeError(f"{name} is required; run bootstrap with --gen-env first")


def ensure_env_file():
    """Generate poc/.env with per-deployment random credentials on first run.

    docker compose auto-loads this file, so the GitLab root password, supervisor
    token and HMAC key differ for every fresh lab and are never committed. An
    existing .env is left untouched so repeated bootstraps stay stable.
    """
    existing = Path(ENV_FILE).read_text() if os.path.exists(ENV_FILE) else ""
    keys = {line.split("=", 1)[0] for line in existing.splitlines() if "=" in line}
    defaults = {
        "GITLAB_ROOT_PASSWORD": secrets.token_urlsafe(18),
        "CONTROL_DB_PASSWORD": secrets.token_urlsafe(24),
        "VAULT_DB_ADMIN_PASSWORD": secrets.token_urlsafe(24),
        "LEGACY_DB_INITIAL_PASSWORD": secrets.token_urlsafe(24),
        "SUPERVISOR_SECRET": secrets.token_urlsafe(32),
        "HMAC_SECRET_KEY": secrets.token_urlsafe(32),
        "AUTH_SIGNING_KEY": secrets.token_urlsafe(32),
        "INTERNAL_SERVICE_TOKEN": secrets.token_urlsafe(32),
        "INTEGRATED_ADMIN_TOKEN": secrets.token_urlsafe(32),
        "IDENTITY_AUTHORITY_TOKEN": secrets.token_urlsafe(32),
        "LEGACY_CONTROL_TOKEN": secrets.token_urlsafe(32),
        "SPIFFE_ADMIN_TOKEN": secrets.token_urlsafe(32),
    }
    missing = {k: v for k, v in defaults.items() if k not in keys}
    if missing:
        if existing:
            backup = ENV_FILE + ".backup-" + str(time.time_ns())
            Path(backup).write_text(existing)
            os.chmod(backup, 0o600)
        with open(ENV_FILE, "a") as f:
            f.write("\n# Generated deployment secrets. Do not commit.\n")
            for key, value in missing.items():
                f.write(f"{key}={value}\n")
    os.chmod(ENV_FILE, 0o600)
    # Passwords remain on the host; only password hashes enter the control container.
    credentials_path = Path(BOOTSTRAP_DIR) / "auth_credentials.json"
    users_path = Path(BOOTSTRAP_DIR) / "auth_users.json"
    credentials = json.loads(credentials_path.read_text()) if credentials_path.exists() else {}
    users = json.loads(users_path.read_text()) if users_path.exists() else {}
    names = ["secops_admin", "admin", "owner_dave", "sec_officer", "bob", "alice",
             "developer_alice", "requester_alice", "sec_responder", "lead_responder",
             "secops_responder", "secops_workflow", "gitleaks", "scanner_svc", "anomaly_monitor"]
    changed = False
    for name in names:
        if name not in credentials or name not in users:
            password = credentials.setdefault(name, secrets.token_urlsafe(24))
            salt = secrets.token_bytes(16)
            users[name] = {"salt": salt.hex(), "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200000).hex()}
            changed = True
    if changed:
        for target, data in [(credentials_path, credentials), (users_path, users)]:
            if target.exists():
                backup = Path(str(target) + ".backup-" + str(time.time_ns()))
                backup.write_bytes(target.read_bytes())
                backup.chmod(0o600)
            target.write_text(json.dumps(data, indent=2) + "\n")
            target.chmod(0o600)
    print("Deployment authentication ready; local user passwords are in .bootstrap/auth_credentials.json", flush=True)

    # Ensure test fixtures exist
    try:
        from generate_fixtures import FIXTURES_DIR
    except Exception:
        f_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
        os.makedirs(f_dir, exist_ok=True)
        pos_f = os.path.join(f_dir, "positive_log.txt")
        if not os.path.exists(pos_f):
            with open(pos_f, "w") as f:
                f.write("# Positive Scanner Fixture Log\n[2026-09-06T12:00:01Z] [DEBUG] Config: {\"token\": \"LAB_SEC_EXP_LEAKED_STATIC_2026\"}\n")
        neg_f = os.path.join(f_dir, "negative_log.txt")
        if not os.path.exists(neg_f):
            with open(neg_f, "w") as f:
                f.write("# Negative Scanner Fixture Log\n[2026-09-06T12:00:01Z] [INFO] Clean execution\n")

def run(cmd, shell=True, check=True):
    res = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"Command failed: {cmd}\nStderr: {res.stderr}\nStdout: {res.stdout}", file=sys.stderr, flush=True)
        raise RuntimeError(f"Command exited with {res.returncode}")
    return res

def wait_for_vault():
    print(f"Waiting for Vault at {VAULT_ADDR}...", flush=True)
    for _ in range(30):
        try:
            resp = requests.get(f"{VAULT_ADDR}/v1/sys/health", verify=CA_CERT, timeout=2)
            if resp.status_code in (200, 429, 501, 503):
                return True
        except Exception:
            time.sleep(1)
    raise TimeoutError("Timed out waiting for Vault")


def wait_for_postgres(attempts=45):
    """Block until PostgreSQL accepts an authenticated connection to appdb.

    The postgres container applies init.sql on first start, and there is a brief
    window where it is listening but still 'starting up'. Configuring the Vault
    database engine before that window closes fails with HTTP 400.
    """
    print("Waiting for PostgreSQL (appdb) to accept connections...", flush=True)
    try:
        import psycopg2
    except Exception:
        time.sleep(5)
        return
    for _ in range(attempts):
        try:
            psycopg2.connect(host="127.0.0.1", port=5432, dbname="appdb",
                             user="vault_dba", password=env_value("VAULT_DB_ADMIN_PASSWORD"),
                             connect_timeout=2).close()
            return
        except Exception:
            time.sleep(2)
    print("WARNING: PostgreSQL not confirmed ready; continuing anyway.", flush=True)

def init_and_unseal_vault():
    vault_keys_file = os.path.join(BOOTSTRAP_DIR, "vault_keys.json")
    if os.path.exists(vault_keys_file):
        print(f"Loading existing Vault keys from {vault_keys_file}", flush=True)
        with open(vault_keys_file, "r") as f:
            data = json.load(f)
            unseal_key = data["keys"][0]
            root_token = data["root_token"]
    else:
        print("Initializing Vault with 1 secret share and threshold 1...", flush=True)
        resp = requests.post(f"{VAULT_ADDR}/v1/sys/init", json={"secret_shares": 1, "secret_threshold": 1}, verify=CA_CERT, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        unseal_key = data["keys"][0]
        root_token = data["root_token"]
        with open(vault_keys_file, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(vault_keys_file, 0o600)
        print(f"Saved Vault keys to {vault_keys_file}", flush=True)

    # Check if sealed
    h_resp = requests.get(f"{VAULT_ADDR}/v1/sys/health", verify=CA_CERT, timeout=5)
    if h_resp.status_code == 503 or h_resp.json().get("sealed"):
        print("Unsealing Vault...", flush=True)
        u_resp = requests.post(f"{VAULT_ADDR}/v1/sys/unseal", json={"key": unseal_key}, verify=CA_CERT, timeout=5)
        u_resp.raise_for_status()
        print("Vault successfully unsealed.", flush=True)
    else:
        print("Vault is already unsealed.", flush=True)

    return root_token

def configure_vault(root_token):
    headers = {"X-Vault-Token": root_token}

    # 1. Enable audit log
    try:
        requests.post(f"{VAULT_ADDR}/v1/sys/audit/file", json={
            "type": "file",
            "options": {"file_path": "/vault/logs/audit.log"}
        }, headers=headers, verify=CA_CERT, timeout=5)
        print("Enabled Vault file audit logging.", flush=True)
    except Exception:
        pass

    # 2. Enable database secrets engine at database/ and KV-v2 engine at secret/
    try:
        requests.post(f"{VAULT_ADDR}/v1/sys/mounts/database", json={"type": "database"}, headers=headers, verify=CA_CERT, timeout=5)
        print("Mounted database secrets engine.", flush=True)
    except Exception:
        pass

    try:
        requests.post(f"{VAULT_ADDR}/v1/sys/mounts/secret", json={"type": "kv-v2"}, headers=headers, verify=CA_CERT, timeout=5)
        print("Mounted secret/ kv-v2 secrets engine.", flush=True)
    except Exception:
        pass

    # 3. Configure connection to PostgreSQL appdb
    print("Configuring Vault PostgreSQL connection to appdb...", flush=True)
    db_config_resp = requests.post(f"{VAULT_ADDR}/v1/database/config/appdb", json={
        "plugin_name": "postgresql-database-plugin",
        "allowed_roles": ["legacy-app-role", "integrated-role"],
        "connection_url": "postgresql://{{username}}:{{password}}@postgres:5432/appdb?sslmode=disable",
        "username": "vault_dba",
        "password": env_value("VAULT_DB_ADMIN_PASSWORD")
    }, headers=headers, verify=CA_CERT, timeout=5)
    db_config_resp.raise_for_status()

    # 4. Configure static role for legacy application
    print("Configuring static role legacy-app-role...", flush=True)
    static_resp = requests.post(f"{VAULT_ADDR}/v1/database/static-roles/legacy-app-role", json={
        "db_name": "appdb",
        "username": "legacy_user",
        "rotation_period": 86400,
        "rotation_statements": ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
    }, headers=headers, verify=CA_CERT, timeout=5)
    static_resp.raise_for_status()

    # 5. Configure dynamic role for integrated application
    print("Configuring dynamic role integrated-role...", flush=True)
    dyn_resp = requests.post(f"{VAULT_ADDR}/v1/database/roles/integrated-role", json={
        "db_name": "appdb",
        "default_ttl": "1h",
        "max_ttl": "24h",
        "creation_statements": [
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' IN ROLE app_reader;"
        ]
    }, headers=headers, verify=CA_CERT, timeout=5)
    dyn_resp.raise_for_status()

    # 6. Enable AppRole auth
    try:
        requests.post(f"{VAULT_ADDR}/v1/sys/auth/approle", json={"type": "approle"}, headers=headers, verify=CA_CERT, timeout=5)
        print("Enabled AppRole auth.", flush=True)
    except Exception:
        pass

    # 7. Policies (Explicitly deny cubbyhole per security baseline)
    # Update default policy to block cubbyhole access
    default_policy_resp = requests.get(f"{VAULT_ADDR}/v1/sys/policies/acl/default", headers=headers, verify=CA_CERT, timeout=5)
    if default_policy_resp.ok:
        cur_default = default_policy_resp.json().get("data", {}).get("policy", "")
        # Remove cubbyhole allow rule and add explicit deny
        cur_default = cur_default.replace('path "cubbyhole/*" {\n    capabilities = ["create", "read", "update", "delete", "list"]\n}', '')
        cur_default += '\npath "cubbyhole/*" {\n    capabilities = ["deny"]\n}\n'
        requests.put(f"{VAULT_ADDR}/v1/sys/policies/acl/default", json={"policy": cur_default}, headers=headers, verify=CA_CERT, timeout=5)
        print("Updated Vault default policy: cubbyhole access denied.", flush=True)

    policies = {
        "control-policy": """
            path "database/*" { capabilities = ["create", "read", "update", "delete", "list"] }
            path "sys/leases/*" { capabilities = ["create", "read", "update", "delete", "list"] }
            path "auth/approle/*" { capabilities = ["create", "read", "update", "delete", "list"] }
            path "secret/*" { capabilities = ["create", "read", "update", "delete", "list"] }
            path "sys/policies/acl/*" { capabilities = ["create", "read", "update", "delete", "list"] }
            path "cubbyhole/*" { capabilities = ["deny"] }
        """,
        "legacy-agent-policy": """
            path "database/static-creds/legacy-app-role" { capabilities = ["read"] }
            path "cubbyhole/*" { capabilities = ["deny"] }
        """,
        "integrated-app-policy": """
            path "database/creds/integrated-role" { capabilities = ["read"] }
            path "sys/leases/renew" { capabilities = ["update"] }
            path "sys/leases/lookup" { capabilities = ["update"] }
            path "cubbyhole/*" { capabilities = ["deny"] }
        """
    }

    for pname, ppolicy in policies.items():
        requests.put(f"{VAULT_ADDR}/v1/sys/policies/acl/{pname}", json={"policy": ppolicy}, headers=headers, verify=CA_CERT, timeout=5)
        print(f"Created Vault policy: {pname}", flush=True)

    # 8. Create AppRoles and extract credentials
    roles = {
        "control-role": "control_approle.json",
        "legacy-agent-role": "legacy_approle.json",
        "integrated-app-role": "integrated_approle.json"
    }

    for rname, out_file in roles.items():
        requests.post(f"{VAULT_ADDR}/v1/auth/approle/role/{rname}", json={
            "token_policies": [rname.replace("-role", "-policy")],
            "token_ttl": "24h"
        }, headers=headers, verify=CA_CERT, timeout=5)

        role_id = requests.get(f"{VAULT_ADDR}/v1/auth/approle/role/{rname}/role-id", headers=headers, verify=CA_CERT, timeout=5).json()["data"]["role_id"]
        secret_id = requests.post(f"{VAULT_ADDR}/v1/auth/approle/role/{rname}/secret-id", headers=headers, verify=CA_CERT, timeout=5).json()["data"]["secret_id"]

        out_path = os.path.join(BOOTSTRAP_DIR, out_file)
        with open(out_path, "w") as f:
            json.dump({"role_id": role_id, "secret_id": secret_id}, f, indent=2)
        os.chmod(out_path, 0o600)
        print(f"Created AppRole {rname}, saved credentials to {out_file}", flush=True)

    # Fetch initial static credential for legacy app
    print("Reading initial static credentials for legacy app...", flush=True)
    static_cred_resp = requests.get(f"{VAULT_ADDR}/v1/database/static-creds/legacy-app-role", headers=headers, verify=CA_CERT, timeout=5)
    legacy_creds = static_cred_resp.json()["data"]

    creds_dir = os.path.join(BOOTSTRAP_DIR, "legacy-creds")
    os.makedirs(creds_dir, exist_ok=True)
    with open(os.path.join(creds_dir, "db-creds.json"), "w") as f:
        json.dump(legacy_creds, f, indent=2)
    os.chmod(os.path.join(creds_dir, "db-creds.json"), 0o600)
    print(f"Rendered initial legacy credentials to {creds_dir}/db-creds.json", flush=True)

    print("Vault bootstrap complete.", flush=True)

def register_spire_workloads():
    print("Configuring SPIRE Server and Agent workloads...", flush=True)

    # Generate token on server
    token_cmd = f"docker compose -p {PROJECT_NAME} -f {COMPOSE_FILE} exec -T spire-server spire-server token generate -spiffeID spiffe://lab.local/agent/node1"
    res = run(token_cmd, check=False)
    token = None
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            if "Token:" in line:
                token = line.split("Token:")[-1].strip()
        if token:
            print("Generated SPIRE agent join token.", flush=True)
            token_path = os.path.join(POC_DIR, "spire", "agent-token.txt")
            with open(token_path, "w") as f:
                f.write(token)
            os.chmod(token_path, 0o644)

    # Register Caller with 10s TTL for fast renewal observation (Scenario A13)
    c_cmd = f"docker compose -p {PROJECT_NAME} -f {COMPOSE_FILE} exec -T spire-server spire-server entry create -spiffeID spiffe://lab.local/workload/caller -parentID spiffe://lab.local/agent/node1 -selector unix:uid:1001 -x509SVIDTTL 10"
    run(c_cmd, check=False)

    # Register Protected Service
    s_cmd = f"docker compose -p {PROJECT_NAME} -f {COMPOSE_FILE} exec -T spire-server spire-server entry create -spiffeID spiffe://lab.local/workload/protected-service -parentID spiffe://lab.local/agent/node1 -selector unix:uid:1002"
    run(s_cmd, check=False)

    print("SPIRE registration entries configured.", flush=True)

CONTROL_ADDR = os.getenv("CONTROL_ADDR", "http://127.0.0.1:8000")


def wait_for_control_plane(attempts=60):
    print(f"Waiting for control plane at {CONTROL_ADDR}...", flush=True)
    for _ in range(attempts):
        try:
            if requests.get(f"{CONTROL_ADDR}/api/health", timeout=2).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(1)
    print("Control plane did not become ready; skipping seed.", flush=True)
    return False


def seed_control_db(reconcile=False):
    if not wait_for_control_plane():
        raise RuntimeError("Control plane unavailable; seed did not complete")
    print("Seeding initial authenticated control plane records...", flush=True)
    credentials = json.loads((Path(BOOTSTRAP_DIR) / "auth_credentials.json").read_text())
    tokens = {}

    def api(method, path, actor, body=None):
        if actor not in tokens:
            response = requests.post(CONTROL_ADDR + "/api/auth/token", json={
                "username": actor, "password": credentials[actor]}, timeout=10)
            if response.status_code != 200:
                raise RuntimeError(f"Seed login failed for {actor}: HTTP {response.status_code}")
            tokens[actor] = response.json()["access_token"]
        response = requests.request(method, CONTROL_ADDR + path, json=body,
                                    headers={"Authorization": "Bearer " + tokens[actor], "X-Run-Id": "bootstrap_seed"}, timeout=20)
        if not response.ok:
            raise RuntimeError(f"Seed {method} {path} failed: HTTP {response.status_code}")
        return response.json()

    payloads = [{'service_id': 'svc-legacy',
  'service_name': 'Legacy Customer Portal',
  'owner_group': 'legacy_team',
  'operational_contact': 'dave@lab.local',
  'fallback_group': 'security_fallback',
  'environment': 'production',
  'classification': 'restricted',
  'business_criticality': 'high',
  'application_category': 'legacy',
  'target_resource': 'postgres:5432/appdb',
  'requested_permissions': ['read', 'write'],
  'consumer_list': ['legacy-app'],
  'lifetime_policy': '30d',
  'replacement_mode': 'restart',
  'expected_restart_behavior': 'graceful_exit',
  'recovery_procedure_id': 'proc-legacy-01',
  'idempotency_key': 'bootstrap-svc-legacy-v2'},
 {'service_id': 'svc-integrated',
  'service_name': 'Payment Gateway Engine',
  'owner_group': 'platform_team',
  'operational_contact': 'alice@lab.local',
  'fallback_group': 'security_fallback',
  'environment': 'production',
  'classification': 'restricted',
  'business_criticality': 'critical',
  'application_category': 'integrated',
  'target_resource': 'postgres:5432/appdb',
  'requested_permissions': ['read', 'write', 'charge'],
  'consumer_list': ['integrated-app'],
  'lifetime_policy': '1h',
  'replacement_mode': 'in_process_reload',
  'expected_restart_behavior': 'hot_reload',
  'recovery_procedure_id': 'proc-integrated-01',
  'network_exposure': 'Public',
  'data_classification': 'Confidential',
  'auto_rotation_support': True,
  'secret_manager_ref': 'secret/data/services/svc-integrated',
  'secondary_credential_configured': False,
  'gitlab_repo_url': 'http://localhost:8000/gitlab/platform/svc-integrated',
  'idempotency_key': 'bootstrap-svc-integrated-v2'},
 {'service_id': 'svc-spiffe',
  'service_name': 'Zero-Secret Identity Mesh',
  'owner_group': 'security_team',
  'operational_contact': 'secops@lab.local',
  'fallback_group': 'security_fallback',
  'environment': 'production',
  'classification': 'restricted',
  'business_criticality': 'high',
  'application_category': 'spiffe',
  'target_resource': 'spiffe-service:8443',
  'requested_permissions': ['mtls_invoke'],
  'consumer_list': ['spiffe-caller'],
  'lifetime_policy': '1h',
  'replacement_mode': 'svid_auto_rotation',
  'expected_restart_behavior': 'none',
  'recovery_procedure_id': 'proc-spiffe-01',
  'network_exposure': 'Internal',
  'data_classification': 'Restricted',
  'auto_rotation_support': True,
  'secret_manager_ref': 'spiffe://lab.local/workload/caller',
  'secondary_credential_configured': False,
  'gitlab_repo_url': 'http://localhost:8000/gitlab/platform/svc-spiffe',
  'idempotency_key': 'bootstrap-svc-spiffe-v2'}]
    existing = {service["id"] for service in api("GET", "/api/services", "secops_admin")}
    for payload in payloads:
        if payload["service_id"] in existing and not reconcile:
            continue  # preserve existing records and credential lineage
        if reconcile:
            import uuid
            payload["idempotency_key"] = "reconcile-" + uuid.uuid4().hex
        intake = api("POST", "/api/intakes", "alice", payload)
        if intake["status"] in ("draft", "submitted"):
            approver = "sec_officer" if payload["service_id"] == "svc-spiffe" else "owner_dave"
            intake = api("POST", f"/api/intakes/{intake['id']}/approve", approver,
                         {"approver_id": approver, "expected_revision": intake["revision"]})
        if intake["status"] != "provisioned":
            api("POST", f"/api/intakes/{intake['id']}/provision", "sec_responder")
    services = {service["id"] for service in api("GET", "/api/services", "secops_admin")}
    if not {payload["service_id"] for payload in payloads}.issubset(services):
        raise RuntimeError("Seed completed without all required services")
    print("Control plane seed verified for all three local services.", flush=True)

def main():
    print("=== Starting lab bootstrap process ===", flush=True)
    ensure_env_file()
    wait_for_vault()
    root_token = init_and_unseal_vault()
    wait_for_postgres()
    configure_vault(root_token)
    register_spire_workloads()
    print("=== Bootstrap completed successfully! ===", flush=True)
    print("Run 'make up' to start the stack and seed the control plane.", flush=True)

if __name__ == "__main__":
    if "--gen-env" in sys.argv:
        ensure_env_file()
    elif "--seed-only" in sys.argv:
        seed_control_db(reconcile="--reconcile" in sys.argv)
    else:
        main()
