#!/usr/bin/env python3
"""Provision the GitLab CE side of the lab once the server is healthy.

Run by `make up` after `docker compose up`. Idempotent and best-effort: if GitLab
is not reachable in time it prints a warning and exits 0 so `make up` still
succeeds (the dashboard's pipeline features then fall back to simulated mode).

What it does:
  1. Obtains an admin API token for `root` via the OAuth password grant, using the
     per-deployment password from poc/.env.
  2. Mints a non-expiring-as-possible personal access token (scope: api) and writes
     it, with the project id, to .bootstrap/gitlab_access.json. The control plane
     reads that file lazily, so no restart is needed.
  3. Ensures the `root/legacy-customer-portal` project exists, initialised with a
     default `main` branch and a clean `config/database.yml` (the file the
     dashboard's "simulate push" flow updates).
"""
import os
import sys
import json
import time
import datetime
import requests

POC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GITLAB_URL = os.getenv("GITLAB_SETUP_URL", "http://127.0.0.1:8929")
PROJECT_PATH = "legacy-customer-portal"
ACCESS_FILE = os.path.join(POC_DIR, ".bootstrap", "gitlab_access.json")

CLEAN_DB_CONFIG = (
    "# Production Database Configuration\n"
    "production:\n"
    "  adapter: postgresql\n"
    "  database: customer_db_prod\n"
    "  username: app_user\n"
    "  password: <%= ENV['DATABASE_PASSWORD'] %>\n"
    "  host: db.internal.corp\n"
)


def _root_password():
    env_path = os.path.join(POC_DIR, ".env")
    if os.path.exists(env_path):
        for line in open(env_path):
            if line.startswith("GITLAB_ROOT_PASSWORD="):
                return line.split("=", 1)[1].strip()
    return os.getenv("GITLAB_ROOT_PASSWORD", "ChangeMeLabRoot2026")


def wait_for_gitlab(attempts=60, delay=10):
    print(f"Waiting for GitLab API at {GITLAB_URL}...", flush=True)
    for _ in range(attempts):
        try:
            # /api/v4/version needs auth; a 401 still means the API is serving.
            r = requests.get(f"{GITLAB_URL}/api/v4/version", timeout=4)
            if r.status_code in (200, 401):
                return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def get_admin_token(password):
    r = requests.post(
        f"{GITLAB_URL}/oauth/token",
        data={"grant_type": "password", "username": "root", "password": password},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def mint_pat(admin_token):
    h = {"Authorization": f"Bearer {admin_token}"}
    me = requests.get(f"{GITLAB_URL}/api/v4/user", headers=h, timeout=10)
    me.raise_for_status()
    uid = me.json()["id"]
    expires = (datetime.date.today() + datetime.timedelta(days=364)).isoformat()
    r = requests.post(
        f"{GITLAB_URL}/api/v4/users/{uid}/personal_access_tokens",
        headers=h,
        data={"name": "lab-control-plane", "scopes[]": "api", "expires_at": expires},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["token"]


def ensure_project(token):
    h = {"PRIVATE-TOKEN": token}
    enc = requests.utils.quote(f"root/{PROJECT_PATH}", safe="")
    r = requests.get(f"{GITLAB_URL}/api/v4/projects/{enc}", headers=h, timeout=10)
    if r.status_code == 200:
        pid = r.json()["id"]
        print(f"Project root/{PROJECT_PATH} already exists (id {pid}).", flush=True)
    else:
        c = requests.post(
            f"{GITLAB_URL}/api/v4/projects",
            headers=h,
            data={"name": PROJECT_PATH, "path": PROJECT_PATH,
                  "initialize_with_readme": "true", "default_branch": "main"},
            timeout=20,
        )
        c.raise_for_status()
        pid = c.json()["id"]
        print(f"Created project root/{PROJECT_PATH} (id {pid}).", flush=True)

    # Ensure config/database.yml exists so the dashboard's 'update' commits apply.
    f_enc = requests.utils.quote("config/database.yml", safe="")
    fr = requests.get(
        f"{GITLAB_URL}/api/v4/projects/{pid}/repository/files/{f_enc}?ref=main",
        headers=h, timeout=10,
    )
    if fr.status_code != 200:
        requests.post(
            f"{GITLAB_URL}/api/v4/projects/{pid}/repository/commits",
            headers={**h, "Content-Type": "application/json"},
            json={"branch": "main", "commit_message": "chore: add database configuration",
                  "actions": [{"action": "create", "file_path": "config/database.yml",
                               "content": CLEAN_DB_CONFIG}]},
            timeout=15,
        )
        print("Seeded config/database.yml.", flush=True)
    return pid


def main():
    if not wait_for_gitlab():
        print("WARNING: GitLab did not become ready; skipping GitLab provisioning. "
              "Dashboard pipeline features will run in simulated mode.", flush=True)
        return 0
    try:
        admin_token = get_admin_token(_root_password())
        pat = mint_pat(admin_token)
        pid = ensure_project(pat)
        os.makedirs(os.path.dirname(ACCESS_FILE), exist_ok=True)
        with open(ACCESS_FILE, "w") as f:
            json.dump({"token": pat, "project_id": pid,
                       "project_path": f"root/{PROJECT_PATH}"}, f, indent=2)
        os.chmod(ACCESS_FILE, 0o600)
        print(f"GitLab access written to {ACCESS_FILE} (project id {pid}).", flush=True)
        return 0
    except Exception as e:
        print(f"WARNING: GitLab provisioning failed ({e}). "
              "Dashboard pipeline features will run in simulated mode.", flush=True)
        return 0


if __name__ == "__main__":
    sys.exit(main())
