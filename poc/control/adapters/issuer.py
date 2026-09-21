import os
import requests
import psycopg2
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

VAULT_ADDR = os.getenv("VAULT_ADDR", "https://vault:8200")
_default_ca = "/certs/ca.pem"
if not os.path.exists(_default_ca):
    _candidate = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "certs", "ca.pem")
    if os.path.exists(_candidate):
        _default_ca = _candidate
VAULT_CACERT = os.getenv("VAULT_CACERT", _default_ca)

class SecretIssuerAdapter(ABC):
    @abstractmethod
    def rotate_static_role(self, role_name: str, token: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def issue_dynamic_credentials(self, role_name: str, token: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def revoke_lease(self, lease_id: str, token: str) -> bool:
        pass

    @abstractmethod
    def terminate_target_sessions(self, username: str) -> int:
        pass

class VaultSecretIssuerAdapter(SecretIssuerAdapter):
    def __init__(self, vault_addr: str = VAULT_ADDR, ca_cert: str = VAULT_CACERT):
        self.vault_addr = vault_addr
        if not ca_cert or not os.path.exists(ca_cert):
            raise FileNotFoundError(f"Missing CA certificate at {ca_cert}. Failing closed to prevent unauthenticated/insecure TLS communication.")
        self.ca_cert = ca_cert

    def _headers(self, token: Optional[str] = None) -> Dict[str, str]:
        if not token:
            token = os.getenv("VAULT_ADMIN_TOKEN")
        if not token:
            for approle_path in ["/poc/.bootstrap/control_approle.json", os.path.join(os.path.dirname(__file__), "..", "..", ".bootstrap", "control_approle.json")]:
                if os.path.exists(approle_path):
                    try:
                        import json
                        with open(approle_path, "r") as f:
                            data = json.load(f)
                        url = f"{self.vault_addr}/v1/auth/approle/login"
                        resp = requests.post(url, json={"role_id": data["role_id"], "secret_id": data["secret_id"]}, verify=self.ca_cert, timeout=5)
                        if resp.status_code == 200:
                            token = resp.json()["auth"]["client_token"]
                            break
                    except Exception:
                        pass
        if not token:
            raise ValueError("Issuer authentication unavailable")
        return {"X-Vault-Token": token}

    def rotate_static_role(self, role_name: str, token: str) -> Dict[str, Any]:
        url = f"{self.vault_addr}/v1/database/rotate-role/{role_name}"
        resp = requests.post(url, headers=self._headers(token), verify=self.ca_cert, timeout=10)
        resp.raise_for_status()
        # Read the static role to get last_vault_rotation or current status
        return self.read_static_role(role_name, token)

    def read_static_role(self, role_name: str, token: str) -> Dict[str, Any]:
        """Read static role metadata from Vault without triggering mutation"""
        r_url = f"{self.vault_addr}/v1/database/static-roles/{role_name}"
        r_resp = requests.get(r_url, headers=self._headers(token), verify=self.ca_cert, timeout=10)
        r_resp.raise_for_status()
        return r_resp.json().get("data", {})

    def issue_dynamic_credentials(self, role_name: str, token: str) -> Dict[str, Any]:
        url = f"{self.vault_addr}/v1/database/creds/{role_name}"
        resp = requests.get(url, headers=self._headers(token), verify=self.ca_cert, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def revoke_lease(self, lease_id: str, token: str) -> bool:
        url = f"{self.vault_addr}/v1/sys/leases/revoke"
        resp = requests.put(url, headers=self._headers(token), json={"lease_id": lease_id}, verify=self.ca_cert, timeout=10)
        return resp.status_code in (200, 204)

    def block_workload_issuance(self, policy_name: str = "integrated-app-policy", token: str = None) -> bool:
        """Block dynamic credential issuance at Vault for a compromised workload."""
        deny_policy = """
            path "database/creds/integrated-role" { capabilities = ["deny"] }
            path "sys/leases/*" { capabilities = ["deny"] }
            path "cubbyhole/*" { capabilities = ["deny"] }
        """
        r = requests.put(f"{self.vault_addr}/v1/sys/policies/acl/{policy_name}",
                         json={"policy": deny_policy}, headers=self._headers(token),
                         verify=self.ca_cert, timeout=5)
        return r.status_code in (200, 204)

    def unblock_workload_issuance(self, policy_name: str = "integrated-app-policy", token: str = None) -> bool:
        """Restore dynamic credential issuance at Vault upon authorized recovery"""
        allow_policy = """
            path "database/creds/integrated-role" { capabilities = ["read"] }
            path "sys/leases/renew" { capabilities = ["update"] }
            path "sys/leases/lookup" { capabilities = ["update"] }
            path "cubbyhole/*" { capabilities = ["deny"] }
        """
        r = requests.put(f"{self.vault_addr}/v1/sys/policies/acl/{policy_name}",
                         json={"policy": allow_policy}, headers=self._headers(token),
                         verify=self.ca_cert, timeout=5)
        return r.status_code in (200, 204)

    def capture_target_sessions(self, username):
        conn = psycopg2.connect(os.environ["APP_DB_ADMIN_URL"])
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pid, backend_start FROM pg_stat_activity WHERE usename=%s", (username,))
                rows = cur.fetchall()
                if any(started is None for _, started in rows):
                    raise ValueError("Target session identity is unavailable; observation permission required")
                return [(pid, started.isoformat()) for pid, started in rows]
        finally:
            conn.close()

    def count_captured_sessions(self, sessions):
        conn = psycopg2.connect(os.environ["APP_DB_ADMIN_URL"])
        try:
            with conn.cursor() as cur:
                total = 0
                for pid, started in sessions:
                    cur.execute("SELECT count(*) FROM pg_stat_activity WHERE pid=%s AND backend_start=%s::timestamptz", (pid, started))
                    total += cur.fetchone()[0]
                return total
        finally:
            conn.close()

    def terminate_captured_sessions(self, sessions):
        # Vault may drop the role while its sessions survive. Bind termination to
        # the captured backend identity, including start time to prevent PID reuse.
        conn = psycopg2.connect(os.environ["APP_DB_ADMIN_URL"])
        try:
            with conn.cursor() as cur:
                total = 0
                for pid, started in sessions:
                    cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid=%s AND backend_start=%s::timestamptz", (pid, started))
                    total += sum(bool(row[0]) for row in cur.fetchall())
                conn.commit()
                return total
        finally:
            conn.close()

    def terminate_target_sessions(self, username: str) -> int:
        app_db_url = os.getenv("APP_DB_ADMIN_URL", "postgresql://vault_dba:vault_dba_pass@postgres:5432/appdb")
        conn = psycopg2.connect(app_db_url)
        cur = conn.cursor()
        cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = %s", (username,))
        terminated = sum(1 for row in cur.fetchall() if row[0])
        conn.commit()
        cur.close()
        conn.close()
        return terminated

    def count_target_sessions(self, username: str) -> int:
        conn = psycopg2.connect(os.environ["APP_DB_ADMIN_URL"])
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM pg_stat_activity WHERE usename=%s", (username,))
                return cur.fetchone()[0]
        finally:
            conn.close()

    def lease_absent(self, lease_id: str, token: str) -> bool:
        response = requests.put(f"{self.vault_addr}/v1/sys/leases/lookup",
                                headers=self._headers(token), json={"lease_id":lease_id}, verify=self.ca_cert, timeout=10)
        if response.status_code == 200:
            return False
        # Only the documented missing-lease error proves absence. Permission,
        # sealed Vault, transport errors and generic 400s remain unavailable.
        if response.status_code == 400 and any("invalid lease" in e.lower() or "lease not found" in e.lower()
                                               for e in response.json().get("errors", [])):
            return True
        response.raise_for_status()
        raise ValueError("Lease lookup did not establish authoritative absence")

    def store_kv_secret(self, path: str, secret_data: Dict[str, Any], token: str) -> Dict[str, Any]:
        """Store secret in Vault KV v2 engine under secret/data/{path}"""
        clean_path = path.removeprefix("secret/data/").removeprefix("secret/")
        url = f"{self.vault_addr}/v1/secret/data/{clean_path}"
        resp = requests.post(url, headers=self._headers(token), json={"data": secret_data}, verify=self.ca_cert, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data", {})

    def read_kv_secret(self, path: str, token: str) -> Dict[str, Any]:
        """Read secret from Vault KV v2 engine"""
        clean_path = path.removeprefix("secret/data/").removeprefix("secret/")
        url = f"{self.vault_addr}/v1/secret/data/{clean_path}"
        resp = requests.get(url, headers=self._headers(token), verify=self.ca_cert, timeout=10)
        resp.raise_for_status()
        return resp.json().get("data", {}).get("data", {})

    def configure_app_access(self, service_id: str, path: str, token: str) -> Dict[str, str]:
        """Automate AppRole and policy creation for a newly provisioned service"""
        clean_path = path.removeprefix("secret/data/").removeprefix("secret/")
        policy_name = f"{service_id}-read-policy"
        policy_rules = f"""
            path "secret/data/{clean_path}" {{ capabilities = ["read"] }}
            path "cubbyhole/*" {{ capabilities = ["deny"] }}
        """
        # Create policy
        p_url = f"{self.vault_addr}/v1/sys/policies/acl/{policy_name}"
        requests.put(p_url, headers=self._headers(token), json={"policy": policy_rules}, verify=self.ca_cert, timeout=10).raise_for_status()

        # Create AppRole
        role_name = f"{service_id}-approle"
        r_url = f"{self.vault_addr}/v1/auth/approle/role/{role_name}"
        requests.post(r_url, headers=self._headers(token), json={"token_policies": [policy_name], "token_ttl": "1h"}, verify=self.ca_cert, timeout=10).raise_for_status()

        role_id = requests.get(f"{r_url}/role-id", headers=self._headers(token), verify=self.ca_cert, timeout=10).json()["data"]["role_id"]
        secret_id = requests.post(f"{r_url}/secret-id", headers=self._headers(token), verify=self.ca_cert, timeout=10).json()["data"]["secret_id"]
        return {"role_id": role_id, "secret_id": secret_id, "policy": policy_name}
