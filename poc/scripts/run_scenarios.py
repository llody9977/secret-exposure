#!/usr/bin/env python3
import os
import sys
import json
import time
import uuid
import hashlib
import platform
import requests
import subprocess
import concurrent.futures
import threading
from urllib.parse import quote
from datetime import datetime, timezone, timedelta

POC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(POC_DIR, "control"))

IS_IN_CONTAINER = os.path.exists("/.dockerenv") or os.environ.get("HOSTNAME") == "lab-control-api"
CONTROL_URL = os.getenv("CONTROL_URL", "http://control-api:8000" if IS_IN_CONTAINER else "http://127.0.0.1:8000")
VAULT_ADDR = os.getenv("VAULT_ADDR", "https://vault:8200" if IS_IN_CONTAINER else "https://127.0.0.1:8200")
os.environ["VAULT_ADDR"] = VAULT_ADDR
os.environ.setdefault("VAULT_CACERT", os.path.join(POC_DIR, "certs", "ca.pem"))
LEGACY_APP_URL = os.getenv("LEGACY_APP_URL", "http://legacy-app:8001" if IS_IN_CONTAINER else "http://127.0.0.1:8001")
INTEGRATED_APP_URL = os.getenv("INTEGRATED_APP_URL", "http://integrated-app:8002" if IS_IN_CONTAINER else "http://127.0.0.1:8002")
SPIFFE_CALLER_URL = os.getenv("SPIFFE_CALLER_URL", "http://spiffe-caller:8003" if IS_IN_CONTAINER else "http://127.0.0.1:8003")
SPIFFE_SERVICE_ADMIN_URL = os.getenv("SPIFFE_SERVICE_ADMIN_URL", "http://spiffe-service:8444" if IS_IN_CONTAINER else "http://127.0.0.1:8444")

SUPERVISOR_SECRET = os.getenv("SUPERVISOR_SECRET")
LOCAL_ENV = {}
env_path = os.path.join(POC_DIR, ".env")
if os.path.exists(env_path):
    with open(env_path) as f:
        for line in f:
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.strip().split("=", 1)
                LOCAL_ENV[key] = value
    SUPERVISOR_SECRET = SUPERVISOR_SECRET or LOCAL_ENV.get("SUPERVISOR_SECRET")

# Tokens are obtained from the deployed authentication boundary, never locally signed.
TOKEN_ALICE = "alice"
TOKEN_BOB = "bob"
TOKEN_DAVE = "owner_dave"
TOKEN_SEC_OFFICER = "sec_officer"
TOKEN_SEC_RESPONDER = "sec_responder"
TOKEN_LEAD_RESPONDER = "lead_responder"
TOKEN_ADMIN = "secops_admin"
TOKEN_SCANNER = "gitleaks"
TOKEN_SCANNER_SVC = "scanner_svc"
TOKEN_ANOMALY = "anomaly_monitor"

CA_CERT = os.path.join(POC_DIR, "certs", "ca.pem")
EVIDENCE_DIR = os.path.join(POC_DIR, "evidence")
RUN_ID = f"run_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
LAB_PREFIX = os.getenv("LAB_PREFIX", "lab")

def container(service: str) -> str:
    return f"{LAB_PREFIX}-{service}"


def source_snapshot():
    from pathlib import Path
    root = Path(POC_DIR)
    excluded = {".git", ".venv", ".bootstrap", ".vault-data", "certs", "evidence", "fixtures", "__pycache__", "bin", ".pytest_cache"}
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not path.is_file() or any(part in excluded or part.startswith(".env") for part in rel.parts):
            continue
        if path.suffix in {".pyc", ".log"}:
            continue
        files[str(rel)] = hashlib.sha256(path.read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"sha256": digest, "files": files}

class ScenarioRunner:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.tokens = {}
        self.results = {}
        self.source_snapshot = source_snapshot()
        self.assertions = []
        self.external_evidence = []
        self.scenario_failed = {}
        self.start_time = datetime.now(timezone.utc).isoformat()

    def auth_headers(self, token: str, extra: dict = None) -> dict:
        delegated = json.loads(os.environ.get("SCENARIO_BEARER_TOKENS", "{}"))
        if token in delegated:
            headers = {"Authorization": "Bearer " + delegated[token], "X-Run-Id": self.run_id}
            if extra:
                headers.update(extra)
            return headers
        if token not in self.tokens:
            with open(os.path.join(POC_DIR, ".bootstrap", "auth_credentials.json")) as handle:
                credentials = json.load(handle)
            response = requests.post(f"{CONTROL_URL}/api/auth/token", json={
                "username": token, "password": credentials[token]}, timeout=5)
            response.raise_for_status()
            self.tokens[token] = response.json()["access_token"]
        import inspect
        scenario = next((frame.function[4:].upper() for frame in inspect.stack()
                         if frame.function.startswith("run_a")), "export")
        h = {
            "Authorization": f"Bearer {self.tokens[token]}",
            "X-Run-Id": self.run_id,
            "X-Scenario-Id": scenario,
        }
        if extra:
            h.update(extra)
        return h

    def integrated_request(self, method, url, **kwargs):
        values = dict(line.split("=", 1) for line in open(env_path).read().splitlines() if "=" in line and not line.startswith("#"))
        kwargs["headers"] = {"Authorization": "Bearer " + values["INTEGRATED_ADMIN_TOKEN"]}
        return requests.request(method, url, **kwargs)

    def legacy_candidate(self, scan=False):
        with open(os.path.join(POC_DIR, ".bootstrap", "legacy-creds", "db-creds.json")) as handle:
            actual = json.load(handle)
        if scan:
            import tempfile
            folder = os.path.join(POC_DIR, ".bootstrap")
            with tempfile.TemporaryDirectory(prefix="scan-", dir=folder) as tmp:
                path = os.path.join(tmp, "exposure.txt")
                with open(path, "w") as handle:
                    handle.write('lab_database_password = ' + json.dumps(actual["password"]) + "\n")
                os.chmod(path, 0o600)
                scan_path = "/poc/" + os.path.relpath(path, POC_DIR)
                result = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", POC_DIR+":/poc:ro",
                    "poc-lab-base:latest", "gitleaks", "detect", "--config", "/poc/scanner/gitleaks.toml",
                    "--source", scan_path, "--no-git", "--redact"], capture_output=True, text=True, timeout=30)
                self.record_assertion("A06", "Real scanner detects the issued disposable database password", result.returncode == 1,
                    {"detector": "gitleaks", "version": "8.24.0", "exit_code": result.returncode})
                if result.returncode != 1:
                    raise RuntimeError("Issued-credential scan did not return a finding")
        response = requests.post(f"{CONTROL_URL}/api/internal/store-candidate", headers=self.auth_headers(TOKEN_SCANNER),
            json={"candidate_val": actual["password"]}, timeout=5)
        response.raise_for_status()
        return response.json()["candidate_ref"]

    def current_legacy_candidate(self):
        """Store the issuer's current static credential as restricted evidence.

        A crash-recovery exercise must target the registered active version, not
        an application file that may intentionally lag during recovery.
        """
        import orchestrator
        token = orchestrator.get_vault_token()
        current = orchestrator._static_credentials("legacy-app-role", token)
        response = requests.post(f"{CONTROL_URL}/api/internal/store-candidate",
                                 headers=self.auth_headers(TOKEN_SCANNER),
                                 json={"candidate_val": current["password"]}, timeout=5)
        response.raise_for_status()
        return response.json()["candidate_ref"]

    def record_assertion(self, scenario_id: str, assertion_name: str, passed: bool, details: dict):
        self.assertions.append({
            "scenario_id": scenario_id,
            "assertion": assertion_name,
            "passed": passed,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        status_str = "PASS" if passed else "FAIL"
        print(f"  [{status_str}] {assertion_name}")
        if not passed:
            # These verifier fields are deliberately constrained to safe
            # identifiers, unlike subprocess output which may carry
            # deployment-local credentials.
            failure_stage = details.get("failure_stage")
            error_type = details.get("error_type")
            if failure_stage or error_type:
                print(f"    diagnostic: stage={failure_stage or 'unknown'} error_type={error_type or 'unknown'}")
            self.scenario_failed[scenario_id] = True

    def run_a01(self):
        print("\n--- Scenario A01: Clean install, doctor, bootstrap & health ---")
        try:
            before = set(os.listdir(os.path.join(POC_DIR, "evidence"))) if os.path.isdir(os.path.join(POC_DIR, "evidence")) else set()
            check = subprocess.run(
                [sys.executable, os.path.join(POC_DIR, "scripts", "verify_a01_clean_install.py")],
                capture_output=True, text=True, timeout=1200,
            )
            after = set(os.listdir(os.path.join(POC_DIR, "evidence"))) if os.path.isdir(os.path.join(POC_DIR, "evidence")) else set()
            run_dirs = sorted(name for name in after - before if name.startswith("a01-"))
            details = {"verifier_exit_code": check.returncode, "evidence_run": run_dirs[-1] if run_dirs else None}
            if run_dirs:
                artifact = os.path.join(POC_DIR, "evidence", run_dirs[-1], "a01-clean-install.json")
                with open(artifact) as handle:
                    clean_install = json.load(handle)
                details.update({key: clean_install[key] for key in ("failure_stage", "error_type") if key in clean_install})
                if check.returncode == 0:
                    self.external_evidence.append({"scenario_id": "A01", "kind": "fresh_source_install", "artifact": artifact, "result": clean_install})
            self.record_assertion("A01", "Fresh source copy builds, bootstraps, and becomes healthy in an isolated project", check.returncode == 0, details)
            self.results["A01"] = "FAIL" if self.scenario_failed.get("A01") else "PASS"
            return
        except Exception as e:
            self.record_assertion("A01", f"A01 clean-install verifier failed: {e}", False, {"error": str(e)})
            self.results["A01"] = "FAIL"
            return

        # Retained below as historical diagnostics; clean-install acceptance is
        # determined by the isolated verifier above.
        try:
            # 1. Check doctor script output
            d_res = subprocess.run([sys.executable, os.path.join(POC_DIR, "scripts", "doctor.py")], capture_output=True, text=True)
            self.record_assertion("A01", "Doctor check passes cleanly without errors", d_res.returncode == 0, {"stdout": d_res.stdout.strip()})

            # 2. Host architecture and resource budget verification (REQ001)
            arch = platform.machine()
            sys_name = platform.system()
            cpu_count = os.cpu_count() or 1
            budget_ok = cpu_count >= 4
            self.record_assertion("A01", "Host architecture and CPU resource budget confirmed",
                                  budget_ok and bool(arch),
                                  {"platform": sys_name, "arch": arch, "cpu_cores": cpu_count, "budget_ok": budget_ok})

            # 3. Verify Dockerfile.base declared source layout aligns with runtime Debian 13 / trixie
            df_path = os.path.join(POC_DIR, "Dockerfile.base")
            with open(df_path, "r") as df:
                df_content = df.read()
            is_trixie = "debian:trixie" in df_content or "debian:13" in df_content
            has_pg17 = "postgresql" in df_content
            self.record_assertion("A01", "Declared base image and PostgreSQL source versions match runtime layout",
                                  is_trixie and has_pg17,
                                  {"is_trixie": is_trixie, "has_postgresql": has_pg17, "base_line": df_content.splitlines()[0]})

            # 4. Check Control API health
            h_res = requests.get(f"{CONTROL_URL}/api/health", headers=self.auth_headers(TOKEN_ADMIN), timeout=3)
            self.record_assertion("A01", "Control plane health probe returns HTTP 200", h_res.status_code == 200, h_res.json())

            self.results["A01"] = "FAIL" if self.scenario_failed.get("A01") else "PASS"
        except Exception as e:
            self.record_assertion("A01", f"A01 execution failed: {e}", False, {"error": str(e)})
            self.results["A01"] = "FAIL"

    def run_a02(self):
        print("\n--- Scenario A02: Incomplete intake rejection with field errors ---")
        try:
            # Missing owner_group
            res1 = requests.post(f"{CONTROL_URL}/api/intakes", headers=self.auth_headers(TOKEN_ALICE), json={
                "service_id": "svc-bad-1",
                "service_name": "Bad Intake 1",
                "owner_group": "",
                "operational_contact": "alice@lab.local",
                "fallback_group": "sec_fallback",
                "environment": "production",
                "classification": "restricted",
                "business_criticality": "high",
                "application_category": "legacy",
                "target_resource": "postgres:5432/appdb",
                "requested_permissions": ["read"],
                "consumer_list": ["legacy-app"],
                "lifetime_policy": "30d",
                "replacement_mode": "restart",
                "expected_restart_behavior": "graceful_exit",
                "recovery_procedure_id": "proc-01"
            }, timeout=3)
            self.record_assertion("A02", "Rejection of intake with empty owner_group", res1.status_code == 422, {"status": res1.status_code})

            # Missing requested_permissions
            res2 = requests.post(f"{CONTROL_URL}/api/intakes", headers=self.auth_headers(TOKEN_ALICE), json={
                "service_id": "svc-bad-2",
                "service_name": "Bad Intake 2",
                "owner_group": "platform_team",
                "operational_contact": "alice@lab.local",
                "fallback_group": "sec_fallback",
                "environment": "production",
                "classification": "restricted",
                "business_criticality": "high",
                "application_category": "legacy",
                "target_resource": "postgres:5432/appdb",
                "requested_permissions": [],
                "consumer_list": ["legacy-app"],
                "lifetime_policy": "30d",
                "replacement_mode": "restart",
                "expected_restart_behavior": "graceful_exit",
                "recovery_procedure_id": "proc-01"
            }, timeout=3)
            self.record_assertion("A02", "Rejection of intake with empty requested_permissions", res2.status_code == 422, {"status": res2.status_code})

            self.results["A02"] = "FAIL" if self.scenario_failed.get("A02") else "PASS"
        except Exception as e:
            self.record_assertion("A02", f"A02 execution failed: {e}", False, {"error": str(e)})
            self.results["A02"] = "FAIL"

    def run_a03(self):
        print("\n--- Scenario A03: Requester self-approval & forgery rejection ---")
        try:
            # 1. Invalid / forged bearer token fails closed with HTTP 401 (Blocker #1)
            bad_token_res = requests.post(f"{CONTROL_URL}/api/intakes", headers={"Authorization": "Bearer invalid.token.value"}, json={
                "service_id": "svc-bad-auth", "service_name": "Bad Auth", "owner_group": "orders_team",
                "operational_contact": "alice@lab.local", "fallback_group": "sec_fallback", "environment": "production",
                "classification": "restricted", "business_criticality": "high", "application_category": "legacy",
                "target_resource": "postgres:5432/appdb", "requested_permissions": ["read"], "consumer_list": ["legacy-app"],
                "lifetime_policy": "30d", "replacement_mode": "restart", "expected_restart_behavior": "graceful_exit",
                "recovery_procedure_id": "proc-01"
            }, timeout=3)
            self.record_assertion("A03", "Invalid token fails closed with HTTP 401", bad_token_res.status_code == 401, {"status": bad_token_res.status_code})

            # 2. Header-only identity (X-Actor-Id without valid token) denied with HTTP 401/403 (Blocker #1)
            hdr_only_res = requests.post(f"{CONTROL_URL}/api/intakes", headers={"X-Requester-Id": "secops_admin"}, json={
                "service_id": "svc-bad-auth-2", "service_name": "Bad Auth 2", "owner_group": "orders_team",
                "operational_contact": "alice@lab.local", "fallback_group": "sec_fallback", "environment": "production",
                "classification": "restricted", "business_criticality": "high", "application_category": "legacy",
                "target_resource": "postgres:5432/appdb", "requested_permissions": ["read"], "consumer_list": ["legacy-app"],
                "lifetime_policy": "30d", "replacement_mode": "restart", "expected_restart_behavior": "graceful_exit",
                "recovery_procedure_id": "proc-01"
            }, timeout=3)
            self.record_assertion("A03", "Header-only identity denied without valid bearer token", hdr_only_res.status_code in (401, 403), {"status": hdr_only_res.status_code})

            # Create valid draft intake using Alice's Bearer token
            intake_res = requests.post(f"{CONTROL_URL}/api/intakes", headers=self.auth_headers(TOKEN_ALICE), json={
                "service_id": "svc-order-api",
                "service_name": "Order Management API",
                "owner_group": "orders_team",
                "operational_contact": "alice@lab.local",
                "fallback_group": "security_fallback",
                "environment": "production",
                "classification": "restricted",
                "business_criticality": "high",
                "application_category": "legacy",
                "target_resource": "postgres:5432/appdb",
                "requested_permissions": ["read", "write"],
                "consumer_list": ["legacy-app"],
                "lifetime_policy": "30d",
                "replacement_mode": "restart",
                "expected_restart_behavior": "graceful_exit",
                "recovery_procedure_id": "proc-order-01"
            }, timeout=3)
            intake_id = intake_res.json()["id"]

            # Requester alice tries to approve her own intake using her Bearer token -> 403
            self_res = requests.post(f"{CONTROL_URL}/api/intakes/{intake_id}/approve", headers=self.auth_headers(TOKEN_ALICE), json={
                "approver_id": "alice",
                "expected_revision": 1
            }, timeout=3)
            self.record_assertion("A03", "Requester self-approval rejected with HTTP 403", self_res.status_code == 403, {"status": self_res.status_code})

            # Alice tries to forge approver field (Token says alice, body claims bob) -> 403
            forge_res = requests.post(f"{CONTROL_URL}/api/intakes/{intake_id}/approve", headers=self.auth_headers(TOKEN_ALICE), json={
                "approver_id": "bob",
                "expected_revision": 1
            }, timeout=3)
            self.record_assertion("A03", "Forged approver identity rejected with HTTP 403", forge_res.status_code == 403, {"status": forge_res.status_code})

            # Non-member approver (bob is in audit_team, intake owner is orders_team) -> 403 (Blocker #1)
            wrong_group_res = requests.post(f"{CONTROL_URL}/api/intakes/{intake_id}/approve", headers=self.auth_headers(TOKEN_BOB), json={
                "approver_id": "bob",
                "expected_revision": 1
            }, timeout=3)
            self.record_assertion("A03", "Non-member approver (audit_team) rejected for orders_team intake with HTTP 403", wrong_group_res.status_code == 403, {"status": wrong_group_res.status_code})

            # Scanner role forbidden from executing operations -> 403 (Blocker #1)
            scanner_exec_res = requests.post(f"{CONTROL_URL}/api/operations/op-dummy/execute", headers=self.auth_headers(TOKEN_SCANNER_SVC), json={
                "execution_identity": "scanner_svc"
            }, timeout=3)
            self.record_assertion("A03", "Scanner role forbidden from executing operations with HTTP 403", scanner_exec_res.status_code == 403, {"status": scanner_exec_res.status_code})

            # Authorized member of orders_team (owner_dave) approves -> 200
            ok_res = requests.post(f"{CONTROL_URL}/api/intakes/{intake_id}/approve", headers=self.auth_headers(TOKEN_DAVE), json={
                "approver_id": "owner_dave",
                "expected_revision": 1
            }, timeout=3)
            self.record_assertion("A03", "Authorized group member approves with HTTP 200", ok_res.status_code == 200, ok_res.json())

            self.results["A03"] = "FAIL" if self.scenario_failed.get("A03") else "PASS"
        except Exception as e:
            self.record_assertion("A03", f"A03 execution failed: {e}", False, {"error": str(e)})
            self.results["A03"] = "FAIL"

    def run_a04(self):
        print("\n--- Scenario A04: Provisioning & ownership change with fallback routing ---")
        try:
            # Create and approve an intake
            s_id = "svc-legacy"
            intake_res = requests.post(f"{CONTROL_URL}/api/intakes", headers=self.auth_headers(TOKEN_ALICE), json={
                "service_id": s_id,
                "service_name": "Customer Service",
                "owner_group": "cust_ops",
                "operational_contact": "carol@lab.local",
                "fallback_group": "sec_fallback",
                "environment": "production",
                "classification": "restricted",
                "business_criticality": "high",
                "application_category": "legacy",
                "target_resource": "postgres:5432/appdb",
                "requested_permissions": ["read"],
                "consumer_list": ["legacy-app"],
                "lifetime_policy": "30d",
                "replacement_mode": "restart",
                "expected_restart_behavior": "graceful_exit",
                "recovery_procedure_id": "proc-cust-01"
            }, timeout=3)
            intake_id = intake_res.json()["id"]

            requests.post(f"{CONTROL_URL}/api/intakes/{intake_id}/approve", headers=self.auth_headers(TOKEN_DAVE), json={
                "approver_id": "owner_dave",
                "expected_revision": 1
            }, timeout=3)

            # Provision
            prov_res = requests.post(f"{CONTROL_URL}/api/intakes/{intake_id}/provision", headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=5)
            prov_data = prov_res.json()
            self.record_assertion("A04", "Provisioning returns operation ID and version ID without secrets",
                                  "operation_id" in prov_data and "current_version_id" in prov_data, prov_data)

            # Check service metadata
            svc_res = requests.get(f"{CONTROL_URL}/api/services/{s_id}", headers=self.auth_headers(TOKEN_ADMIN), timeout=3).json()
            self.record_assertion("A04", "Service resolves registered owner group", svc_res["owner_group"] == "cust_ops", svc_res)

            # Simulate unknown service finding -> routes to fallback
            finding_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": f"evt-unknown-{uuid.uuid4().hex[:6]}",
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "logs/unknown.log",
                "detector_identity": "gitleaks-lab",
                "detector_version": "8.24.0",
                "claimed_service_hint": "svc-nonexistent"
            }, timeout=3).json()
            self.record_assertion("A04", "Unknown ownership routes to security_fallback queue",
                                  finding_res["assigned_owner"] == "security_fallback", finding_res)

            self.results["A04"] = "FAIL" if self.scenario_failed.get("A04") else "PASS"
        except Exception as e:
            self.record_assertion("A04", f"A04 execution failed: {e}", False, {"error": str(e)})
            self.results["A04"] = "FAIL"

    def run_a05(self):
        print("\n--- Scenario A05: Credential masking verification (no raw secrets leaked) ---")
        try:
            # Check services list
            svcs = requests.get(f"{CONTROL_URL}/api/services", headers=self.auth_headers(TOKEN_ADMIN), timeout=3).text
            # Check incidents list
            incs = requests.get(f"{CONTROL_URL}/api/incidents", headers=self.auth_headers(TOKEN_ADMIN), timeout=3).text
            # Check metrics
            mets = requests.get(f"{CONTROL_URL}/api/metrics", headers=self.auth_headers(TOKEN_ADMIN), timeout=3).text

            forbidden_patterns = ["password", "PRIVATE KEY", "root_token"]
            leaks = []
            for pat in forbidden_patterns:
                if f'"{pat}":' in svcs or f'"{pat}":' in incs or f'"{pat}":' in mets:
                    leaks.append(pat)

            self.record_assertion("A05", "No raw passwords or tokens exposed in API endpoints", len(leaks) == 0, {"leaks_found": leaks})
            self.results["A05"] = "FAIL" if self.scenario_failed.get("A05") else "PASS"
        except Exception as e:
            self.record_assertion("A05", f"A05 execution failed: {e}", False, {"error": str(e)})
            self.results["A05"] = "FAIL"

    def run_a06(self):
        print("\n--- Scenario A06: Legacy app exposure, rotation, restart & target verification ---")
        try:
            candidate_ref = self.legacy_candidate(scan=True)

            # Scanner detects the secret
            event_id = f"evt-scan-{uuid.uuid4().hex[:6]}"
            finding_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": event_id,
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "repo/app/settings.py:14",
                "candidate_ref": candidate_ref,
                "detector_identity": "gitleaks-lab",
                "detector_version": "8.24.0"
            }, timeout=3).json()
            incident_id = finding_res["id"]
            self.record_assertion("A06", "Finding correlated to svc-legacy and owner assigned",
                                  finding_res["service_id"] == "svc-legacy", finding_res)

            # Owner decision: approve rotation
            dec_res = requests.post(f"{CONTROL_URL}/api/incidents/{incident_id}/decisions", json={
                "actor": "owner_dave",
                "action": "rotate",
                "reason": "Exposed credential detected in commit",
                "expected_revision": finding_res["revision"]
            }, headers=self.auth_headers(TOKEN_DAVE), timeout=3).json()
            operation_id = dec_res["operation"]["id"]
            self.record_assertion("A06", "Triage decision recorded with operation enqueued",
                                  dec_res["operation"]["action"] == "rotate", dec_res["operation"])

            # Execute operation
            exec_res = requests.post(f"{CONTROL_URL}/api/operations/{operation_id}/execute", json={
                "execution_identity": "sec_responder"
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=60).json()
            self.record_assertion("A06", "Operation executed, interruption measured, containment verified",
                                  exec_res.get("containment") == "verified" and "interruption_ms" in exec_res, exec_res)

            self.results["A06"] = "FAIL" if self.scenario_failed.get("A06") else "PASS"
        except Exception as e:
            self.record_assertion("A06", f"A06 execution failed: {e}", False, {"error": str(e)})
            self.results["A06"] = "FAIL"

    def run_a07(self):
        print("\n--- Scenario A07: Legacy restart failure handling ---")
        try:
            # Create incident for restart failure test
            f_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": f"evt-fail-{uuid.uuid4().hex[:6]}",
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "logs/leak.log",
                "claimed_service_hint": "svc-legacy",
                "candidate_ref": self.current_legacy_candidate(),
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()
            inc_id = f_res["id"]

            dec_res = requests.post(f"{CONTROL_URL}/api/incidents/{inc_id}/decisions", json={
                "actor": "owner_dave",
                "action": "rotate",
                "reason": "Testing restart failure scenario",
                "expected_revision": f_res["revision"]
            }, headers=self.auth_headers(TOKEN_DAVE), timeout=3).json()
            op_id = dec_res["operation"]["id"]

            # Execute with simulate_restart_failure=True
            fail_res = requests.post(f"{CONTROL_URL}/api/operations/{op_id}/execute?simulate_restart_failure=true", json={
                "execution_identity": "sec_responder"
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=60).json()

            self.record_assertion("A07", "Containment verified while recovery is marked failed separately",
                                  fail_res.get("containment") == "verified" and fail_res.get("recovery") == "failed", fail_res)

            inc_status = requests.get(f"{CONTROL_URL}/api/incidents/{inc_id}", headers=self.auth_headers(TOKEN_ADMIN), timeout=3).json()
            self.record_assertion("A07", "Case remains open when recovery has failed", inc_status["case_status"] == "open", inc_status)

            repair = requests.post("http://127.0.0.1:8080/restart/legacy-app", headers={"Authorization": f"Bearer {SUPERVISOR_SECRET}"}, timeout=45)
            repair.raise_for_status()
            self.record_assertion("A07", "Authorized repair restarts on replacement credentials", repair.json().get("healthy") is True, repair.json())

            self.results["A07"] = "FAIL" if self.scenario_failed.get("A07") else "PASS"
        except Exception as e:
            self.record_assertion("A07", f"A07 execution failed: {e}", False, {"error": str(e)})
            self.results["A07"] = "FAIL"

    def run_a08(self):
        print("\n--- Scenario A08: Unmodifiable credential exception record ---")
        try:
            # Register unmodifiable application
            s_id = f"svc-legacy-firmware-{uuid.uuid4().hex[:4]}"
            intake_res = requests.post(f"{CONTROL_URL}/api/intakes", headers=self.auth_headers(TOKEN_DAVE), json={
                "service_id": s_id,
                "service_name": "Embedded Hardware Gateway",
                "owner_group": "hardware_team",
                "operational_contact": "dave@lab.local",
                "fallback_group": "sec_fallback",
                "environment": "production",
                "classification": "restricted",
                "business_criticality": "high",
                "application_category": "unmodifiable",
                "target_resource": "postgres:5432/appdb",
                "requested_permissions": ["read"],
                "consumer_list": ["legacy-firmware-app"],
                "lifetime_policy": "permanent_exception",
                "replacement_mode": "manual",
                "expected_restart_behavior": "manual_power_cycle",
                "recovery_procedure_id": "proc-hw-01",
                "exception_status": {
                    "reason": "Hardcoded firmware device key",
                    "owner": "owner_dave",
                    "residual_authority": "read_only_status",
                    "compensating_control": "IP whitelist and network isolation",
                    "exit_condition": "Hardware retirement scheduled Q4"
                }
            }, timeout=3)
            intake_data = intake_res.json()
            intake_id = intake_data.get("id")
            if not intake_id:
                raise RuntimeError(f"Intake creation failed: {intake_res.status_code} {intake_data}")

            # Approve
            requests.post(f"{CONTROL_URL}/api/intakes/{intake_id}/approve", headers=self.auth_headers(TOKEN_SEC_OFFICER), json={
                "approver_id": "sec_officer",
                "expected_revision": 1
            }, timeout=3)

            # Finding for this unmodifiable service
            finding_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": f"evt-hw-{uuid.uuid4().hex[:6]}",
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "firmware/config.hex",
                "claimed_service_hint": s_id,
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()

            # Record exception action
            dec_res = requests.post(f"{CONTROL_URL}/api/incidents/{finding_res['id']}/decisions", json={
                "actor": "sec_officer",
                "action": "record_exception",
                "reason": "Compensating controls active per approved exception record",
                "expected_revision": finding_res["revision"]
            }, headers=self.auth_headers(TOKEN_SEC_OFFICER), timeout=3).json()

            op_res = requests.post(f"{CONTROL_URL}/api/operations/{dec_res['operation']['id']}/execute", json={
                "execution_identity": "sec_responder"
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=3).json()

            self.record_assertion("A08", "Exception retains residual exposure and degraded recovery",
                                  op_res.get("containment") == "partial" and op_res.get("recovery") == "degraded", op_res)

            self.results["A08"] = "FAIL" if self.scenario_failed.get("A08") else "PASS"
        except Exception as e:
            self.record_assertion("A08", f"A08 execution failed: {e}", False, {"error": str(e)})
            self.results["A08"] = "FAIL"

    def run_a09(self):
        print("\n--- Scenario A09: Dynamic credentials, lease renewal & replacement ---")
        try:
            # Ensure issuance unblocked in Vault and app before running normal renewal & replacement
            requests.post(f"{CONTROL_URL}/api/services/svc-integrated/unblock-issuance",
                          headers=self.auth_headers(TOKEN_ADMIN), timeout=5)
            self.integrated_request("POST", f"{INTEGRATED_APP_URL}/block_issuance?blocked=false",
                          headers={"Authorization": f"Bearer {SUPERVISOR_SECRET}"}, timeout=3)
            self.integrated_request("POST", f"{INTEGRATED_APP_URL}/replace", timeout=5)

            # Integrated app health check
            h_res = self.integrated_request("GET", f"{INTEGRATED_APP_URL}/health", timeout=5).json()
            self.record_assertion("A09", "Integrated app holds active dynamic lease",
                                  h_res.get("status") == "healthy" and h_res.get("lease_valid") is True, h_res)

            # Renew lease
            r_res = self.integrated_request("POST", f"{INTEGRATED_APP_URL}/renew", timeout=5).json()
            self.record_assertion("A09", "Dynamic credential lease renewed successfully",
                                  r_res.get("status") == "renewed" and r_res.get("count", 0) > 0, r_res)

            # Replace pool
            p_res = self.integrated_request("POST", f"{INTEGRATED_APP_URL}/replace", timeout=5).json()
            self.record_assertion("A09", "Dynamic credential pool replacement succeeds",
                                  p_res.get("status") == "replaced", p_res)

            self.results["A09"] = "FAIL" if self.scenario_failed.get("A09") else "PASS"
        except Exception as e:
            self.record_assertion("A09", f"A09 execution failed: {e}", False, {"error": str(e)})
            self.results["A09"] = "FAIL"

    def run_a10(self):
        print("\n--- Scenario A10: Dynamic lease revocation & target session containment ---")
        try:
            # Ensure fresh active dynamic lease and connection before holding session
            requests.post(f"{CONTROL_URL}/api/services/svc-integrated/unblock-issuance",
                          headers=self.auth_headers(TOKEN_ADMIN), timeout=5)
            self.integrated_request("POST", f"{INTEGRATED_APP_URL}/block_issuance?blocked=false",
                          headers={"Authorization": f"Bearer {SUPERVISOR_SECRET}"}, timeout=3)
            self.integrated_request("POST", f"{INTEGRATED_APP_URL}/replace", timeout=5)

            # Hold a persistent session
            hold_res = self.integrated_request("POST", f"{INTEGRATED_APP_URL}/sessions/hold", timeout=5).json()
            backend_pid = hold_res.get("backend_pid")
            self.record_assertion("A10", "Persistent database session established", backend_pid is not None, hold_res)

            status_res = self.integrated_request("GET", f"{INTEGRATED_APP_URL}/status", timeout=5).json()
            lease_id = status_res.get("lease_id")
            fingerprint = status_res.get("fingerprint")

            exposure = self.integrated_request("POST", f"{INTEGRATED_APP_URL}/exposure", timeout=5)
            exposure.raise_for_status()
            candidate_ref = exposure.json()["candidate_ref"]

            # Create incident for dynamic lease exposure
            f_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": f"evt-dyn-{uuid.uuid4().hex[:6]}",
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "logs/app.log",
                "candidate_ref": candidate_ref,
                "claimed_service_hint": "svc-integrated",
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()

            dec_res = requests.post(f"{CONTROL_URL}/api/incidents/{f_res['id']}/decisions", json={
                "actor": "sec_responder",
                "action": "revoke",
                "reason": "Dynamic lease exposure containment",
                "expected_revision": f_res["revision"]
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=3).json()

            # Execute revocation & session termination
            exec_res = requests.post(f"{CONTROL_URL}/api/operations/{dec_res['operation']['id']}/execute", json={
                "execution_identity": "sec_responder"
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=10).json()

            self.record_assertion("A10", "Lease revoked and active PostgreSQL sessions terminated",
                                  exec_res.get("containment") == "verified", exec_res)

            self.results["A10"] = "FAIL" if self.scenario_failed.get("A10") else "PASS"
        except Exception as e:
            self.record_assertion("A10", f"A10 execution failed: {e}", False, {"error": str(e)})
            self.results["A10"] = "FAIL"

    def run_a11(self):
        print("\n--- Scenario A11: Compromised workload issuance blocking ---")
        try:
            # Block issuance on integrated app
            self.integrated_request("POST", f"{INTEGRATED_APP_URL}/block_issuance?blocked=true",
                          headers={"Authorization": f"Bearer {SUPERVISOR_SECRET}"}, timeout=3)

            # Try to replace credential while issuance blocked
            rep_res = self.integrated_request("POST", f"{INTEGRATED_APP_URL}/replace", timeout=3)
            issuer_probe = self.integrated_request("POST", f"{INTEGRATED_APP_URL}/issuance/probe", timeout=8)
            self.record_assertion("A11", "Vault itself denies issuance to compromised workload",
                                  issuer_probe.status_code == 200 and issuer_probe.json().get("issuer_denied") is True,
                                  {"status": issuer_probe.status_code})

            # Unblock / recover (explicit recovery authorization by operator per Blocker #2)
            requests.post(f"{CONTROL_URL}/api/services/svc-integrated/unblock-issuance",
                          headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=5)
            self.integrated_request("POST", f"{INTEGRATED_APP_URL}/block_issuance?blocked=false",
                          headers={"Authorization": f"Bearer {SUPERVISOR_SECRET}"}, timeout=3)
            ok_res = self.integrated_request("POST", f"{INTEGRATED_APP_URL}/replace", timeout=5)
            self.record_assertion("A11", "Workload replacement succeeds after explicit recovery authorization",
                                  ok_res.status_code == 200, ok_res.json() if ok_res.status_code == 200 else {"status": ok_res.status_code, "body": ok_res.text})

            self.results["A11"] = "FAIL" if self.scenario_failed.get("A11") else "PASS"
        except Exception as e:
            self.record_assertion("A11", f"A11 execution failed: {e}", False, {"error": str(e)})
            self.results["A11"] = "FAIL"

    def run_a12(self):
        print("\n--- Scenario A12: SPIRE attestation, mTLS & identity authorization ---")
        try:
            # Caller calls protected service via mTLS
            call_response = requests.get(f"{SPIFFE_CALLER_URL}/call", timeout=5)
            try:
                call_res = call_response.json()
            except ValueError:
                call_res = {"status_code": call_response.status_code, "body": call_response.text[:200]}
            self.record_assertion("A12", "Allowed SPIFFE identity accesses protected resource via mTLS",
                                  call_response.status_code == 200 and call_res.get("status") == "authorized", call_res)

            # Forbidden operation check
            forbid_res = requests.get(f"{SPIFFE_CALLER_URL}/call_forbidden", timeout=5)
            self.record_assertion("A12", "Forbidden operation denied with HTTP 403",
                                  forbid_res.status_code == 403, {"status": forbid_res.status_code})

            self.results["A12"] = "FAIL" if self.scenario_failed.get("A12") else "PASS"
        except Exception as e:
            self.record_assertion("A12", f"A12 execution failed: {e}", False, {"error": str(e)})
            self.results["A12"] = "FAIL"

    def run_a13(self):
        print("\n--- Scenario A13: SVID renewal observation ---")
        try:
            # Query SVID metadata - first snapshot
            info_res = requests.get(f"{SPIFFE_CALLER_URL}/svid_info", timeout=5).json()
            has_serial = "serial_number" in info_res and "spiffe_id" in info_res
            self.record_assertion("A13", "SPIFFE SVID non-secret metadata and serial recorded", has_serial, info_res)

            serial_1 = info_res.get("serial_number")

            # Wait for SVID renewal (SPIRE lab TTL is short)
            time.sleep(8)

            # Query SVID metadata - second snapshot after renewal window
            info_res_2 = requests.get(f"{SPIFFE_CALLER_URL}/svid_info", timeout=5).json()
            serial_2 = info_res_2.get("serial_number")
            self.record_assertion("A13", "SVID serial changes after renewal period",
                                  serial_1 != serial_2 and serial_2 is not None,
                                  {"serial_before": serial_1, "serial_after": serial_2})

            self.results["A13"] = "FAIL" if self.scenario_failed.get("A13") else "PASS"
        except Exception as e:
            self.record_assertion("A13", f"A13 execution failed: {e}", False, {"error": str(e)})
            self.results["A13"] = "FAIL"

    def run_a14(self):
        print("\n--- Scenario A14: SPIFFE compromised identity target policy containment ---")
        try:
            # Verify caller SVID is valid before containment
            svid_before = requests.get(f"{SPIFFE_CALLER_URL}/svid_info", timeout=5).json()
            self.record_assertion("A14", "Caller workload holds active SPIFFE SVID",
                                  "spiffe_id" in svid_before, svid_before)

            # Create incident for SPIFFE workload
            f_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_ANOMALY), json={
                "event_id": f"evt-spiffe-{uuid.uuid4().hex[:6]}",
                "source": "workload_anomaly",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "cluster/workload/caller",
                "claimed_service_hint": "svc-spiffe",
                "detector_identity": "anomaly_monitor",
                "detector_version": "1.0"
            }, timeout=3).json()

            # Decide isolate
            dec_res = requests.post(f"{CONTROL_URL}/api/incidents/{f_res['id']}/decisions", json={
                "actor": "sec_responder",
                "action": "isolate",
                "reason": "Compromised caller workload isolation",
                "expected_revision": f_res["revision"]
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=3).json()

            # Execute isolation (sets target policy to deny caller)
            exec_res = requests.post(f"{CONTROL_URL}/api/operations/{dec_res['operation']['id']}/execute", json={
                "execution_identity": "sec_responder"
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=30).json()

            self.record_assertion("A14", "Issuer denial and held/fresh target connections separately verified",
                exec_res.get("issuance_blocked") is True and exec_res.get("held_connection_denied") is True
                and exec_res.get("existing_connection_reused") is True and exec_res.get("fresh_connection_denied") is True, exec_res)

            # Test fresh caller mTLS request -> should now be denied with HTTP 403!
            denied_res = requests.get(f"{SPIFFE_CALLER_URL}/call", timeout=5)
            self.record_assertion("A14", "Target authorization policy denies isolated SPIFFE identity on fresh requests",
                                  denied_res.status_code == 403, {"status": denied_res.status_code})

            # Check that existing SVID remains intact on the caller (proving containment is target policy, not instant SVID deletion)
            svid_after = requests.get(f"{SPIFFE_CALLER_URL}/svid_info", timeout=5).json()
            self.record_assertion("A14", "Caller still holds SVID demonstrating effective target policy containment",
                                  "spiffe_id" in svid_after, svid_after)

            # Restore policy cleanly
            values = dict(line.split("=", 1) for line in open(env_path).read().splitlines() if "=" in line and not line.startswith("#")) if os.path.exists(env_path) else os.environ
            authority_url = "http://identity-authority:8445" if IS_IN_CONTAINER else "http://127.0.0.1:8445"
            restore = requests.post(authority_url+"/caller/restore", headers={"Authorization":"Bearer "+values["IDENTITY_AUTHORITY_TOKEN"]}, timeout=20)
            restore.raise_for_status()
            policy = requests.post(f"{SPIFFE_SERVICE_ADMIN_URL}/admin/policy", json={"allowed_spiffe_ids": ["spiffe://lab.local/workload/caller"]},
                headers={"Authorization":"Bearer "+values["SPIFFE_ADMIN_TOKEN"]}, timeout=5)
            policy.raise_for_status()

            # Confirm access restored
            restored_res = requests.get(f"{SPIFFE_CALLER_URL}/call", timeout=5)
            self.record_assertion("A14", "Target policy restored successfully",
                                  restored_res.status_code == 200, {"status": restored_res.status_code})

            self.results["A14"] = "FAIL" if self.scenario_failed.get("A14") else "PASS"
        except Exception as e:
            self.record_assertion("A14", f"A14 execution failed: {e}", False, {"error": str(e)})
            self.results["A14"] = "FAIL"

    def run_a15(self):
        print("\n--- Scenario A15: Scanner positive and negative fixtures ---")
        try:
            import shutil
            if shutil.which("gitleaks"):
                pos_cmd = f"gitleaks detect --config {os.path.join(POC_DIR, 'scanner/gitleaks.toml')} --source {os.path.join(POC_DIR, 'fixtures/positive_log.txt')} --no-git --redact"
                neg_cmd = f"gitleaks detect --config {os.path.join(POC_DIR, 'scanner/gitleaks.toml')} --source {os.path.join(POC_DIR, 'fixtures/negative_log.txt')} --no-git --redact"
            else:
                pos_cmd = f"docker run --rm -v {POC_DIR}:/poc poc-lab-base:latest gitleaks detect --config /poc/scanner/gitleaks.toml --source /poc/fixtures/positive_log.txt --no-git --redact"
                neg_cmd = f"docker run --rm -v {POC_DIR}:/poc poc-lab-base:latest gitleaks detect --config /poc/scanner/gitleaks.toml --source /poc/fixtures/negative_log.txt --no-git --redact"

            p_res = subprocess.run(pos_cmd, shell=True, capture_output=True, text=True)
            p_out = (p_res.stdout + p_res.stderr).lower()
            p_detected = p_res.returncode == 1 and "no leaks found" not in p_out and "leaks found" in p_out
            self.record_assertion("A15", "Positive fixture detects lab secrets (gitleaks exits 1 with leaks found)",
                                  p_detected, {"exit_code": p_res.returncode, "output": p_res.stdout[:200]})

            n_res = subprocess.run(neg_cmd, shell=True, capture_output=True, text=True)
            n_out = (n_res.stdout + n_res.stderr).lower()
            n_clean = n_res.returncode == 0 and "no leaks found" in n_out
            self.record_assertion("A15", "Negative fixture clean (gitleaks exits 0 with no leaks found)",
                                  n_clean, {"exit_code": n_res.returncode, "output": n_res.stdout[:200]})

            self.results["A15"] = "FAIL" if self.scenario_failed.get("A15") else "PASS"
        except Exception as e:
            self.record_assertion("A15", f"A15 execution failed: {e}", False, {"error": str(e)})
            self.results["A15"] = "FAIL"

    def run_a16(self):
        print("\n--- Scenario A16: Attacker-injected destination rejection ---")
        try:
            val_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": f"evt-inj-{uuid.uuid4().hex[:6]}",
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "logs/leak.log",
                "claimed_service_hint": "http://malicious-external-host.com:9999/steal",
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()

            self.record_assertion("A16", "Injected destination not invoked; routes to security_fallback queue",
                                  val_res["assigned_owner"] == "security_fallback" and val_res["service_id"] is None, val_res)

            self.results["A16"] = "FAIL" if self.scenario_failed.get("A16") else "PASS"
        except Exception as e:
            self.record_assertion("A16", f"A16 execution failed: {e}", False, {"error": str(e)})
            self.results["A16"] = "FAIL"

    def run_a17(self):
        print("\n--- Scenario A17: Validator status mapping ---")
        try:
            from adapters.validator import ValidatorAdapter
            val = ValidatorAdapter()

            # Wrong target
            r_unsupp = val.validate_credential("unknown_db:5432/bad", "user", "pass")
            self.record_assertion("A17", "Unknown target maps to 'unsupported'", r_unsupp["status"] == "unsupported", r_unsupp)

            # Invalid password
            r_inv = val.validate_credential("postgres:5432/appdb", "legacy_user", "WRONG_PASSWORD_12345")
            self.record_assertion("A17", "Password rejection maps to 'invalid'", r_inv["status"] == "invalid", r_inv)

            with open(os.path.join(POC_DIR, ".bootstrap", "legacy-creds", "db-creds.json")) as handle:
                actual = json.load(handle)
            active = val.validate_credential("postgres:5432/appdb", actual["username"], actual["password"])
            self.record_assertion("A17", "Actual current credential maps to active", active["status"] == "active", active)
            from unittest.mock import patch
            import psycopg2
            for failure in ("connection timeout", "permission denied"):
                with patch("adapters.validator.psycopg2.connect", side_effect=psycopg2.OperationalError(failure)):
                    result = val.validate_credential("postgres:5432/appdb", "controlled-probe", "unused")
                self.record_assertion("A17", failure + " remains inconclusive under controlled fault injection",
                    result["status"] == "inconclusive", {"fault_injection":True, "result":result})
            self.results["A17"] = "FAIL" if self.scenario_failed.get("A17") else "PASS"
        except Exception as e:
            self.record_assertion("A17", f"A17 execution failed: {e}", False, {"error": str(e)})
            self.results["A17"] = "FAIL"

    def run_a18(self):
        print("\n--- Scenario A18: Incident closure validation rules ---")
        try:
            # Create incident with pending containment
            f_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": f"evt-close-test-{uuid.uuid4().hex[:6]}",
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "code/test.py",
                "claimed_service_hint": "svc-legacy",
                "candidate_ref": self.legacy_candidate(),
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()
            inc_id = f_res["id"]

            # Try to close before containment verified
            c_res = requests.post(f"{CONTROL_URL}/api/incidents/{inc_id}/close", headers=self.auth_headers(TOKEN_LEAD_RESPONDER), json={
                "actor": "lead_responder",
                "recovery_disposition": "restored",
                "investigation_limitations": "none",
                "recurrence_owner": "owner_dave",
                "expected_revision": f_res["revision"]
            }, timeout=3)
            self.record_assertion("A18", "Premature closure rejected with HTTP 422", c_res.status_code == 422, {"status": c_res.status_code})

            # Now rotate and verify containment
            dec_res = requests.post(f"{CONTROL_URL}/api/incidents/{inc_id}/decisions", json={
                "actor": "owner_dave",
                "action": "rotate",
                "reason": "Containment for closure test",
                "expected_revision": f_res["revision"]
            }, headers=self.auth_headers(TOKEN_DAVE), timeout=3).json()
            requests.post(f"{CONTROL_URL}/api/operations/{dec_res['operation']['id']}/execute", json={
                "execution_identity": "lead_responder"
            }, headers=self.auth_headers(TOKEN_LEAD_RESPONDER), timeout=20)

            latest_inc = requests.get(f"{CONTROL_URL}/api/incidents/{inc_id}", headers=self.auth_headers(TOKEN_ADMIN), timeout=3).json()

            # Now close properly
            ok_close = requests.post(f"{CONTROL_URL}/api/incidents/{inc_id}/close", headers=self.auth_headers(TOKEN_LEAD_RESPONDER), json={
                "actor": "lead_responder",
                "recovery_disposition": "healthy_rotation_verified",
                "investigation_limitations": "Tested internal PostgreSQL connection cutover",
                "recurrence_owner": "owner_dave",
                "expected_revision": latest_inc["revision"]
            }, timeout=3)
            self.record_assertion("A18", "Closure succeeds when verified containment and all dispositions are recorded",
                                  ok_close.status_code == 200 and ok_close.json()["case_status"] == "closed", ok_close.json())

            self.results["A18"] = "FAIL" if self.scenario_failed.get("A18") else "PASS"
        except Exception as e:
            self.record_assertion("A18", f"A18 execution failed: {e}", False, {"error": str(e)})
            self.results["A18"] = "FAIL"

    def run_a19(self):
        print("\n--- Scenario A19: Historical finding replay after rotation ---")
        try:
            # 1. Query Vault static role metadata before replaying historical finding
            headers = self.auth_headers(TOKEN_ADMIN)
            headers_scanner = self.auth_headers(TOKEN_SCANNER)

            # Fetch actual revoked legacy credential version from control plane database or API
            # A historical replay must use a real revoked version. A placeholder
            # fingerprint would only test unmatched-finding behavior.
            revoked_fp = None
            import psycopg2
            try:
                db_url = os.getenv("CONTROL_DB_URL") or LOCAL_ENV.get("CONTROL_DB_URL")
                if not db_url:
                    password = LOCAL_ENV.get("CONTROL_DB_PASSWORD")
                    if not password:
                        raise RuntimeError("CONTROL_DB_PASSWORD is required for A19")
                    db_url = f"postgresql://control_user:{quote(password, safe='')}@127.0.0.1:5432/controldb"
                conn = psycopg2.connect(db_url)
                with conn.cursor() as cur:
                    cur.execute("SELECT hmac_fingerprint FROM credential_versions WHERE credential_id='cred-svc-legacy' AND status='revoked' ORDER BY created_at ASC LIMIT 1")
                    row = cur.fetchone()
                    if row and row[0]:
                        revoked_fp = row[0]
                conn.close()
            except Exception as dberr:
                print(f"DB lookup note: {dberr}")

            # Baseline check: read static role timestamp from Vault
            import orchestrator
            token = orchestrator.get_vault_token()
            vault_before = orchestrator.issuer_adapter.read_static_role("legacy-app-role", token)
            last_rot_before = vault_before.get("last_vault_rotation")

            if not revoked_fp:
                raise RuntimeError("No revoked legacy credential version is available for historical replay")

            # 2. Replay finding with actual revoked credential fingerprint
            f_res = requests.post(f"{CONTROL_URL}/api/findings", headers=headers_scanner, json={
                "event_id": f"evt-hist-{uuid.uuid4().hex[:6]}",
                "source": "historical_audit",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "old_backups/dump.sql",
                "fingerprint": revoked_fp,
                "claimed_service_hint": "svc-legacy",
                "detector_identity": "historical_scanner",
                "detector_version": "1.0"
            }, timeout=5).json()

            # 3. Read static role metadata from Vault after historical finding replay
            vault_after = orchestrator.issuer_adapter.read_static_role("legacy-app-role", token)
            last_rot_after = vault_after.get("last_vault_rotation")

            vault_unchanged = (last_rot_before == last_rot_after) and bool(last_rot_before)
            self.record_assertion("A19", "Replay of historical finding does not trigger blind rotation of active credential",
                                  f_res["case_status"] == "open" and f_res["containment_status"] == "pending", f_res)
            self.record_assertion("A19", "Vault issuer static rotation state remains strictly unchanged across historical replay",
                                  vault_unchanged,
                                  {"last_rotation_before": last_rot_before, "last_rotation_after": last_rot_after, "vault_unchanged": vault_unchanged})

            self.results["A19"] = "FAIL" if self.scenario_failed.get("A19") else "PASS"
        except Exception as e:
            self.record_assertion("A19", f"A19 execution failed: {e}", False, {"error": str(e)})
            self.results["A19"] = "FAIL"

    def run_a20(self):
        print("\n--- Scenario A20: Duplicate findings & execution idempotency ---")
        try:
            evt_id = f"evt-dup-{uuid.uuid4().hex[:6]}"
            f1 = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": evt_id,
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "logs/dup.log",
                "claimed_service_hint": "svc-legacy",
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()

            # Resend duplicate event sequentially
            f2 = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": evt_id,
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "logs/dup.log",
                "claimed_service_hint": "svc-legacy",
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()

            self.record_assertion("A20", "Duplicate finding accepted idempotently and references existing incident",
                                  f2.get("status") == "duplicate_accepted" and f2.get("incident_id") == f1["id"], f2)

            # Concurrent execution test (REQ029, REQ034)
            c_evt_id = f"evt-concurrent-{uuid.uuid4().hex[:6]}"
            concurrent_candidate = self.legacy_candidate()
            def post_concurrent_finding(i):
                return requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                    "event_id": c_evt_id,
                    "source": "gitleaks",
                    "detected_at": datetime.now(timezone.utc).isoformat(),
                    "locator": "logs/concurrent.log",
                    "claimed_service_hint": "svc-legacy",
                    "candidate_ref": concurrent_candidate,
                    "detector_identity": "gitleaks",
                    "detector_version": "8.24.0"
                }, timeout=5).json()

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                concurrent_res = list(executor.map(post_concurrent_finding, range(4)))

            matched_inc_ids = set()
            for r in concurrent_res:
                if "id" in r:
                    matched_inc_ids.add(r["id"])
                elif "incident_id" in r:
                    matched_inc_ids.add(r["incident_id"])

            self.record_assertion("A20", "Concurrent duplicate findings resolve to exactly one unique incident record",
                                  len(matched_inc_ids) == 1, {"concurrent_responses": len(concurrent_res), "incident_ids": list(matched_inc_ids)})

            if len(matched_inc_ids) != 1:
                raise RuntimeError("Concurrent finding correlation failed")
            incident_id = next(iter(matched_inc_ids))
            incident = requests.get(f"{CONTROL_URL}/api/incidents/{incident_id}", headers=self.auth_headers(TOKEN_ADMIN), timeout=5).json()
            decision = requests.post(f"{CONTROL_URL}/api/incidents/{incident_id}/decisions", headers=self.auth_headers(TOKEN_DAVE),
                json={"actor":"owner_dave", "action":"rotate", "reason":"Concurrent execution acceptance", "expected_revision":incident["revision"]}, timeout=5)
            decision.raise_for_status()
            operation_id = decision.json()["operation"]["id"]
            operation_headers = self.auth_headers(TOKEN_SEC_RESPONDER)
            def execute_same(_):
                response = requests.post(f"{CONTROL_URL}/api/operations/{operation_id}/execute", headers=operation_headers,
                    json={"execution_identity":"sec_responder"}, timeout=60)
                response.raise_for_status()
                return response.json()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                executions = list(executor.map(execute_same, range(4)))
            completed = [r for r in executions if r.get("status") == "completed"]
            self.record_assertion("A20", "Concurrent execution has one completion and only busy/idempotent duplicates",
                len(completed) == 1 and all(r.get("status") in ("completed", "busy", "already_completed") for r in executions),
                {"responses": executions})

            self.results["A20"] = "FAIL" if self.scenario_failed.get("A20") else "PASS"
        except Exception as e:
            self.record_assertion("A20", f"A20 execution failed: {e}", False, {"error": str(e)})
            self.results["A20"] = "FAIL"

    def run_a21(self):
        print("\n--- Scenario A21: Worker crash reconciliation ---")
        try:
            baseline = requests.post(f"{CONTROL_URL}/api/internal/reconcile-static-legacy",
                                     headers=self.auth_headers(TOKEN_ADMIN), timeout=10)
            baseline.raise_for_status()
            # Create incident and decision
            f_res = requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id": f"evt-reconcile-{uuid.uuid4().hex[:6]}",
                "source": "gitleaks",
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "locator": "code/interrupted.py",
                "claimed_service_hint": "svc-legacy",
                "candidate_ref": self.current_legacy_candidate(),
                "detector_identity": "gitleaks",
                "detector_version": "8.24.0"
            }, timeout=3).json()

            dec_res = requests.post(f"{CONTROL_URL}/api/incidents/{f_res['id']}/decisions", json={
                "actor": "owner_dave",
                "action": "rotate",
                "reason": "Worker interruption test",
                "expected_revision": f_res["revision"]
            }, headers=self.auth_headers(TOKEN_DAVE), timeout=3).json()
            op_id = dec_res["operation"]["id"]

            # 1. Hold the actual worker after the issuer mutation but before it
            # records completion/interruption, then kill that in-flight worker.
            def execute_to_barrier():
                try:
                    requests.post(f"{CONTROL_URL}/api/operations/{op_id}/execute?pause_after_issuer_effect=true", json={
                        "execution_identity": "sec_responder"
                    }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=70)
                except requests.RequestException:
                    pass
            worker = threading.Thread(target=execute_to_barrier, daemon=True)
            worker.start()
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                state = requests.get(f"{CONTROL_URL}/api/operations/{op_id}", headers=self.auth_headers(TOKEN_ADMIN), timeout=5).json()
                if (state.get("params") or {}).get("phase") == "issuer_effect_barrier":
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("A21 worker did not reach post-issuer barrier")
            subprocess.run(["docker", "kill", container("control-api")], capture_output=True, text=True, check=True)
            killed = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", container("control-api")],
                                    capture_output=True, text=True, check=True).stdout.strip()
            # Restart only the exact worker that was killed. `compose up` may
            # recreate dependencies, which would invalidate the crash-window
            # test by sealing Vault or resetting the database connection.
            subprocess.run(["docker", "start", container("control-api")], capture_output=True, text=True, check=True)

            # Docker restarts the control worker. Do not infer recovery merely from
            # elapsed time: require the authenticated health endpoint to return.
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                try:
                    health = requests.get(f"{CONTROL_URL}/api/health", timeout=3)
                    if health.status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(1)
            else:
                raise RuntimeError("Control worker did not restart after A21 termination")
            self.record_assertion("A21", "Actual operation worker was terminated after issuer mutation and restarted",
                                  killed == "exited 137", {"worker_restarted": True, "operation_id": op_id,
                                                             "observed_exit": killed})

            # 2. Resume from durable intent and reconcile issuer state without a
            # second rotation.
            resume_res = requests.post(f"{CONTROL_URL}/api/operations/{op_id}/execute", json={
                "execution_identity": "sec_responder"
            }, headers=self.auth_headers(TOKEN_SEC_RESPONDER), timeout=60).json()
            self.record_assertion("A21", "Resumed worker reconciles external state and completes safely without blind second rotation",
                                  resume_res.get("status") == "completed" and resume_res.get("external_reconciled") is True and resume_res.get("old_credential_rejected") is True, resume_res)

            self.results["A21"] = "FAIL" if self.scenario_failed.get("A21") else "PASS"
        except Exception as e:
            self.record_assertion("A21", f"A21 execution failed: {e}", False, {"error": str(e)})
            self.results["A21"] = "FAIL"

    def run_a22(self):
        print("\n--- Scenario A22: Actual workload and scanner privilege denials ---")
        try:
            denied = requests.post(f"{CONTROL_URL}/api/operations/nonexistent/execute",
                headers=self.auth_headers(TOKEN_SCANNER), json={"execution_identity":"gitleaks"}, timeout=5)
            self.record_assertion("A22", "Scanner cannot execute a privileged operation", denied.status_code == 403, {"status": denied.status_code})
            code = "import os,json; print(json.dumps({'bootstrap_readable':os.access('/poc/.bootstrap/vault_keys.json',os.R_OK), 'docker_socket':os.path.exists('/var/run/docker.sock')}))"
            boundary = subprocess.run(["docker", "exec", container("integrated-app"), "python3", "-c", code], capture_output=True, text=True, timeout=10)
            boundary.check_returncode()
            state = json.loads(boundary.stdout)
            self.record_assertion("A22", "Integrated app cannot read bootstrap root keys or Docker socket", not state["bootstrap_readable"] and not state["docker_socket"], state)
            code = "import main,requests,json; t=main.authenticate_vault(); r=requests.get(main.VAULT_ADDR+'/v1/database/static-creds/legacy-app-role',headers={'X-Vault-Token':t},verify=main.get_ca(),timeout=5); print(json.dumps({'status':r.status_code}))"
            cross = subprocess.run(["docker", "exec", container("integrated-app"), "python3", "-c", code], capture_output=True, text=True, timeout=12)
            cross.check_returncode()
            status = json.loads(cross.stdout.strip().splitlines()[-1])
            self.record_assertion("A22", "Integrated workload Vault identity cannot read legacy static credential", status.get("status") == 403, status)
            self.results["A22"] = "FAIL" if self.scenario_failed.get("A22") else "PASS"
        except Exception as exc:
            self.record_assertion("A22", "Live isolation checks completed", False, {"error": type(exc).__name__})
            self.results["A22"] = "FAIL"

    def run_a23(self):
        print("\n--- Scenario A23: Persistence across restart & confined reset ---")
        # A23 must exercise a real reset.  The verifier snapshots this source into
        # a disposable Compose project, so it cannot disrupt the lab under test.
        try:
            before = set(os.listdir(os.path.join(POC_DIR, "evidence"))) if os.path.isdir(os.path.join(POC_DIR, "evidence")) else set()
            check = subprocess.run(
                [sys.executable, os.path.join(POC_DIR, "scripts", "verify_a23_isolated.py")],
                capture_output=True, text=True, timeout=600,
            )
            after = set(os.listdir(os.path.join(POC_DIR, "evidence"))) if os.path.isdir(os.path.join(POC_DIR, "evidence")) else set()
            run_dirs = sorted(name for name in after - before if name.startswith("a23-"))
            details = {"verifier_exit_code": check.returncode, "evidence_run": run_dirs[-1] if run_dirs else None}
            if run_dirs:
                artifact = os.path.join(POC_DIR, "evidence", run_dirs[-1], "a23-isolated-lifecycle.json")
                with open(artifact) as handle:
                    lifecycle = json.load(handle)
                details.update({key: lifecycle[key] for key in ("failure_stage", "error_type") if key in lifecycle})
                if check.returncode == 0:
                    self.external_evidence.append({"scenario_id": "A23", "kind": "isolated_compose_lifecycle", "artifact": artifact, "result": lifecycle})
            self.record_assertion(
                "A23", "Disposable full-stack restart, unseal, scoped reset, and unrelated-workload sentinel all succeed",
                check.returncode == 0, details,
            )
            self.results["A23"] = "FAIL" if self.scenario_failed.get("A23") else "PASS"
            return
        except Exception as e:
            self.record_assertion("A23", f"A23 isolated lifecycle verifier failed: {e}", False, {"error": str(e)})
            self.results["A23"] = "FAIL"
            return

        # Retained below as historical diagnostics; the return above ensures
        # acceptance relies on the isolated behavioral verifier, not source text.
        try:
            # 1. Verify persistent volume bindings in compose file
            with open(os.path.join(POC_DIR, "docker-compose.yml"), "r") as f:
                content = f.read()
            has_volumes = "vault-data:" in content and "pg-data:" in content
            self.record_assertion("A23", "Docker compose defines isolated volumes for vault and postgres",
                                  has_volumes, {"vault-data": "vault-data:" in content, "pg-data": "pg-data:" in content})

            # 2. Record service count prior to database container restart
            svc_res_before = requests.get(f"{CONTROL_URL}/api/services", headers=self.auth_headers(TOKEN_ADMIN), timeout=3)
            svc_res_before.raise_for_status()
            ids_before = {row["id"] for row in svc_res_before.json()}
            count_before = len(ids_before)

            # 3. Live restart of stateful database container (Blocker #6)
            restarted = False
            try:
                d_res = subprocess.run(["docker", "restart", container("postgres")], capture_output=True, text=True, timeout=30)
                if d_res.returncode == 0:
                    restarted = True
                    time.sleep(3)
            except Exception as dex:
                print(f"Docker restart note: {dex}")

            # Re-query control plane to verify persistence across the restart
            persisted = False
            count_after = 0
            for _ in range(5):
                try:
                    time.sleep(1)
                    svc_res_after = requests.get(f"{CONTROL_URL}/api/services", headers=self.auth_headers(TOKEN_ADMIN), timeout=5)
                    if svc_res_after.status_code == 200:
                        count_after = len(svc_res_after.json())
                        persisted = restarted and bool(ids_before) and ids_before == {row["id"] for row in svc_res_after.json()}
                        break
                except Exception:
                    pass

            self.record_assertion("A23", "Stateful data tier accessible and returns persistent records across restart",
                                  persisted, {"restarted": restarted, "count_before": count_before, "count_after": count_after})

            # 4. Full stack unseal verification with persistent unseal key
            vault_keys_file = os.path.join(POC_DIR, ".bootstrap", "vault_keys.json")
            vault_unsealed = False
            unseal_details = {}
            if os.path.exists(vault_keys_file):
                with open(vault_keys_file, "r") as vkf:
                    vk_data = json.load(vkf)
                unseal_key = vk_data.get("keys", [None])[0]
                # Query Vault health
                v_health = requests.get(f"{VAULT_ADDR}/v1/sys/health", verify=CA_CERT, timeout=5)
                is_sealed = v_health.status_code == 503 or v_health.json().get("sealed") is True
                if is_sealed and unseal_key:
                    u_resp = requests.post(f"{VAULT_ADDR}/v1/sys/unseal", json={"key": unseal_key}, verify=CA_CERT, timeout=5)
                    vault_unsealed = (u_resp.status_code == 200 and not u_resp.json().get("sealed"))
                    unseal_details = {"performed_unseal": True, "sealed": u_resp.json().get("sealed")}
                else:
                    vault_unsealed = (v_health.status_code == 200 and not v_health.json().get("sealed"))
                    unseal_details = {"performed_unseal": False, "sealed": False, "status_code": v_health.status_code}

            self.record_assertion("A23", "Vault state verified and unseal sequence operates with persistent unseal key",
                                  vault_unsealed, unseal_details)

            # 5. Confined project reset scoping check
            # Verify Makefile reset command specifies -p $(PROJECT_NAME) and down -v
            makefile_path = os.path.join(POC_DIR, "Makefile")
            with open(makefile_path, "r") as mf:
                make_content = mf.read()
            confined_scoping = "docker compose -p $(PROJECT_NAME)" in make_content and "down -v" in make_content
            self.record_assertion("A23", "Confined reset targets only project namespace without affecting other Docker workloads",
                                  confined_scoping, {"confined_scoping": confined_scoping, "project_name": "poc"})

            self.results["A23"] = "FAIL" if self.scenario_failed.get("A23") else "PASS"
        except Exception as e:
            self.record_assertion("A23", f"A23 execution failed: {e}", False, {"error": str(e)})
            self.results["A23"] = "FAIL"

    def run_a24(self):
        print("\n--- Scenario A24: Missing scans, open cases and removed ownership ---")
        original_owner = None
        try:
            headers = self.auth_headers(TOKEN_ADMIN)
            def metrics():
                response = requests.get(f"{CONTROL_URL}/api/metrics", headers=headers, timeout=5)
                response.raise_for_status()
                return response.json()["metrics"]
            original_owner = requests.get(f"{CONTROL_URL}/api/services/svc-legacy", headers=headers, timeout=5).json()["owner_group"]
            before = metrics()
            ids = []
            for _ in range(2):
                response = requests.post(f"{CONTROL_URL}/api/scan-attempts", headers=headers,
                    json={"service_id":"svc-legacy", "due_at":(datetime.now(timezone.utc)-timedelta(seconds=60)).isoformat()}, timeout=5)
                response.raise_for_status()
                ids.append(response.json()["id"])
            response = requests.post(f"{CONTROL_URL}/api/scan-attempts/{ids[0]}/complete", headers=self.auth_headers(TOKEN_SCANNER),
                json={"outcome":"clean", "detector_version":"acceptance-controlled-1"}, timeout=5)
            response.raise_for_status()
            response = requests.post(f"{CONTROL_URL}/api/services/svc-legacy/owner", headers=headers, json={"owner_group":""}, timeout=5)
            response.raise_for_status()
            requests.post(f"{CONTROL_URL}/api/findings", headers=self.auth_headers(TOKEN_SCANNER), json={
                "event_id":"metrics-"+uuid.uuid4().hex, "source":"gitleaks", "detected_at":datetime.now(timezone.utc).isoformat(),
                "locator":"controlled-missing-owner", "claimed_service_hint":"svc-legacy", "detector_identity":"gitleaks", "detector_version":"8.24.0"}, timeout=5).raise_for_status()
            after = metrics()
            b,a=before["scan_coverage"],after["scan_coverage"]
            self.record_assertion("A24", "Missing scan remains in denominator after owner removal",
                a["expected"] == b["expected"]+2 and a["completed"] == b["completed"]+1 and a["missing"] == b["missing"]+1, {"before":b,"after":a})
            self.record_assertion("A24", "Open case duration and unresolved ownership remain visible",
                after["open_cases"] > before["open_cases"] and after["unresolved_ownership_count"] > before["unresolved_ownership_count"] and after["oldest_open_case_seconds"] is not None, after)
            self.results["A24"] = "FAIL" if self.scenario_failed.get("A24") else "PASS"
        except Exception as exc:
            self.record_assertion("A24", "Metric behavior checked", False, {"error":str(exc)})
            self.results["A24"] = "FAIL"
        finally:
            if original_owner is not None:
                response=requests.post(f"{CONTROL_URL}/api/services/svc-legacy/owner", headers=self.auth_headers(TOKEN_ADMIN), json={"owner_group":original_owner}, timeout=5)
                if not response.ok:
                    self.results["A24"] = "FAIL"

    def run_a25(self):
        print("\n--- Scenario A25: Real browser keyboard and viewport checks ---")
        try:
            from playwright.sync_api import sync_playwright
            target_dir = os.path.join(EVIDENCE_DIR, self.run_id)
            os.makedirs(target_dir, exist_ok=True)

            with sync_playwright() as browser_runtime:
                browser = browser_runtime.chromium.launch(headless=True)
                def tab_to(page, selector, limit=80):
                    for _ in range(limit):
                        if page.locator(selector).evaluate("el => el === document.activeElement"):
                            return True
                        page.keyboard.press("Tab")
                    return False

                def keyboard_fill(page, selector, value):
                    if not tab_to(page, selector):
                        raise RuntimeError(f"Keyboard could not reach {selector}")
                    page.keyboard.press("Meta+A" if sys.platform == "darwin" else "Control+A")
                    page.keyboard.type(value)

                def keyboard_select(page, selector, value):
                    if not tab_to(page, selector):
                        raise RuntimeError(f"Keyboard could not reach {selector}")
                    page.keyboard.type(value)
                    if page.locator(selector).input_value() != value:
                        raise RuntimeError(f"Keyboard could not select {value} in {selector}")

                def keyboard_activate(page, selector):
                    if not tab_to(page, selector):
                        raise RuntimeError(f"Keyboard could not reach {selector}")
                    page.keyboard.press("Enter")
                for width in (390, 1440):
                    page = browser.new_page(viewport={"width": width, "height": 900})
                    page.goto(CONTROL_URL, wait_until="domcontentloaded")
                    page.locator("#auth-dialog").wait_for(state="visible")
                    page.locator("#auth-account option").first.wait_for(state="attached")
                    if not page.locator("#auth-account").evaluate("el => el === document.activeElement"):
                        raise RuntimeError("Login dialog does not place initial keyboard focus on local account picker")
                    self.record_assertion("A25", f"Four human workflow roles are presented at {width}px",
                        page.locator("#auth-account option").all_text_contents() == [
                            "secops_admin (admin)", "alice (requester)", "owner_dave (approver)", "sec_responder (operator)"],
                        {"viewport": width, "accounts": page.locator("#auth-account option").all_text_contents()})
                    page.keyboard.press("Tab")
                    self.record_assertion("A25", f"Keyboard account picker reaches continue action at {width}px",
                        page.locator("#auth-form button[type='submit']").evaluate("el => el === document.activeElement"), {"viewport": width})
                    page.keyboard.press("Enter")
                    page.locator("#auth-dialog").wait_for(state="hidden")
                    page.keyboard.press("Tab")
                    focus = page.evaluate("({tag: document.activeElement.tagName, text: document.activeElement.textContent.slice(0,100)})")
                    self.record_assertion("A25", f"Keyboard reaches an interactive control after login at {width}px",
                        focus["tag"] in ("BUTTON", "A", "INPUT", "SELECT"), focus)
                    overflow = page.evaluate("document.documentElement.scrollWidth > innerWidth")
                    self.record_assertion("A25", f"Page has no horizontal viewport overflow at {width}px", not overflow, {"viewport": width})
                    page.screenshot(path=os.path.join(target_dir, f"ui-{width}.png"), full_page=True)
                    page.close()

                # Complete full keyboard journey on desktop viewport (1440px):
                # 1. Choose alice -> keyboard submit intake
                # 2. Switch user to owner_dave -> keyboard review & peer-approve intake
                # 3. Navigate incidents queue & evidence link via keyboard
                j_page = browser.new_page(viewport={"width": 1440, "height": 900})
                j_page.goto(CONTROL_URL, wait_until="domcontentloaded")
                j_page.locator("#auth-dialog").wait_for(state="visible")
                j_page.locator("#auth-account option").first.wait_for(state="attached")

                # Sign in as alice
                keyboard_select(j_page, "#auth-account", "alice")
                j_page.keyboard.press("Tab")
                j_page.keyboard.press("Enter")
                j_page.locator("#auth-dialog").wait_for(state="hidden")

                # Submit intake via keyboard
                test_svc_id = f"svc-kb-{uuid.uuid4().hex[:6]}"
                keyboard_activate(j_page, "#nav-btn-intake")
                j_page.locator("#intake-modal-overlay").wait_for(state="visible")
                keyboard_fill(j_page, "#m_svc_id", test_svc_id)
                keyboard_fill(j_page, "#m_svc_name", "Keyboard Journey Gateway")
                keyboard_fill(j_page, "#m_owner_grp", "orders_team")
                keyboard_activate(j_page, "#modal-intake-submit-btn")
                j_page.wait_for_function("document.querySelector('#modal-intake-status').innerText.includes('Successfully Submitted')")
                intakes = requests.get(f"{CONTROL_URL}/api/intakes", headers=self.auth_headers(TOKEN_ADMIN), timeout=5)
                intakes.raise_for_status()
                created = next((row for row in intakes.json() if row.get("payload", {}).get("service_id") == test_svc_id), None)
                created_ok = created is not None and created.get("status") in ("submitted", "draft")
                keyboard_activate(j_page, "#intake-modal-close-btn")
                j_page.locator("#intake-modal-overlay").wait_for(state="hidden")
                self.record_assertion("A25", "Keyboard service intake creation journey succeeds",
                                      created_ok, {"service_id": test_svc_id,
                                                   "intake_id": created.get("id") if created else None,
                                                   "status": created.get("status") if created else None})

                # Switch user to owner_dave
                keyboard_activate(j_page, "#session-switch")
                j_page.locator("#auth-dialog").wait_for(state="visible")
                keyboard_select(j_page, "#auth-account", "owner_dave")
                j_page.keyboard.press("Tab")
                j_page.keyboard.press("Enter")
                j_page.locator("#auth-dialog").wait_for(state="hidden")

                # Review & peer-approve intake via keyboard
                keyboard_activate(j_page, "#nav-btn-intakes-list")
                j_page.locator("#info-modal-overlay").wait_for(state="visible")
                j_page.locator("#intakes-table").wait_for(state="visible")
                approve_btn = j_page.locator(f'tr:has-text("{test_svc_id}") button:has-text("Approve")')
                approve_btn.wait_for(state="visible")
                keyboard_activate(j_page, f'tr:has-text("{test_svc_id}") button:has-text("Approve")')
                deadline = time.monotonic() + 10
                approved = None
                while time.monotonic() < deadline:
                    rows = requests.get(f"{CONTROL_URL}/api/intakes", headers=self.auth_headers(TOKEN_ADMIN), timeout=5).json()
                    approved = next((row for row in rows if row.get("id") == created["id"]), None)
                    if approved and approved.get("status") == "approved":
                        break
                    time.sleep(0.25)
                keyboard_activate(j_page, "#info-modal-close-btn")
                j_page.locator("#info-modal-overlay").wait_for(state="hidden")
                self.record_assertion("A25", "Keyboard peer intake approval journey succeeds",
                                      approved is not None and approved.get("status") == "approved",
                                      {"approved_service": test_svc_id, "approver": "owner_dave",
                                       "intake_id": created["id"], "persisted_status": approved.get("status") if approved else None})

                # Incidents queue navigation
                keyboard_activate(j_page, "#nav-btn-incidents")
                j_page.locator("#info-modal-overlay").wait_for(state="visible")
                j_page.locator('table th:has-text("Incident ID")').wait_for(state="visible", timeout=10000)
                has_inc_table = j_page.locator('table th:has-text("Incident ID")').is_visible()
                keyboard_activate(j_page, "#info-modal-close-btn")
                j_page.locator("#info-modal-overlay").wait_for(state="hidden")
                self.record_assertion("A25", "Keyboard incident queue triage navigation succeeds", has_inc_table, {})

                # Evidence must be fetched through the authenticated wrapper and
                # downloaded as JSON rather than following an unauthenticated link.
                with j_page.expect_download() as download_info:
                    keyboard_activate(j_page, "#nav-btn-evidence")
                download = download_info.value
                self.record_assertion("A25", "Authenticated Evidence Hub downloads exported JSON",
                                      download.suggested_filename == "credential-lifecycle-evidence.json",
                                      {"filename": download.suggested_filename})

                j_page.close()
                browser.close()

            self.results["A25"] = "FAIL" if self.scenario_failed.get("A25") else "PASS"
        except ImportError:
            self.results["A25"] = "INCOMPLETE (install Playwright and Chromium with make browser-setup)"
        except Exception as exc:
            self.record_assertion("A25", "Real browser checks completed", False, {"error": str(exc)})
            self.results["A25"] = "FAIL"

    def run_a26(self):
        print("\n--- Scenario A26: Verify Docker egress isolation and local issuer/target traffic ---")
        try:
            containers = tuple(container(service) for service in ("control-api", "vault", "postgres", "integrated-app", "spiffe-caller"))
            network_ids = set()
            for container_name in containers:
                info = json.loads(subprocess.check_output(["docker", "inspect", container_name], text=True))[0]
                network_ids.update(n["NetworkID"] for n in info["NetworkSettings"]["Networks"].values())
            networks = json.loads(subprocess.check_output(["docker", "network", "inspect", *sorted(network_ids)], text=True))
            isolated = bool(networks) and all(n["Internal"] for n in networks)
            self.record_assertion("A26", "Every attached core network blocks external routing", isolated,
                {"networks": [{"name": n["Name"], "internal": n["Internal"]} for n in networks]})
            if not isolated:
                self.results["A26"] = "FAIL"
                return
            probe = subprocess.run(["docker", "exec", container("control-api"), "python3", "-c",
                "import socket,sys; s=socket.socket(); s.settimeout(3); rc=s.connect_ex(('1.1.1.1',443)); sys.exit(0 if rc != 0 else 1)"], capture_output=True, text=True, timeout=8)
            self.record_assertion("A26", "Core process cannot connect to public IP over HTTPS", probe.returncode == 0,
                {"probe_exit": probe.returncode})
            for label, url in (("control", f"{CONTROL_URL}/api/health"), ("legacy business", f"{LEGACY_APP_URL}/health"),
                               ("integrated business", f"{INTEGRATED_APP_URL}/health"), ("mTLS business", f"{SPIFFE_CALLER_URL}/call")):
                response = requests.get(url, headers=self.auth_headers(TOKEN_ADMIN), timeout=5)
                self.record_assertion("A26", f"{label} succeeds with external routing unavailable", response.status_code == 200, {"status": response.status_code})
            self.results["A26"] = "FAIL" if self.scenario_failed.get("A26") else "PASS"
        except Exception as exc:
            self.record_assertion("A26", "Offline execution verified", False, {"error": str(exc)})
            self.results["A26"] = "FAIL"

    def run_all(self):
        scenarios = [
            self.run_a01, self.run_a02, self.run_a03, self.run_a04, self.run_a05,
            self.run_a06, self.run_a07, self.run_a08, self.run_a09, self.run_a10,
            self.run_a11, self.run_a12, self.run_a13, self.run_a14, self.run_a15,
            self.run_a16, self.run_a17, self.run_a18, self.run_a19, self.run_a20,
            self.run_a21, self.run_a22, self.run_a23, self.run_a24, self.run_a25,
            self.run_a26
        ]
        for s in scenarios:
            s()

        self.save_evidence()

    def save_evidence(self):
        target_dir = os.path.join(EVIDENCE_DIR, self.run_id)
        os.makedirs(target_dir, exist_ok=True)

        # 1. Events JSONL, strictly filtered to this run ID with no fallback.
        events_data = []
        try:
            ev_resp = requests.get(f"{CONTROL_URL}/api/evidence?run_id={self.run_id}", headers=self.auth_headers(TOKEN_ADMIN), timeout=5)
            if ev_resp.status_code == 200:
                events_data = [e for e in ev_resp.json() if e.get("run_id") == self.run_id]
            with open(os.path.join(target_dir, "events.jsonl"), "w") as f:
                for ev in events_data:
                    f.write(json.dumps(ev, default=str) + "\n")
        except Exception as e:
            print(f"Warning: could not export events via API: {e}")

        # Index events by scenario_id for linking assertions (Blocker #6)
        events_by_scenario = {}
        for ev in events_data:
            s_id = ev.get("scenario_id")
            if s_id:
                events_by_scenario.setdefault(s_id, []).append(ev.get("id"))

        # Link assertions to corresponding evidence event IDs
        for a in self.assertions:
            scen = a.get("scenario_id")
            if scen in events_by_scenario:
                a["event_ids"] = events_by_scenario[scen]

        # 2. Assertions JSON
        with open(os.path.join(target_dir, "assertions.json"), "w") as f:
            json.dump(self.assertions, f, indent=2)
        with open(os.path.join(target_dir, "external-evidence.json"), "w") as f:
            json.dump(self.external_evidence, f, indent=2)

        # 3. Manifest JSON - derive exact revision dynamically (Blocker #6)
        git_sha = None
        try:
            git_res = subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=POC_DIR
            )
            if git_res.returncode == 0 and git_res.stdout.strip():
                git_sha = git_res.stdout.strip()
        except Exception:
            pass

        # Git HEAD alone does not identify untracked/modified implementation files.
        snapshot_after = source_snapshot()
        source_unchanged = snapshot_after["sha256"] == self.source_snapshot["sha256"]
        with open(os.path.join(target_dir, "source-files.json"), "w") as handle:
            json.dump(self.source_snapshot, handle, indent=2)
        if not source_unchanged:
            self.results["SOURCE"] = "INCOMPLETE (source changed during run)"
        if not events_data and not self.external_evidence:
            self.results["EVIDENCE"] = "INCOMPLETE (no correlated events exported)"
        detected_platform = platform.platform()

        manifest = {
            "run_id": self.run_id,
            "source_revision": git_sha,
            "source_snapshot_sha256": self.source_snapshot["sha256"],
            "source_unchanged_during_run": source_unchanged,
            "event_count": len(events_data),
            "external_evidence_count": len(self.external_evidence),
            "platform": detected_platform,
            "start_time": self.start_time,
            "end_time": datetime.now(timezone.utc).isoformat(),
            "scenarios": self.results
        }
        with open(os.path.join(target_dir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)

        # 4. Report Markdown
        pass_count = sum(1 for v in self.results.values() if v == "PASS")
        fail_count = sum(1 for v in self.results.values() if v == "FAIL")
        incomplete_count = sum(1 for v in self.results.values() if v.startswith("INCOMPLETE"))
        report_md = f"""# Acceptance Test Report: {self.run_id}

- **Platform:** {detected_platform}
- **Source Revision:** `{git_sha}`
- **Implementation snapshot SHA256:** `{self.source_snapshot["sha256"]}`
- **Execution Window:** {self.start_time} to {datetime.now(timezone.utc).isoformat()}
- **Summary:** {pass_count} Passed, {fail_count} Failed, {incomplete_count} Incomplete

## Core Scenarios (A01–A26)

| Scenario | Requirement | Status | Evidence |
| -------- | ----------- | ------ | -------- |
"""
        for k in sorted(self.results.keys()):
            if k.startswith("A"):
                status = self.results[k]
                report_md += f"| {k} | REQ-Core | **{status}** | assertions.json, events.jsonl |\n"

        with open(os.path.join(target_dir, "report.md"), "w") as f:
            f.write(report_md)

        # Also write latest evidence link
        latest_file = os.path.join(EVIDENCE_DIR, "latest_run.txt")
        with open(latest_file, "w") as f:
            f.write(self.run_id)

        print(f"\nEvidence package saved to: {target_dir}")
        print(f"Summary: {pass_count} PASS, {fail_count} FAIL, {incomplete_count} INCOMPLETE")

if __name__ == "__main__":
    runner = ScenarioRunner(RUN_ID)
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        runner.run_all()
    elif len(sys.argv) > 2 and sys.argv[1] == "--scenario":
        targets = [t.strip() for t in sys.argv[2].split(",")]
        for target in targets:
            method_name = f"run_{target.lower()}"
            if hasattr(runner, method_name):
                getattr(runner, method_name)()
            else:
                runner.results[target] = "FAIL"
                print(f"Unknown scenario: {target}")
        runner.save_evidence()
    else:
        runner.run_all()

    # Exit nonzero if any scenario failed
    has_failures = any(v != "PASS" and not (k.startswith("X") and v.startswith("SKIPPED")) for k, v in runner.results.items())
    sys.exit(1 if has_failures else 0)
