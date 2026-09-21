import os
import re
import uuid
import json
import time
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import requests

from database import get_connection
from adapters.validator import ValidatorAdapter

_remediation_lock = threading.Lock()

POC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GITLAB_INTERNAL_URL = os.getenv("GITLAB_INTERNAL_URL", "http://lab-gitlab:8929")
GITLAB_EXTERNAL_URL = os.getenv("GITLAB_EXTERNAL_URL", "http://localhost:8929")

_GITLAB_ACCESS_FILE = os.path.join(POC_DIR, ".bootstrap", "gitlab_access.json")


def _gitlab_access():
    """Per-deployment GitLab API token and project id, provisioned by
    scripts/gitlab_setup.py during `make up`. Read lazily on each call so the
    running control plane picks the file up without a restart; falls back to the
    environment, then to inert defaults (dashboard runs in simulated mode)."""
    try:
        with open(_GITLAB_ACCESS_FILE) as f:
            d = json.load(f)
        return (d.get("token") or os.getenv("GITLAB_TOKEN", "glpat-unprovisioned"),
                str(d.get("project_id") or os.getenv("GITLAB_PROJECT_ID", "1")))
    except Exception:
        return (os.getenv("GITLAB_TOKEN", "glpat-unprovisioned"),
                os.getenv("GITLAB_PROJECT_ID", "1"))


def gl_token():
    return _gitlab_access()[0]


def gl_project_id():
    return _gitlab_access()[1]

validator_adapter = ValidatorAdapter()

class GitLabSimulator:
    """
    Connects to the official GitLab CE server and runner to execute real
    CI/CD pipelines with Gitleaks security scans, while maintaining
    correlation with the Authoritative CMDB and Incident Management system.
    """

    def trigger_pipeline(self, project_id: str, commit_sha: str, commit_message: str,
                         diff_content: str, branch: str = "main") -> Dict[str, Any]:
        detected_secrets = self._scan_diff(diff_content)
        is_leak = len(detected_secrets) > 0

        real_pipeline = None
        gl_headers = {"PRIVATE-TOKEN": gl_token(), "Content-Type": "application/json"}

        # 1. Push real commit to GitLab CE repository to trigger pipeline on runner
        try:
            if is_leak:
                leak_val = detected_secrets[0]
                config_content = (
                    "# Production Database Configuration\n"
                    "production:\n"
                    "  adapter: postgresql\n"
                    "  database: customer_db_prod\n"
                    "  username: app_user\n"
                    f'  password: "{leak_val}"\n'
                    "  host: db.internal.corp\n"
                    f"  # Exposure timestamp: {datetime.now(timezone.utc).isoformat()}\n"
                )
                action_msg = f"feat(config): update database settings with static secret [leak exposure {uuid.uuid4().hex[:6]}]"
            else:
                config_content = (
                    "# Production Database Configuration\n"
                    "production:\n"
                    "  adapter: postgresql\n"
                    "  database: customer_db_prod\n"
                    "  username: app_user\n"
                    "  password: <%= ENV['DATABASE_PASSWORD'] %>\n"
                    "  host: db.internal.corp\n"
                    f"  # Clean update timestamp: {datetime.now(timezone.utc).isoformat()}\n"
                )
                action_msg = f"chore(clean): verified clean configuration without secrets [{uuid.uuid4().hex[:6]}]"

            # Create commit in GitLab via Commits API
            commit_payload = {
                "branch": branch,
                "commit_message": commit_message or action_msg,
                "actions": [
                    {
                        "action": "update",
                        "file_path": "config/database.yml",
                        "content": config_content
                    }
                ]
            }
            commit_url = f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/repository/commits"
            c_res = requests.post(commit_url, json=commit_payload, headers=gl_headers, timeout=6)

            if c_res.status_code in (200, 201):
                c_data = c_res.json()
                commit_sha = c_data.get("id", commit_sha)

                # Wait for GitLab to generate the CI/CD pipeline for this commit
                for _ in range(8):
                    time.sleep(0.7)
                    pipe_res = requests.get(
                        f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/pipelines?ref={branch}&per_page=1",
                        headers=gl_headers,
                        timeout=4
                    )
                    if pipe_res.status_code == 200:
                        pipes = pipe_res.json()
                        if pipes and pipes[0].get("sha") == commit_sha:
                            real_pipeline = pipes[0]
                            break
        except Exception as ex:
            print(f"[WARN] GitLab CE API unavailable: {ex}. Proceeding with simulated execution.")

        if real_pipeline:
            pipeline_id = str(real_pipeline["id"])
            pipeline_iid = str(real_pipeline.get("iid", pipeline_id))
            web_url = f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/pipelines/{pipeline_id}"
            commit_sha = real_pipeline.get("sha", commit_sha)
        else:
            pipeline_id = f"gl-pipe-{uuid.uuid4().hex[:8]}"
            pipeline_iid = pipeline_id
            web_url = f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/pipelines"

        # Define the initial local pipeline stages.
        init_stages = [
            {"name": "build", "status": "running", "duration_s": 0},
            {"name": "secret-detect", "status": "pending", "duration_s": 0},
            {"name": "deploy", "status": "pending", "duration_s": 0}
        ]
        init_status = "running"
        incident_id = None
        cmdb_context = None

        # Pre-correlate CMDB context if secret is detected in diff
        if is_leak:
            cand_secret = detected_secrets[0]
            cmdb_context = self._correlate_secret_with_cmdb(cand_secret, project_id)

        # Persist pipeline in database with initial running state
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO gitlab_pipelines
            (id, project_id, ref, commit_sha, status, stages, scan_findings, incident_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE
            SET status = EXCLUDED.status, stages = EXCLUDED.stages, scan_findings = EXCLUDED.scan_findings, updated_at = NOW()
            RETURNING *
        """, (
            pipeline_id, project_id, branch, commit_sha, init_status,
            json.dumps(init_stages), json.dumps(detected_secrets), incident_id
        ))
        conn.commit()
        cur.close()
        conn.close()

        return {
            "pipeline_id": pipeline_id,
            "pipeline_iid": pipeline_iid,
            "project_id": project_id,
            "commit_sha": commit_sha,
            "status": init_status,
            "stages": init_stages,
            "blocked": False,
            "detected_secrets_count": len(detected_secrets),
            "cmdb_context": cmdb_context,
            "incident_id": incident_id,
            "web_url": web_url
        }


    def _scan_diff(self, diff: str) -> List[str]:
        leaks = []
        patterns = [
            r"LAB_SEC_[A-Z0-9_]+",
            r"(?:api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?([^'\"\s\r\n]{8,})['\"]?"
        ]
        for pat in patterns:
            matches = re.findall(pat, diff, re.IGNORECASE)
            for m in matches:
                leaks.append(m if isinstance(m, str) else m[0])
        return leaks

    def _correlate_secret_with_cmdb(self, candidate_secret: str, project_hint: str) -> Dict[str, Any]:
        """Look up secret in single source of truth to tie to application, owner, and classification"""
        from hmac_service import compute_fingerprint
        fp = compute_fingerprint(candidate_secret, "v1")

        conn = get_connection()
        cur = conn.cursor()
        # 1. Match HMAC fingerprint
        cur.execute("""
            SELECT cv.*, c.service_id, s.name as service_name, s.owner_group,
                   s.classification, s.data_classification, s.network_exposure,
                   s.auto_rotation_support, s.secret_manager_ref, s.target_resource
            FROM credential_versions cv
            JOIN credentials c ON cv.credential_id = c.credential_id
            JOIN services s ON c.service_id = s.id
            WHERE cv.hmac_fingerprint = %s
            LIMIT 1
        """, (fp,))
        row = cur.fetchone()

        # 2. Fallback to service repository correlation if fingerprint is new
        if not row:
            cur.execute("""
                SELECT id as service_id, name as service_name, owner_group,
                       classification, data_classification, network_exposure,
                       auto_rotation_support, secret_manager_ref, target_resource
                FROM services
                WHERE id = %s OR gitlab_repo_url LIKE %s
                ORDER BY CASE WHEN id = %s THEN 0 ELSE 1 END
                LIMIT 1
            """, (project_hint, f"%{project_hint}%", project_hint))
            row = cur.fetchone()

        cur.close()
        conn.close()

        if row:
            return dict(row)
        return {
            "service_id": project_hint,
            "owner_group": "security_fallback",
            "classification": "unknown",
            "data_classification": "Restricted",
            "network_exposure": "Internal",
            "auto_rotation_support": False,
            "target_resource": "db.internal.corp:5432/appdb"
        }

    def validate_secret(self, candidate_secret: str, cmdb_context: Dict[str, Any]) -> Dict[str, Any]:
        """Live verification of candidate secret against target resource (REQ030)"""
        target_resource = cmdb_context.get("target_resource") or "db.internal.corp:5432/appdb"
        if "postgres" in target_resource or "db.internal.corp" in target_resource or "5432" in target_resource:
            # Test against target database
            res = validator_adapter.validate_credential(target_resource, "legacy_user", candidate_secret)
            if res.get("status") == "active":
                return {**res, "target_resource": target_resource, "tested_account": "legacy_user"}
            res2 = validator_adapter.validate_credential(target_resource, "app_user", candidate_secret)
            if res2.get("status") == "active":
                return {**res2, "target_resource": target_resource, "tested_account": "app_user"}
            return {**res, "target_resource": target_resource, "tested_account": "legacy_user"}
        return {
            "status": "unsupported",
            "reason": f"Target resource '{target_resource}' does not support live probe verification.",
            "target_resource": target_resource,
            "tested_account": "none"
        }

    def remediate_git_file(self, branch: str = "main", file_path: str = "config/database.yml", action: str = "clean", original_pipeline_id: Optional[str] = None) -> Dict[str, Any]:
        """Remediate Git repository by scrubbing the secret or deleting the file via Commits API"""
        with _remediation_lock:
            # Idempotency guard: prevent duplicate remediation commits on same pipeline
            if original_pipeline_id:
                conn_chk = get_connection()
                cur_chk = conn_chk.cursor()
                cur_chk.execute("SELECT remediated_by_pipeline_id FROM gitlab_pipelines WHERE id = %s", (original_pipeline_id,))
                existing_row = cur_chk.fetchone()
                if existing_row and existing_row.get("remediated_by_pipeline_id") and existing_row["remediated_by_pipeline_id"] not in ("in_progress", None):
                    already_id = existing_row["remediated_by_pipeline_id"]
                    cur_chk.close()
                    conn_chk.close()
                    return {
                        "success": True,
                        "action": action,
                        "new_pipeline_id": already_id,
                        "new_pipeline_url": f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/pipelines/{already_id}",
                        "original_pipeline_id": original_pipeline_id,
                        "message": f"Pipeline #{original_pipeline_id} has already been remediated by clean Pipeline #{already_id}."
                    }
                # Mark in_progress immediately
                cur_chk.execute("UPDATE gitlab_pipelines SET remediated_by_pipeline_id = 'in_progress', updated_at = NOW() WHERE id = %s", (original_pipeline_id,))
                conn_chk.commit()
                cur_chk.close()
                conn_chk.close()

            gl_headers = {"PRIVATE-TOKEN": gl_token(), "Content-Type": "application/json"}
            commit_url = f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/repository/commits"

            timestamp_str = datetime.now(timezone.utc).isoformat()
            if action == "delete":
                actions = [{
                    "action": "delete",
                    "file_path": file_path
                }]
                commit_msg = f"security(remediation-bot): remove leaked secret file {file_path}"
            else:
                clean_config = (
                    "# Production Database Configuration (Remediated by SecOps Bot)\n"
                    "production:\n"
                    "  adapter: postgresql\n"
                    "  database: customer_db_prod\n"
                    "  username: app_user\n"
                    "  password: <%= ENV['DATABASE_PASSWORD'] %>\n"
                    "  host: db.internal.corp\n"
                    f"  # Remediated clean timestamp: {timestamp_str}\n"
                )
                actions = [{
                    "action": "update",
                    "file_path": file_path,
                    "content": clean_config
                }]
                commit_msg = f"chore(remediation-bot): sanitize {file_path} with environment variable template"

            commit_payload = {
                "branch": branch,
                "commit_message": commit_msg,
                "actions": actions
            }
            try:
                r = requests.post(commit_url, json=commit_payload, headers=gl_headers, timeout=6)
                if r.status_code not in (200, 201):
                    if original_pipeline_id:
                        conn_f = get_connection()
                        cur_f = conn_f.cursor()
                        cur_f.execute("UPDATE gitlab_pipelines SET remediated_by_pipeline_id = NULL WHERE id = %s", (original_pipeline_id,))
                        conn_f.commit()
                        cur_f.close()
                        conn_f.close()
                    return {"success": False, "status_code": r.status_code, "error": r.text, "action": action}

                commit_data = r.json()
                new_commit_sha = commit_data.get("id")

                # Wait for GitLab to generate the CI/CD pipeline for this clean commit
                new_pipeline = None
                for _ in range(12):
                    time.sleep(0.8)
                    pipe_res = requests.get(
                        f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/pipelines?ref={branch}&per_page=3",
                        headers=gl_headers,
                        timeout=4
                    )
                    if pipe_res.status_code == 200:
                        pipes = pipe_res.json()
                        for p in pipes:
                            if p.get("sha") == new_commit_sha:
                                new_pipeline = p
                                break
                        if new_pipeline:
                            break

                new_pipe_id = str(new_pipeline["id"]) if new_pipeline else None
                new_pipe_iid = str(new_pipeline.get("iid", new_pipe_id)) if new_pipeline else None
                new_pipe_url = f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/pipelines/{new_pipe_id}" if new_pipe_id else None

                # Register the new clean remediation pipeline in local database
                if new_pipe_id:
                    init_stages = [
                        {"name": "build", "status": "running", "duration_s": 0},
                        {"name": "secret-detect", "status": "pending", "duration_s": 0},
                        {"name": "deploy", "status": "pending", "duration_s": 0}
                    ]
                    conn = get_connection()
                    cur = conn.cursor()
                    cur.execute("""
                        INSERT INTO gitlab_pipelines
                        (id, project_id, ref, commit_sha, status, stages, scan_findings, incident_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE
                        SET status = EXCLUDED.status, stages = EXCLUDED.stages, updated_at = NOW()
                    """, (
                        new_pipe_id, "svc-legacy", branch, new_commit_sha, "running",
                        json.dumps(init_stages), json.dumps([]), None
                    ))

                    # Update original pipeline if specified
                    if original_pipeline_id:
                        cur.execute("""
                            UPDATE gitlab_pipelines
                            SET remediated_by_pipeline_id = %s,
                                remediation_details = %s,
                                updated_at = NOW()
                            WHERE id = %s
                        """, (
                            new_pipe_id,
                            json.dumps({
                                "action": action,
                                "remediated_commit_sha": new_commit_sha,
                                "new_pipeline_id": new_pipe_id,
                                "timestamp": timestamp_str
                            }),
                            original_pipeline_id
                        ))

                    conn.commit()
                    cur.close()
                    conn.close()

                return {
                    "success": True,
                    "commit": commit_data,
                    "action": action,
                    "file_path": file_path,
                    "new_commit_sha": new_commit_sha,
                    "new_pipeline_id": new_pipe_id,
                    "new_pipeline_iid": new_pipe_iid,
                    "new_pipeline_url": new_pipe_url,
                    "original_pipeline_id": original_pipeline_id,
                    "message": f"SecOps Bot pushed clean sanitized commit {new_commit_sha[:8] if new_commit_sha else ''} to branch '{branch}'. Fresh pipeline #{new_pipe_id} launched in GitLab!"
                }
            except Exception as ex:
                if original_pipeline_id:
                    try:
                        conn_f = get_connection()
                        cur_f = conn_f.cursor()
                        cur_f.execute("UPDATE gitlab_pipelines SET remediated_by_pipeline_id = NULL WHERE id = %s", (original_pipeline_id,))
                        conn_f.commit()
                        cur_f.close()
                        conn_f.close()
                    except Exception:
                        pass
                return {"success": False, "error": str(ex), "action": action}
            return {"success": False, "error": str(ex), "action": action}

    def _create_pipeline_incident(self, pipeline_id: str, project_id: str, secret: str, cmdb: Dict[str, Any]) -> str:
        conn = get_connection()
        cur = conn.cursor()
        inc_id = f"inc-gl-{uuid.uuid4().hex[:8]}"

        cur.execute("""
            INSERT INTO incidents (id, finding_id, service_id, credential_version_id,
                                  correlation_status, triage_status, containment_status,
                                  recovery_status, investigation_status, case_status,
                                  assigned_owner, revision)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            inc_id, f"pipeline-{pipeline_id}", cmdb.get("service_id"),
            cmdb.get("version_id"), "matched", "pending", "pending", "pending",
            "open", "open", cmdb.get("owner_group", "security_fallback"), 1
        ))
        conn.commit()
        cur.close()
        conn.close()
        return inc_id

    def list_pipelines(self) -> List[Dict[str, Any]]:
        """Fetch pipelines from real GitLab CE server, enriched with incidents from database"""
        gl_headers = {"PRIVATE-TOKEN": gl_token()}
        real_pipelines = []

        try:
            r = requests.get(
                f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/pipelines?per_page=15",
                headers=gl_headers,
                timeout=3
            )
            if r.status_code == 200:
                real_pipelines = r.json()
        except Exception:
            pass

        # Also get local database incidents and stages
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM gitlab_pipelines ORDER BY created_at DESC LIMIT 30")
        db_rows = {str(r["id"]): dict(r) for r in cur.fetchall()}
        cur.close()
        conn.close()

        if real_pipelines:
            result = []
            for p in real_pipelines:
                p_id = str(p["id"])
                db_record = db_rows.get(p_id, {})
                status_raw = p.get("status", "running")
                status = "blocked" if status_raw == "failed" else ("passed" if status_raw == "success" else status_raw)
                if db_record.get("status"):
                    status = db_record["status"]

                stages = db_record.get("stages") or [
                    {"name": "build", "status": "passed" if status in ("passed", "blocked") else "running"},
                    {"name": "secret-detect", "status": "failed" if status == "blocked" else ("passed" if status == "passed" else "running")},
                    {"name": "deploy", "status": "blocked" if status == "blocked" else ("passed" if status == "passed" else "pending")}
                ]

                result.append({
                    "id": p_id,
                    "iid": p.get("iid", p_id),
                    "project_id": "svc-legacy",
                    "ref": p.get("ref", "main"),
                    "commit_sha": p.get("sha", ""),
                    "status": status,
                    "stages": stages,
                    "detected_secrets_count": len(db_record.get("scan_findings") or []),
                    "validation_status": db_record.get("validation_status"),
                    "validation": db_record.get("validation_data") if isinstance(db_record.get("validation_data"), dict) else (json.loads(db_record["validation_data"]) if db_record.get("validation_data") else None),
                    "incident_id": db_record.get("incident_id"),
                    "web_url": f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/pipelines/{p_id}",
                    "created_at": p.get("created_at")
                })
            return result

        # Fallback to DB
        return list(db_rows.values())

    _DECIDED_STATUSES = {
        "passed", "blocked", "rejected", "approved_false_positive",
        "allowed_unrotated", "mitigated_rotated", "revoked_compromised", "sanitized_clean",
    }

    def _simulate_stages(self, db_record):
        """Deterministic stage progression for the local pipeline simulator.

        Returns (stages, status) derived from the pipeline's age and scan result, or
        None once a real outcome / SecOps decision is already persisted (so it is
        never overwritten). Real GitLab job data, if a runner is added later, still
        takes precedence in get_pipeline().
        """
        if not db_record:
            return None
        # Once a terminal/decided status is persisted, trust the stored stages.
        # While still "running" the progression is recomputed from elapsed time
        # (monotonic), so a partially-advanced stored record is fine to replace.
        if db_record.get("status") in self._DECIDED_STATUSES:
            return None
        db_stages = db_record.get("stages") or []
        if any(
            s.get("status") in (
                "revoked_compromised", "approved_false_positive", "mitigated_rotated",
                "allowed_unrotated", "rejected", "sanitized_clean",
            )
            for s in db_stages
        ):
            return None
        created = db_record.get("created_at")
        try:
            if isinstance(created, str):
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            elapsed = (datetime.now(timezone.utc) - created).total_seconds()
        except Exception:
            elapsed = 99.0
        has_leak = len(db_record.get("scan_findings") or []) > 0

        build = {"name": "build", "status": "running", "duration_s": 0}
        detect = {"name": "secret-detect", "status": "pending", "duration_s": 0}
        deploy = {"name": "deploy", "status": "pending", "duration_s": 0}
        status = "running"
        if elapsed >= 2:
            build["status"], build["duration_s"] = "passed", 2
            detect["status"] = "running"
        if elapsed >= 4:
            detect["duration_s"] = 2
            if has_leak:
                detect["status"], deploy["status"], status = "failed", "manual", "blocked"
            else:
                detect["status"] = "passed"
                deploy["status"], deploy["duration_s"], status = "passed", 3, "passed"
        return [build, detect, deploy], status

    def get_pipeline(self, pipeline_id: str) -> Optional[Dict[str, Any]]:
        """Fetch single pipeline live status and stage breakdown from real GitLab CE server"""
        gl_headers = {"PRIVATE-TOKEN": gl_token()}
        real_pipeline = None

        try:
            r = requests.get(
                f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/pipelines/{pipeline_id}",
                headers=gl_headers,
                timeout=4
            )
            if r.status_code == 200:
                real_pipeline = r.json()
        except Exception:
            pass

        # Also get local database record
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM gitlab_pipelines WHERE id = %s", (pipeline_id,))
        db_record = cur.fetchone()
        cur.close()
        conn.close()

        if not real_pipeline and not db_record:
            return None

        # Determine raw status from real GitLab pipeline if available
        status_raw = (real_pipeline or {}).get("status") or (db_record or {}).get("status", "running")
        status = "blocked" if status_raw == "failed" else ("passed" if status_raw == "success" else status_raw)

        # Query jobs to determine exact stage statuses
        stages = [
            {"name": "build", "status": "pending", "duration_s": 0},
            {"name": "secret-detect", "status": "pending", "duration_s": 0},
            {"name": "deploy", "status": "pending", "duration_s": 0}
        ]

        # The local simulator provides deterministic stage progression.
        # from pipeline age. Real job data (below) overrides this if a runner exists.
        is_simulated = False
        _sim = self._simulate_stages(db_record)
        if _sim:
            stages, status = _sim
            is_simulated = True
        elif db_record and db_record.get("stages"):
            stages = db_record["stages"]
            # With no runner the deploy job cannot report completion; once the
            # pipeline as a whole has passed, settle a still-"running" deploy stage.
            if status == "passed" and len(stages) >= 3 and stages[2].get("status") in ("running", "manual"):
                stages[2]["status"] = "passed"

        try:
            jr = requests.get(
                f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/pipelines/{pipeline_id}/jobs",
                headers=gl_headers,
                timeout=4
            )
            if jr.status_code == 200:
                jobs = jr.json()
                job_map = {j.get("name"): j for j in jobs}

                # Map build-job
                b_job = job_map.get("build-job")
                if b_job:
                    stages[0]["status"] = b_job.get("status", "pending")
                    stages[0]["duration_s"] = round(b_job.get("duration") or 0)
                    stages[0]["job_id"] = b_job.get("id")
                    stages[0]["job_url"] = f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/jobs/{b_job.get('id')}"

                # Map secret-detect-job
                s_job = job_map.get("secret-detect-job")
                if s_job:
                    s_status = s_job.get("status", "pending")
                    stages[1]["status"] = "failed" if s_status == "failed" else s_status
                    stages[1]["duration_s"] = round(s_job.get("duration") or 0)
                    stages[1]["job_id"] = s_job.get("id")
                    stages[1]["job_url"] = f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/jobs/{s_job.get('id')}"

                # Map deploy-job
                d_job = job_map.get("deploy-job")
                if d_job:
                    d_status = d_job.get("status", "pending")
                    stages[2]["status"] = "blocked" if (d_status == "skipped" and status == "blocked") else d_status
                    stages[2]["duration_s"] = round(d_job.get("duration") or 0)
                    stages[2]["job_id"] = d_job.get("id")
                    stages[2]["job_url"] = f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/jobs/{d_job.get('id')}"

                # If secret-detect failed or warned, OR if secrets were detected in scan_findings,
                # and deploy-job is waiting in 'manual' state,
                # pipeline status should reflect 'blocked' / awaiting approval unless already decided
                has_detected_secrets = bool(db_record and len(db_record.get("scan_findings") or []) > 0)
                if (stages[1]["status"] in ("failed", "warning") or has_detected_secrets) and stages[2]["status"] in ("manual", "blocked", "pending"):
                    if not (db_record and db_record.get("status") in ("passed", "approved_false_positive", "rejected")):
                        status = "blocked"
                        if stages[1]["status"] not in ("revoked_compromised", "approved_false_positive", "mitigated_rotated", "allowed_unrotated", "rejected"):
                            stages[1]["status"] = "failed"
        except Exception:
            if db_record and db_record.get("stages"):
                stages = db_record["stages"]

        # Preserve custom SecOps decision state for secret-detect stage if already resolved in DB
        if db_record and db_record.get("stages"):
            db_s = db_record["stages"]
            if len(db_s) >= 2 and db_s[1].get("status") in ("revoked_compromised", "approved_false_positive", "mitigated_rotated", "allowed_unrotated", "rejected", "sanitized_clean"):
                stages[1]["status"] = db_s[1].get("status")
            if db_record.get("status") in ("passed", "approved_false_positive") and status != "failed":
                status = "passed"
            elif db_record.get("status") == "rejected":
                status = "rejected"

        # Correlate secret with CMDB and perform live target verification only when secret-detect stage has run
        incident_id = (db_record or {}).get("incident_id")
        cmdb_context = None
        validation = None
        if db_record and db_record.get("scan_findings"):
            findings = db_record["scan_findings"]
            if findings:
                project_ref = (db_record or {}).get("project_id", "svc-legacy")
                cmdb_context = self._correlate_secret_with_cmdb(findings[0], project_ref)
                # Only validate against target database if secret-detect has started/executed, or pipeline is blocked/failed
                detect_has_executed = (
                    status in ("blocked", "failed", "rejected") or
                    (len(stages) >= 2 and stages[1].get("status") in ("running", "failed", "passed", "success", "revoked_compromised", "approved_false_positive", "mitigated_rotated", "allowed_unrotated", "rejected"))
                )
                if detect_has_executed:
                    saved_val_status = (db_record or {}).get("validation_status")
                    saved_val_data = (db_record or {}).get("validation_data")
                    if saved_val_status and saved_val_data:
                        validation = saved_val_data if isinstance(saved_val_data, dict) else json.loads(saved_val_data)
                    else:
                        validation = self.validate_secret(findings[0], cmdb_context)
                        try:
                            conn_v = get_connection()
                            cur_v = conn_v.cursor()
                            cur_v.execute("""
                                UPDATE gitlab_pipelines
                                SET validation_status = %s, validation_data = %s, updated_at = NOW()
                                WHERE id = %s
                            """, (validation.get("status"), json.dumps(validation), pipeline_id))
                            conn_v.commit()
                            cur_v.close()
                            conn_v.close()
                        except Exception:
                            pass

                    if not incident_id and status in ("blocked", "failed"):
                        incident_id = self._create_pipeline_incident(pipeline_id, project_ref, findings[0], cmdb_context)

        # Update gitlab_pipelines database record with latest status
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE gitlab_pipelines
                SET status = %s, stages = %s, incident_id = COALESCE(incident_id, %s), updated_at = NOW()
                WHERE id = %s
            """, (status, json.dumps(stages), incident_id, pipeline_id))
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            pass

        commit_sha = (real_pipeline or {}).get("sha") or (db_record or {}).get("commit_sha", "")
        remediated_by = (db_record or {}).get("remediated_by_pipeline_id")
        remediation_details = (db_record or {}).get("remediation_details")
        remediation_url = f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/pipelines/{remediated_by}" if remediated_by else None

        return {
            "pipeline_id": pipeline_id,
            "pipeline_iid": (real_pipeline or {}).get("iid", pipeline_id),
            "project_id": (db_record or {}).get("project_id", "svc-legacy"),
            "commit_sha": commit_sha,
            "status": status,
            "stages": stages,
            "simulated": is_simulated,
            "blocked": status == "blocked",
            "detected_secrets_count": len((db_record or {}).get("scan_findings") or []),
            "cmdb_context": cmdb_context,
            "validation": validation,
            "auto_rotation_supported": (cmdb_context or {}).get("auto_rotation_support", False),
            "incident_id": incident_id,
            "web_url": f"{GITLAB_EXTERNAL_URL}/root/legacy-customer-portal/-/pipelines/{pipeline_id}",
            "remediated_by_pipeline_id": remediated_by,
            "remediation_details": remediation_details,
            "remediation_pipeline_url": remediation_url
        }

    def play_manual_job(self, job_id: int) -> Dict[str, Any]:
        """Trigger native GitLab manual job play API (unblocks deploy in SAME pipeline)"""
        gl_headers = {"PRIVATE-TOKEN": gl_token()}
        url = f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/jobs/{job_id}/play"
        try:
            r = requests.post(url, headers=gl_headers, timeout=6)
            if r.status_code in (200, 201):
                return {"success": True, "job": r.json()}
            return {"success": False, "status_code": r.status_code, "error": r.text}
        except Exception as ex:
            return {"success": False, "error": str(ex)}

    def cancel_manual_job(self, job_id: Optional[int] = None, pipeline_id: Optional[str] = None) -> Dict[str, Any]:
        """Cancel native GitLab manual job or entire pipeline (permanently blocks deploy in SAME pipeline)"""
        gl_headers = {"PRIVATE-TOKEN": gl_token()}
        results = {}
        if job_id:
            try:
                jr = requests.post(f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/jobs/{job_id}/cancel", headers=gl_headers, timeout=6)
                results["job_cancel"] = jr.status_code in (200, 201)
            except Exception as ex:
                results["job_cancel_error"] = str(ex)
        if pipeline_id:
            try:
                pr = requests.post(f"{GITLAB_INTERNAL_URL}/api/v4/projects/{gl_project_id()}/pipelines/{pipeline_id}/cancel", headers=gl_headers, timeout=6)
                results["pipeline_cancel"] = pr.status_code in (200, 201)
            except Exception as ex:
                results["pipeline_cancel_error"] = str(ex)
        return {"success": True, "details": results}
