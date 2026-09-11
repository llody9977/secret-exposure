#!/usr/bin/env python3
"""Prove A01 from a fresh source tree and independent Docker image/project."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import requests


POC_DIR = Path(__file__).resolve().parents[1]
EXCLUDED = {".bootstrap", ".vault-data", "evidence", ".env", "__pycache__", ".pytest_cache"}


def run(command, *, cwd, env, timeout=600):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout)[-1800:]
        raise RuntimeError(f"command failed ({' '.join(command)}): {detail}")
    return result


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_health(url, seconds=120):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(url, timeout=4)
            if response.status_code == 200 and response.json().get("status") == "healthy":
                return
            last_error = f"HTTP {response.status_code}"
        except requests.RequestException as exc:
            last_error = type(exc).__name__
        time.sleep(1)
    raise RuntimeError(f"control-plane health check did not succeed: {last_error}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="retain the failed disposable source tree for diagnosis")
    args = parser.parse_args()
    run_id = f"a01-{uuid.uuid4().hex[:10]}"
    project = run_id.replace("-", "")
    image = f"{run_id}-base:latest"
    sandbox = Path(tempfile.mkdtemp(prefix=f"secret-exposure-{run_id}-")) / "poc"
    evidence_dir = POC_DIR / "evidence" / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    port_map = {
        "INGRESS_POSTGRES_PORT": str(port()), "INGRESS_VAULT_PORT": str(port()),
        "INGRESS_AUTHORITY_PORT": str(port()), "INGRESS_CONTROL_PORT": str(port()),
        "INGRESS_SUPERVISOR_PORT": str(port()), "INGRESS_LEGACY_PORT": str(port()),
        "INGRESS_INTEGRATED_PORT": str(port()), "INGRESS_SPIFFE_SERVICE_PORT": str(port()),
        "INGRESS_SPIFFE_CALLER_PORT": str(port()),
    }
    env = os.environ.copy()
    env.update(port_map)
    env.update({
        "PROJECT_NAME": project, "LAB_PREFIX": run_id, "BASE_IMAGE": image, "POC_BASE_IMAGE": image,
        "VAULT_ADDR": f"https://127.0.0.1:{port_map['INGRESS_VAULT_PORT']}",
        "CONTROL_ADDR": f"http://127.0.0.1:{port_map['INGRESS_CONTROL_PORT']}",
    })
    report = {"scenario": "A01", "run_id": run_id, "project": project, "image": image, "checks": [], "status": "FAIL"}
    stage = "copy_source"

    try:
        shutil.copytree(POC_DIR, sandbox, ignore=shutil.ignore_patterns(*EXCLUDED))
        absent = [name for name in EXCLUDED if (sandbox / name).exists()]
        if absent:
            raise RuntimeError(f"fresh source copy contains runtime state: {absent}")
        report["checks"].append({"name": "fresh source tree excludes generated runtime state", "passed": True})

        stage = "doctor"
        run(["make", "doctor"], cwd=sandbox, env=env, timeout=120)
        report["checks"].append({"name": "environment preflight succeeds", "passed": True})

        # This invokes the declared build and bootstrap targets against a unique
        # image and Compose project, preventing reuse of the active lab state.
        stage = "bootstrap"
        run(["make", "bootstrap"], cwd=sandbox, env=env, timeout=900)
        stage = "start_services"
        run(["make", "up"], cwd=sandbox, env=env, timeout=300)
        stage = "health_check"
        wait_for_health(f"http://127.0.0.1:{port_map['INGRESS_CONTROL_PORT']}/api/health")
        stage = "image_inspection"
        image_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", image], cwd=sandbox, env=env).stdout.strip()
        report["checks"].append({"name": "fresh image build, bootstrap, and isolated health check succeed", "passed": bool(image_id), "image_id": image_id})
        report["status"] = "PASS"
    except Exception as exc:
        # Evidence and CI logs intentionally carry only a stage and exception
        # class. Command output can contain bootstrap-local credentials.
        report["failure_stage"] = stage
        report["error_type"] = type(exc).__name__
        raise
    finally:
        (evidence_dir / "a01-clean-install.json").write_text(json.dumps(report, indent=2) + "\n")
        if not args.keep:
            subprocess.run(["docker", "compose", "-p", project, "-f", str(sandbox / "docker-compose.yml"), "down", "-v", "--remove-orphans"], text=True, capture_output=True, env=env)
            shutil.rmtree(sandbox.parent, ignore_errors=True)


if __name__ == "__main__":
    main()
