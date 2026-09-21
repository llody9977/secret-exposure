#!/usr/bin/env python3
"""Exercise A23 against a disposable Compose project, never the active lab."""

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
RUNTIME_NAMES = {".bootstrap", ".vault-data", "evidence", ".env", "__pycache__", ".pytest_cache"}


def run(command, *, cwd, env, timeout=180):
    result = subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout)[-1600:]
        raise RuntimeError(f"command failed ({' '.join(command)}): {detail}")
    return result


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(url, *, verify, expected, seconds=90):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            response = requests.get(url, verify=verify, timeout=4)
            if response.status_code in expected:
                return response
            last_error = f"HTTP {response.status_code}"
        except requests.RequestException as exc:
            last_error = type(exc).__name__
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {url}: {last_error}")


def compose_up(compose, *, cwd, env):
    """Start the PID-sharing caller only after its agent namespace is running."""
    services = run(compose + ["config", "--services"], cwd=cwd, env=env).stdout.splitlines()
    primary = [service for service in services if service not in {"spiffe-caller", "spiffe-service"}]
    last_error = None
    for _ in range(3):
        try:
            run(compose + ["up", "-d", *primary], cwd=cwd, env=env)
            agent = f"{env['LAB_PREFIX']}-spire-agent"
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                state = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", agent], capture_output=True, text=True)
                if state.returncode == 0 and state.stdout.strip() == "true":
                    # A short stable period avoids joining a namespace during
                    # the agent's first registration/restart cycle.
                    time.sleep(8)
                    stable = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", agent], capture_output=True, text=True)
                    if stable.returncode == 0 and stable.stdout.strip() == "true":
                        break
                time.sleep(1)
            else:
                raise RuntimeError("SPIRE agent did not reach a running state")
            run(compose + ["up", "-d", "--no-deps", "spiffe-service"], cwd=cwd, env=env)
            run(compose + ["up", "-d", "--no-deps", "spiffe-caller"], cwd=cwd, env=env)
            return
        except RuntimeError as exc:
            last_error = exc
            time.sleep(3)
    raise last_error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="keep the disposable source directory when a check fails")
    args = parser.parse_args()

    run_id = f"a23-{uuid.uuid4().hex[:10]}"
    project = run_id.replace("-", "")
    sandbox = Path(tempfile.mkdtemp(prefix=f"secret-exposure-{run_id}-")) / "poc"
    evidence_dir = POC_DIR / "evidence" / run_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    sentinel = f"{run_id}-sentinel"
    ports = {
        "INGRESS_POSTGRES_PORT": str(port()), "INGRESS_VAULT_PORT": str(port()),
        "INGRESS_AUTHORITY_PORT": str(port()), "INGRESS_CONTROL_PORT": str(port()),
        "INGRESS_SUPERVISOR_PORT": str(port()), "INGRESS_LEGACY_PORT": str(port()),
        "INGRESS_INTEGRATED_PORT": str(port()), "INGRESS_SPIFFE_SERVICE_PORT": str(port()),
        "INGRESS_SPIFFE_CALLER_PORT": str(port()),
    }
    env = os.environ.copy()
    env.update(ports)
    env.update({"PROJECT_NAME": project, "LAB_PREFIX": run_id, "POC_BASE_IMAGE": "poc-lab-base:latest"})
    env.update({
        "VAULT_ADDR": f"https://127.0.0.1:{ports['INGRESS_VAULT_PORT']}",
        "CONTROL_ADDR": f"http://127.0.0.1:{ports['INGRESS_CONTROL_PORT']}",
    })
    report = {"scenario": "A23", "run_id": run_id, "project": project, "checks": [], "status": "FAIL"}
    reset_completed = False
    stage = "copy_source"

    try:
        shutil.copytree(POC_DIR, sandbox, ignore=shutil.ignore_patterns(*RUNTIME_NAMES))
        stage = "generate_environment"
        run(["make", ".env"], cwd=sandbox, env=env)
        stage = "generate_tls"
        run(["./certs/generate_certs.sh"], cwd=sandbox, env=env)
        compose = ["docker", "compose", "-p", project, "-f", str(sandbox / "docker-compose.yml")]
        stage = "bootstrap_dependencies"
        run(compose + ["up", "-d", "postgres", "vault", "spire-server", "lab-ingress"], cwd=sandbox, env=env)
        stage = "bootstrap"
        run([sys.executable, "scripts/bootstrap.py"], cwd=sandbox, env=env)
        stage = "start_services"
        compose_up(compose, cwd=sandbox, env=env)
        stage = "seed_control_plane"
        run([sys.executable, "scripts/bootstrap.py", "--seed-only"], cwd=sandbox, env=env)

        control = f"http://127.0.0.1:{ports['INGRESS_CONTROL_PORT']}/api/health"
        stage = "initial_health_check"
        wait_for(control, verify=False, expected={200})
        report["checks"].append({"name": "initial isolated stack is healthy", "passed": True})

        stage = "start_sentinel"
        run(["docker", "run", "-d", "--name", sentinel, "--network", "none", "poc-lab-base:latest", "sleep", "600"], cwd=sandbox, env=env)
        report["checks"].append({"name": "unrelated workload sentinel started", "passed": True, "container": sentinel})

        stage = "restart_stack"
        run(compose + ["down"], cwd=sandbox, env=env)
        compose_up(compose, cwd=sandbox, env=env)
        vault = f"https://127.0.0.1:{ports['INGRESS_VAULT_PORT']}"
        ca_cert = sandbox / "certs" / "ca.pem"
        stage = "vault_health_after_restart"
        health = wait_for(f"{vault}/v1/sys/health", verify=str(ca_cert), expected={200, 429, 472, 473, 501, 503})
        if health.status_code == 503 or health.json().get("sealed"):
            stage = "unseal_after_restart"
            key_data = json.loads((sandbox / ".bootstrap" / "vault_keys.json").read_text())
            response = requests.post(f"{vault}/v1/sys/unseal", json={"key": key_data["keys"][0]}, verify=str(ca_cert), timeout=8)
            if response.status_code != 200 or response.json().get("sealed"):
                raise RuntimeError("Vault did not unseal after full-stack restart")
        stage = "seed_after_restart"
        run([sys.executable, "scripts/bootstrap.py", "--seed-only"], cwd=sandbox, env=env)
        stage = "health_after_restart"
        wait_for(control, verify=False, expected={200})
        report["checks"].append({"name": "full stack restart preserves and restores Vault-backed state", "passed": True})

        stage = "confined_reset"
        run(["make", "reset", "CONFIRM=yes"], cwd=sandbox, env=env)
        reset_completed = True
        stage = "sentinel_check"
        inspect = run(["docker", "inspect", "--format", "{{.State.Running}}", sentinel], cwd=sandbox, env=env)
        sentinel_running = inspect.stdout.strip() == "true"
        report["checks"].append({"name": "confined reset leaves unrelated workload running", "passed": sentinel_running, "container": sentinel})
        if not sentinel_running:
            raise RuntimeError("unrelated workload was affected by isolated reset")
        report["status"] = "PASS"
    except Exception as exc:
        # Keep failure evidence safe to archive and print: command output may
        # contain deployment-local credentials.
        report["failure_stage"] = stage
        report["error_type"] = type(exc).__name__
        raise
    finally:
        report["reset_completed"] = reset_completed
        (evidence_dir / "a23-isolated-lifecycle.json").write_text(json.dumps(report, indent=2) + "\n")
        subprocess.run(["docker", "rm", "-f", sentinel], text=True, capture_output=True)
        if not args.keep:
            subprocess.run(["docker", "compose", "-p", project, "-f", str(sandbox / "docker-compose.yml"), "down", "-v", "--remove-orphans"], text=True, capture_output=True, env=env)
            shutil.rmtree(sandbox.parent, ignore_errors=True)


if __name__ == "__main__":
    main()
