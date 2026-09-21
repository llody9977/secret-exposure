"""Narrow local authority for the single lab caller's SPIRE registration."""
import hmac
import json
import os
import subprocess
import threading

from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="Lab identity registration authority")
TOKEN = os.environ["IDENTITY_AUTHORITY_TOKEN"]
SOCKET = "/tmp/spire-server/private/api.sock"
CALLER = "spiffe://lab.local/workload/caller"
PARENT = "spiffe://lab.local/agent/node1"
LOCK = threading.Lock()


def authorize(authorization):
    if not authorization or not hmac.compare_digest(authorization, "Bearer " + TOKEN):
        raise HTTPException(status_code=401, detail="Invalid authority credentials")


def cli(*args):
    result = subprocess.run(["spire-server", "entry", *args, "-socketPath", SOCKET, "-output", "json"],
                            text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise HTTPException(status_code=502, detail="SPIRE registration operation failed")
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise HTTPException(status_code=502, detail="Invalid SPIRE registration response")


def entries():
    found = cli("show", "-spiffeID", CALLER).get("entries")
    if not isinstance(found, list):
        raise HTTPException(status_code=502, detail="Incomplete SPIRE registration response")
    for entry in found:
        if (entry.get("spiffe_id") != {"trust_domain": "lab.local", "path": "/workload/caller"}
                or entry.get("parent_id") != {"trust_domain": "lab.local", "path": "/agent/node1"}
                or entry.get("selectors") != [{"type": "unix", "value": "uid:1001"}]):
            raise HTTPException(status_code=409, detail="Caller registration differs from lab contract")
    return found


def status():
    found = entries()
    return {"spiffe_id": CALLER, "issuance_blocked": not bool(found), "entries": [entry["id"] for entry in found]}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/caller")
def caller(authorization: str = Header(None)):
    authorize(authorization)
    with LOCK:
        return status()


@app.post("/caller/disable")
def disable(authorization: str = Header(None)):
    authorize(authorization)
    with LOCK:
        for entry in entries():
            cli("delete", "-entryID", entry["id"])
        result = status()
        if not result["issuance_blocked"]:
            raise HTTPException(status_code=502, detail="Caller registration still permits issuance")
        return result


@app.post("/caller/restore")
def restore(authorization: str = Header(None)):
    authorize(authorization)
    with LOCK:
        if not entries():
            cli("create", "-spiffeID", CALLER, "-parentID", PARENT, "-selector", "unix:uid:1001", "-x509SVIDTTL", "10")
        result = status()
        if result["issuance_blocked"]:
            raise HTTPException(status_code=502, detail="Caller registration was not restored")
        return result
