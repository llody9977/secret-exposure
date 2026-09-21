import os
import time
import json
import base64
import hmac
import hashlib
import binascii
from typing import Dict, Optional, Set, List, Any
from fastapi import Request, HTTPException

AUTH_SIGNING_KEY = os.getenv("AUTH_SIGNING_KEY", "")
INTERNAL_SERVICE_TOKEN = os.getenv("INTERNAL_SERVICE_TOKEN", "")
AUTH_USERS_FILE = os.getenv("AUTH_USERS_FILE", "/poc/.bootstrap/auth_users.json")
DEMO_ACCOUNT_PICKER_ENABLED = os.getenv("LAB_DEMO_ACCOUNT_PICKER_ENABLED", "false").lower() == "true"
DEMO_ACCOUNT_IDS = ("secops_admin", "owner_dave", "sec_officer", "alice", "sec_responder")

class Principal:
    def __init__(self, principal_id: str, role: str, permissions: Set[str], groups: Optional[Set[str]] = None):
        self.id = principal_id
        self.role = role
        self.permissions = permissions
        self.groups = groups or set()

    def has_permission(self, perm: str) -> bool:
        return "all" in self.permissions or perm in self.permissions

    def is_member_of(self, group: str) -> bool:
        return self.role == "admin" or "all" in self.groups or group in self.groups

# Lab RBAC permissions mapping (REQ009, REQ025)
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": {"all"},
    "approver": {"intake:create", "intake:approve", "intake:read", "incident:decide", "incident:read", "service:read"},
    "operator": {"operation:execute", "intake:provision", "incident:decide", "incident:close", "incident:read", "service:read"},
    "requester": {"intake:create", "intake:read", "service:read", "incident:read"},
    "scanner": {"finding:create", "event:create", "incident:read", "internal:store"},
    "internal": {"internal:register", "internal:store"}
}

# Principal definitions with authentic role and group memberships
PRINCIPALS: Dict[str, Dict[str, Any]] = {
    "secops_admin": {"role": "admin", "groups": {"all", "security_team"}},
    "admin": {"role": "admin", "groups": {"all", "security_team"}},
    "owner_dave": {"role": "approver", "groups": {"orders_team", "cust_ops", "platform_team", "legacy_team", "hardware_team"}},
    "sec_officer": {"role": "approver", "groups": {"security_team", "sec_fallback", "hardware_team"}},
    "bob": {"role": "approver", "groups": {"audit_team"}},  # Member of audit_team only (not orders_team/platform_team)
    "alice": {"role": "requester", "groups": {"dev_team"}},
    "developer_alice": {"role": "requester", "groups": {"dev_team"}},
    "requester_alice": {"role": "requester", "groups": {"dev_team"}},
    "sec_responder": {"role": "operator", "groups": {"secops", "incident_response"}},
    "lead_responder": {"role": "operator", "groups": {"secops", "incident_response"}},
    "secops_responder": {"role": "operator", "groups": {"secops", "incident_response"}},
    "secops_workflow": {"role": "operator", "groups": {"secops", "incident_response"}},
    "gitleaks": {"role": "scanner", "groups": {"automated_scanners"}},
    "scanner_svc": {"role": "scanner", "groups": {"automated_scanners"}},
    "anomaly_monitor": {"role": "scanner", "groups": {"automated_scanners"}},
    "supervisor": {"role": "operator", "groups": {"supervisor"}},
    "internal": {"role": "internal", "groups": {"internal"}},
}

def get_principal(principal_id: str) -> Optional[Principal]:
    """Retrieve a Principal by ID if known."""
    if principal_id in PRINCIPALS:
        p_info = PRINCIPALS[principal_id]
        role = p_info["role"]
        groups = set(p_info.get("groups", []))
        perms = ROLE_PERMISSIONS.get(role, set())
        return Principal(principal_id, role, perms, groups)
    return None

def create_access_token(principal_id: str) -> str:
    """Mint only a registered identity; authorization remains server-owned."""
    if not AUTH_SIGNING_KEY:
        raise HTTPException(status_code=503, detail="Authentication is not initialized")
    if not get_principal(principal_id):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    payload = {"sub": principal_id, "iat": int(time.time()), "exp": int(time.time()) + 3600,
               "aud": "credential-control"}
    raw = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode()).decode().rstrip("=")
    sig = hmac.new(AUTH_SIGNING_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def login(principal_id: str, password: str) -> str:
    try:
        with open(AUTH_USERS_FILE) as f:
            entry = json.load(f).get(principal_id)
        if not entry or not get_principal(principal_id):
            raise ValueError("unknown account")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(entry["salt"]), 200000).hex()
        if not hmac.compare_digest(actual, entry["hash"]):
            raise ValueError("wrong password")
    except (OSError, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return create_access_token(principal_id)


def local_demo_accounts() -> List[Dict[str, str]]:
    """Return a bounded set of bootstrap accounts for the loopback POC picker.

    This replaces password entry only in the explicitly enabled local lab mode.
    It never returns or reads the plaintext credential cache.
    """
    if not DEMO_ACCOUNT_PICKER_ENABLED:
        raise HTTPException(status_code=404, detail="Local account picker is disabled")
    try:
        with open(AUTH_USERS_FILE) as f:
            provisioned = json.load(f)
    except (OSError, ValueError, TypeError):
        raise HTTPException(status_code=503, detail="Local accounts are not initialized")
    accounts = []
    for principal_id in DEMO_ACCOUNT_IDS:
        principal = get_principal(principal_id)
        if principal and principal_id in provisioned:
            accounts.append({"principal_id": principal.id, "role": principal.role})
    return accounts


def login_as_local_demo(principal_id: str) -> str:
    if principal_id not in {account["principal_id"] for account in local_demo_accounts()}:
        raise HTTPException(status_code=401, detail="Invalid local demo account")
    return create_access_token(principal_id)


def verify_token(token_str: str) -> Optional[Principal]:
    if not token_str:
        return None
    if INTERNAL_SERVICE_TOKEN and hmac.compare_digest(token_str, INTERNAL_SERVICE_TOKEN):
        return get_principal("internal")
    if not AUTH_SIGNING_KEY:
        return None
    try:
        raw, sig = token_str.split(".")
        expected = hmac.new(AUTH_SIGNING_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        if not isinstance(data, dict):
            return None
        if data.get("aud") != "credential-control" or not isinstance(data.get("exp"), (float, int)):
            return None
        if time.time() >= data["exp"]:
            return None
        return get_principal(data["sub"])
    except (ValueError, KeyError, TypeError, binascii.Error):
        return None

def authenticate_request(request: Request, require_auth: bool = False) -> Principal:
    """
    Server-enforced authentication: binds caller strictly to a validated cryptographic token.
    Fails closed: invalid credentials always raise HTTP 401; no identity-header fallbacks.
    """
    token = None
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        token = auth_hdr.split(" ", 1)[1].strip()
    elif auth_hdr:
        raise HTTPException(status_code=401, detail="Invalid authorization scheme")
    elif "X-Auth-Token" in request.headers:
        token = request.headers.get("X-Auth-Token", "").strip()

    if token:
        principal = verify_token(token)
        if not principal:
            raise HTTPException(
                status_code=401,
                detail="Invalid, expired or forged authorization token"
            )
        return principal

    if require_auth:
        raise HTTPException(
            status_code=401,
            detail="Missing required authorization bearer token"
        )

    # Public discovery fallback for endpoints with no required authorization
    return Principal("anonymous", "guest", set(), set())

def require_permission(perm: str):
    """FastAPI dependency for strict role and permission enforcement."""
    def dependency(request: Request) -> Principal:
        principal = authenticate_request(request, require_auth=True)
        if not principal.has_permission(perm):
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Principal '{principal.id}' with role '{principal.role}' lacks permission '{perm}'"
            )
        request.state.principal = principal
        return principal
    return dependency
