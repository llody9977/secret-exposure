import psycopg2
from typing import Dict, Any

# Authorized lab validation targets. Values are (primary_host, fallback_host, port, dbname).
# The candidate credential is never interpolated into a connection URI; host/port/db come
# only from this table, so an attacker-controlled leaked secret cannot redirect the probe.
ALLOWED_TARGETS = {
    "postgres:5432/appdb": ("postgres", "127.0.0.1", 5432, "appdb"),
    "db.internal.corp:5432/appdb": ("db.internal.corp", "127.0.0.1", 5432, "appdb"),
    "db-primary.internal.corp:5432/appdb": ("db-primary.internal.corp", "127.0.0.1", 5432, "appdb"),
    "postgres:5432/controldb": ("postgres", "127.0.0.1", 5432, "controldb"),
}


class ValidatorAdapter:
    def validate_credential(self, target_resource: str, username: str, candidate_password: str) -> Dict[str, Any]:
        # Enforce target boundary: reject arbitrary injected hostnames (REQ030, A16)
        if target_resource not in ALLOWED_TARGETS:
            return {
                "status": "unsupported",
                "reason": f"Target resource '{target_resource}' is not an authorized lab target.",
            }

        primary_host, fallback_host, port, dbname = ALLOWED_TARGETS[target_resource]

        def _connect(host: str):
            return psycopg2.connect(
                host=host,
                port=port,
                dbname=dbname,
                user=username,
                password=candidate_password,
                connect_timeout=3,
            )

        try:
            # On a host where the docker service name does not resolve, retry against localhost.
            try:
                conn = _connect(primary_host)
            except psycopg2.OperationalError as e:
                if any(err in str(e) for err in ["could not translate host name", "nodename nor servname provided"]):
                    conn = _connect(fallback_host)
                else:
                    raise

            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            conn.close()
            return {
                "status": "active",
                "reason": "Successfully connected and executed harmless lab query SELECT 1.",
            }
        except psycopg2.OperationalError as e:
            err_msg = str(e).lower()
            if "password authentication failed" in err_msg or "authentication failed" in err_msg or "fatal:  role" in err_msg:
                return {
                    "status": "invalid",
                    "reason": "Target rejected candidate credentials with authentication failure.",
                }
            elif "timeout" in err_msg or "could not connect" in err_msg:
                return {
                    "status": "inconclusive",
                    "reason": f"Connection timed out or network error: {e}",
                }
            elif "permission denied" in err_msg:
                return {
                    "status": "inconclusive",
                    "reason": f"Permission denied during validation check: {e}",
                }
            else:
                return {
                    "status": "inconclusive",
                    "reason": f"Operational error encountered: {e}",
                }
        except Exception as e:
            return {
                "status": "inconclusive",
                "reason": f"Unexpected error during validation: {e}",
            }
