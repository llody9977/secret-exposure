import os

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
os.makedirs(FIXTURES_DIR, exist_ok=True)

positive_content = """# Positive Scanner Fixture Log
[2026-09-06T12:00:01Z] [DEBUG] Initializing database client connection
[2026-09-06T12:00:02Z] [DEBUG] Config payload loaded: {"token": "LAB_SEC_EXP_A06_LEAKED_STATIC_SECRET_2026", "service": "svc-legacy"}
[2026-09-06T12:00:03Z] [INFO] Database connection string: postgresql://legacy_user:LAB_SEC_EXP_A06_LEAKED_STATIC_SECRET_2026@postgres:5432/appdb
[2026-09-06T12:00:04Z] [INFO] Worker idle
"""

negative_content = """# Negative Scanner Fixture Log
[2026-09-06T12:00:01Z] [INFO] Health probe returned HTTP 200 OK
[2026-09-06T12:00:02Z] [DEBUG] Request correlation ID: 4a2b9c71-3e4f-4a11-8d22-99ab12cd34ef
[2026-09-06T12:00:03Z] [INFO] Vault secret reference: database/roles/legacy-app-role
[2026-09-06T12:00:04Z] [INFO] SPIFFE ID: spiffe://lab.local/workload/caller
[2026-09-06T12:00:05Z] [INFO] PostgreSQL connection string: postgresql://readonly_user@postgres:5432/appdb
"""

with open(os.path.join(FIXTURES_DIR, "positive_log.txt"), "w") as f:
    f.write(positive_content)

with open(os.path.join(FIXTURES_DIR, "negative_log.txt"), "w") as f:
    f.write(negative_content)

print(f"Generated positive and negative fixtures in {FIXTURES_DIR}")
