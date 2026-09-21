import hmac
import hashlib
import os

HMAC_SECRET_KEY = os.environ["HMAC_SECRET_KEY"].encode("utf-8")

def canonicalize(raw_secret: str) -> str:
    # Version 1 canonicalization: strip whitespace and surrounding quotes
    return raw_secret.strip().strip("'\"")

def compute_fingerprint(raw_secret: str, canonical_version: str = "v1") -> str:
    if canonical_version != "v1":
        raise ValueError(f"Unsupported canonicalization version: {canonical_version}")
    clean_secret = canonicalize(raw_secret)
    h = hmac.new(HMAC_SECRET_KEY, clean_secret.encode("utf-8"), hashlib.sha256)
    return f"hmac_sha256:{h.hexdigest()}"

def verify_fingerprint(raw_secret: str, expected_fingerprint: str, canonical_version: str = "v1") -> bool:
    calculated = compute_fingerprint(raw_secret, canonical_version)
    return hmac.compare_digest(calculated, expected_fingerprint)
