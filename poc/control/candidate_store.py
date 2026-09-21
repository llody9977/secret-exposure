"""Restricted local candidate vault. Registry stores opaque references only.

The control process is the trusted validator/broker. Values live in a mode-0700
runtime directory, files mode-0600, with ten-minute retention and audited reads.
Never include this directory in logs or evidence exports.
"""
import json
import os
import re
import time
import uuid
from pathlib import Path

ROOT = Path(os.getenv('CANDIDATE_STORE_DIR', str(Path(__file__).resolve().parents[1] / '.bootstrap' / 'candidates')))


def put(value, ttl=600):
    if not isinstance(value, str) or not value or len(value) > 16384:
        raise ValueError('Invalid candidate material')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    # Sweep expired material on writes; reads also delete expired references.
    for path in ROOT.glob('cand-*.json'):
        try:
            if json.loads(path.read_text())['expires_at'] <= time.time():
                path.unlink()
        except (ValueError, KeyError, OSError):
            pass
    ref = 'cand-' + uuid.uuid4().hex
    fd = os.open(ROOT / (ref + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'value': value, 'expires_at': time.time() + min(ttl, 600)}, f)
        f.flush()
        os.fsync(f.fileno())
    return ref


def get(ref, actor, run_id, operation_id=None):
    if not ref or not re.fullmatch(r'cand-[0-9a-f]{12,32}', ref):
        raise ValueError('Missing or invalid candidate reference')
    status = 'inconclusive'
    try:
        path = ROOT / (ref + '.json')
        data = json.loads(path.read_text())
        if data['expires_at'] <= time.time():
            path.unlink(missing_ok=True)
            raise ValueError('Candidate reference expired; capture authorized evidence again')
        status = 'read'
        return data['value']
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError('Candidate reference unavailable') from exc
    finally:
        from orchestrator import record_evidence
        record_evidence(run_id, 'A05', actor, 'candidate_reference_access', status,
                        operation_id=operation_id, redacted_result={'candidate_ref': ref})
