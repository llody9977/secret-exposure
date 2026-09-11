#!/usr/bin/env python3
"""Rotate a previously exposed Vault bootstrap root token without revoking children.

Host-only maintenance. The old file is backed up before any mutation; the new
credential is durably saved and verified before the old token is revoked. No
credential values or HTTP response bodies are printed.
"""
import json
import os
from pathlib import Path
import time
import requests

POC = Path(__file__).resolve().parents[1]


def write_private(path, payload):
    temporary = Path(str(path) + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(payload, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def rotate_vault():
    path = POC / '.bootstrap' / 'vault_keys.json'
    data = json.loads(path.read_text())
    old = data['root_token']
    url = os.getenv('VAULT_ADDR', 'https://127.0.0.1:8200').rstrip('/')
    ca = str(POC / 'certs' / 'ca.pem')
    session = requests.Session()

    def call(method, endpoint, token, body=None):
        response = session.request(method, url + '/v1/' + endpoint,
                                   headers={'X-Vault-Token':token}, json=body,
                                   verify=ca, timeout=10)
        return response

    if call('GET', 'auth/token/lookup-self', old).status_code != 200:
        raise RuntimeError('Existing bootstrap token does not authenticate; no change made')
    backup = path.with_name(path.name + '.before-token-rotation-' + str(time.time_ns()))
    write_private(backup, data)
    response = call('POST', 'auth/token/create', old, {'policies':['root'], 'no_parent':True,
                                                    'display_name':'local-bootstrap-root'})
    if response.status_code != 200:
        raise RuntimeError('Replacement token creation failed; original remains active')
    new = response.json()['auth']['client_token']
    if call('GET', 'auth/token/lookup-self', new).status_code != 200:
        raise RuntimeError('Replacement token verification failed; original remains active')
    data['root_token'] = new
    write_private(path, data)
    # Revoke only the exposed token; existing AppRole sessions/leases survive.
    response = call('POST', 'auth/token/revoke-orphan', new, {'token':old})
    if response.status_code not in (200, 204):
        raise RuntimeError('Replacement saved but old token revocation incomplete; retry from backup using new root')
    if call('GET', 'auth/token/lookup-self', old).status_code != 403:
        raise RuntimeError('Replacement saved but old-token rejection was not established')
    if call('GET', 'auth/token/lookup-self', new).status_code != 200:
        raise RuntimeError('Replacement token post-check failed')
    print('Vault bootstrap token replaced; old token rejected; existing child sessions preserved.')


if __name__ == '__main__':
    rotate_vault()
