"""Negative authentication regressions; no external services required."""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("HMAC_SECRET_KEY", "unit-test-only-hmac-key")
os.environ.setdefault("VAULT_CACERT", str(Path(__file__).resolve().parents[1] / "certs" / "ca.pem"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'control'))
import auth
from fastapi import HTTPException
from starlette.requests import Request


def request(headers):
    return Request({'type': 'http', 'headers': [(k.lower().encode(), v.encode()) for k, v in headers.items()]})


class AuthBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.keys = patch.multiple(auth, AUTH_SIGNING_KEY='test-signing-key-unique', INTERNAL_SERVICE_TOKEN='test-scoped-internal-token')
        self.keys.start()
        self.addCleanup(self.keys.stop)

    def test_identity_headers_cannot_authenticate(self):
        for headers in [{'X-Actor-Id': 'secops_admin'}, {'X-Requester-Id': 'admin'},
                        {'Authorization': 'Bearer invalid', 'X-Actor-Id': 'secops_admin'}]:
            with self.assertRaises(HTTPException) as ctx:
                auth.authenticate_request(request(headers), require_auth=True)
            self.assertEqual(ctx.exception.status_code, 401)

    def test_published_secrets_and_signing_key_are_not_bearer_credentials(self):
        for token in ['lab_hmac_secret_key_isolated_2026', 'lab_supervisor_token_internal', auth.AUTH_SIGNING_KEY]:
            self.assertIsNone(auth.verify_token(token))

    def test_internal_identity_cannot_execute_or_create_intakes(self):
        principal = auth.verify_token(auth.INTERNAL_SERVICE_TOKEN)
        self.assertTrue(principal.has_permission('internal:register'))
        for permission in ['operation:execute', 'intake:create', 'intake:approve', 'finding:create']:
            self.assertFalse(principal.has_permission(permission))

    def test_valid_token_uses_server_membership(self):
        principal = auth.verify_token(auth.create_access_token('bob'))
        self.assertTrue(principal.is_member_of('audit_team'))
        self.assertFalse(principal.is_member_of('orders_team'))
        self.assertFalse(principal.has_permission('operation:execute'))

    def signed(self, payload):
        raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        return raw + '.' + hmac.new(auth.AUTH_SIGNING_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()

    def test_malformed_expired_unknown_tokens_fail_closed(self):
        for payload in [[], None, 'bad', {}, {'sub': 'alice', 'aud': 'credential-control'},
                        {'sub': 'alice', 'exp': time.time()-1, 'aud': 'credential-control'},
                        {'sub': 'invented-admin', 'exp': time.time()+60, 'aud': 'credential-control'}]:
            self.assertIsNone(auth.verify_token(self.signed(payload)))
        for token in ['bad', 'a.b.c', '%%%.' + '0'*64]:
            self.assertIsNone(auth.verify_token(token))

    def test_embedded_role_claim_cannot_elevate_registered_user(self):
        token = self.signed({'sub': 'alice', 'role': 'admin', 'groups':['all'], 'exp':time.time()+60, 'aud':'credential-control'})
        self.assertFalse(auth.verify_token(token).has_permission('operation:execute'))

    def test_password_is_required_and_unknown_user_cannot_be_minted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'users.json'
            salt = os.urandom(16)
            path.write_text(json.dumps({'alice': {'salt':salt.hex(), 'hash': hashlib.pbkdf2_hmac('sha256', b'correct-password', salt, 200000).hex()}}))
            with patch.object(auth, 'AUTH_USERS_FILE', str(path)):
                for name, password in [('alice', ''), ('alice', 'wrong'), ('new-admin', 'correct-password')]:
                    with self.assertRaises(HTTPException):
                        auth.login(name, password)
                self.assertEqual(auth.verify_token(auth.login('alice', 'correct-password')).id, 'alice')
        with self.assertRaises(HTTPException):
            auth.create_access_token('unknown')

    def test_demo_picker_is_disabled_without_explicit_local_mode(self):
        with patch.object(auth, 'DEMO_ACCOUNT_PICKER_ENABLED', False):
            with self.assertRaises(HTTPException) as ctx:
                auth.local_demo_accounts()
        self.assertEqual(ctx.exception.status_code, 404)

    def test_demo_picker_only_issues_registered_bootstrap_account(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'users.json'
            path.write_text(json.dumps({'alice': {}, 'secops_admin': {}}))
            with patch.multiple(auth, AUTH_USERS_FILE=str(path), DEMO_ACCOUNT_PICKER_ENABLED=True):
                accounts = auth.local_demo_accounts()
                self.assertEqual([item['principal_id'] for item in accounts], ['secops_admin', 'alice'])
                self.assertEqual(auth.verify_token(auth.login_as_local_demo('alice')).id, 'alice')
                with self.assertRaises(HTTPException):
                    auth.login_as_local_demo('admin')


class ApiBoundaryTests(unittest.TestCase):
    def setUp(self):
        import main
        from fastapi.testclient import TestClient
        self.main = main
        self.client = TestClient(main.app)
        self.audit = patch.object(main.orchestrator, 'record_evidence')
        self.audit_mock = self.audit.start()
        self.addCleanup(self.audit.stop)
        self.keys = patch.multiple(auth, AUTH_SIGNING_KEY='api-test-only-key', INTERNAL_SERVICE_TOKEN='scoped-api-test-token')
        self.keys.start()
        self.addCleanup(self.keys.stop)

    def test_health_is_public_sensitive_routes_are_not(self):
        self.assertEqual(self.client.get('/api/health').status_code, 200)
        for path in ['/api/credentials', '/api/evidence', '/api/incidents', '/api/gitlab/runner/status']:
            self.assertEqual(self.client.get(path).status_code, 401)
        self.assertTrue(self.audit_mock.called)

    def test_token_exchange_requires_password_not_role_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'users.json'
            path.write_text('{}')
            with patch.object(auth, 'AUTH_USERS_FILE', str(path)):
                response = self.client.post('/api/auth/token', json={'username':'secops_admin', 'role':'admin', 'groups':['all']})
        self.assertEqual(response.status_code, 401)

    def test_privileged_optional_and_internal_routes_reject_requester(self):
        headers = {'Authorization': 'Bearer ' + auth.create_access_token('alice')}
        for path in ['/api/gitlab/pipelines/test/approve', '/api/demo/suite', '/api/apps/integrated/renew',
                     '/api/internal/register-fingerprint', '/api/internal/reconcile-static-legacy']:
            self.assertEqual(self.client.post(path, headers=headers, json={}).status_code, 403, path)

    def test_invalid_token_overrides_identity_header(self):
        response = self.client.post('/api/intakes', headers={'Authorization':'Bearer forged', 'X-Actor-Id':'admin'}, json={})
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
