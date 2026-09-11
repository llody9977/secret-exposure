import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ.setdefault('IDENTITY_AUTHORITY_TOKEN', 'test-authority-token')
source = Path(__file__).resolve().parents[1] / 'identity-authority' / 'main.py'
spec = importlib.util.spec_from_file_location('identity_authority', source)
authority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority)

ENTRY = {'id':'test-id', 'spiffe_id':{'trust_domain':'lab.local','path':'/workload/caller'},
         'parent_id':{'trust_domain':'lab.local','path':'/agent/node1'}, 'selectors':[{'type':'unix','value':'uid:1001'}]}


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(authority.app)
        self.headers = {'Authorization':'Bearer ' + authority.TOKEN}

    def test_unauthenticated_cannot_access_authority(self):
        with patch.object(authority, 'cli') as call:
            for method, path in [('GET','/caller'), ('POST','/caller/disable'), ('POST','/caller/restore')]:
                self.assertEqual(self.client.request(method, path).status_code, 401)
            call.assert_not_called()

    def test_disable_verifies_authoritative_absence(self):
        with patch.object(authority, 'cli', side_effect=[{'entries':[ENTRY]}, {}, {'entries':[]}]) as call:
            response = self.client.post('/caller/disable', headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json()['issuance_blocked'])
            self.assertEqual(call.call_args_list[1].args, ('delete','-entryID','test-id'))

    def test_disable_failure_cannot_report_contained(self):
        with patch.object(authority, 'cli', side_effect=[{'entries':[ENTRY]}, {}, {'entries':[ENTRY]}]):
            self.assertEqual(self.client.post('/caller/disable', headers=self.headers).status_code, 502)

    def test_conflicting_registration_is_not_mutated(self):
        changed = dict(ENTRY, selectors=[{'type':'unix','value':'uid:0'}])
        with patch.object(authority, 'cli', return_value={'entries':[changed]}) as call:
            self.assertEqual(self.client.post('/caller/disable', headers=self.headers).status_code, 409)
            self.assertEqual(call.call_count, 1)

    def test_restore_is_idempotent_and_fixed_scope(self):
        with patch.object(authority, 'cli', side_effect=[{'entries':[]}, {}, {'entries':[ENTRY]}]) as call:
            response = self.client.post('/caller/restore?identity=spiffe://evil/root', headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(call.call_args_list[1].args, ('create','-spiffeID',authority.CALLER,'-parentID',authority.PARENT,'-selector','unix:uid:1001','-x509SVIDTTL','10'))


if __name__ == '__main__':
    unittest.main()
