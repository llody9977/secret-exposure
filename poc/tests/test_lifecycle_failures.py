"""Failure-path tests; these support, never replace, real service acceptance."""
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

POC=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(POC/'control'))
os.environ.setdefault('HMAC_SECRET_KEY','isolated-unit-test-key')
os.environ.setdefault('VAULT_CACERT',str(POC/'certs'/'ca.pem'))
import orchestrator
import candidate_store
from adapters.validator import ValidatorAdapter
from adapters.issuer import VaultSecretIssuerAdapter

class Cursor:
    rowcount=1
    def __init__(self, action='rotate', service='svc-legacy'):
        self.op={'id':'op-test','incident_id':'inc-test','credential_version_id':'v-test','target':service,'action':action,
                 'status':'pending','params':{},'attempts':0,'interrupted':False}
        self.inc={'id':'inc-test','service_id':service,'triage_status':'decided','decision_action':action,'candidate_ref':None}
        self.service={'id':service,'target_resource':'postgres:5432/appdb','application_category':'legacy'}
        self.version={'credential_id':'cred-test','version_id':'v-test','hmac_fingerprint':'not-real','canonical_version':'v1'}
        self.cred={'credential_id':'cred-test','service_id':service,'credential_type':'database_static','issuer_ref':'database/static-roles/legacy-app-role','current_version_id':'v-test'}
        self.result=None
        self.updates=[]
    def execute(self, sql, args=None):
        if 'SELECT * FROM operations' in sql: self.result=self.op
        elif 'SELECT credential_id FROM credential_versions' in sql:self.result={'credential_id':'cred-test'}
        elif 'pg_try_advisory_lock' in sql:self.result={'acquired':True}
        elif 'SELECT * FROM incidents' in sql:self.result=self.inc
        elif 'SELECT * FROM services' in sql:self.result=self.service
        elif 'SELECT * FROM credential_versions' in sql:self.result=self.version
        elif 'SELECT * FROM credentials' in sql:self.result=self.cred
        else:self.updates.append((sql,args))
    def fetchone(self):return self.result
    def close(self):pass

class Connection:
    def __init__(self,cursor):self.cur=cursor
    def cursor(self):return self.cur
    def commit(self):pass
    def rollback(self):pass
    def close(self):pass

class LifecycleFailures(unittest.TestCase):
    def run_operation(self, cursor):
        with patch.object(orchestrator,'get_connection',return_value=Connection(cursor)), \
             patch.object(orchestrator,'get_vault_token',return_value='isolated-test-token'), \
             patch.object(orchestrator,'record_evidence'), \
             patch.object(orchestrator.issuer_adapter,'rotate_static_role') as rotate:
            result=orchestrator.execute_operation('op-test','operator','',False,'unit-only')
            rotate.assert_not_called()
            return result

    def test_missing_real_candidate_aborts_without_rotation(self):
        result=self.run_operation(Cursor())
        self.assertEqual(result['containment'],'failed')
        self.assertIn('Actual exposed candidate',result['error'])

    def test_unrelated_incident_cannot_isolate_caller(self):
        with patch.object(orchestrator.identity_adapter,'contain_workload') as isolate:
            result=self.run_operation(Cursor(action='isolate',service='svc-unrelated'))
            isolate.assert_not_called()
            self.assertEqual(result['status'],'failed')

    def test_completed_operation_does_not_repeat_effect(self):
        cursor=Cursor();cursor.op['status']='completed'
        self.assertEqual(self.run_operation(cursor)['status'],'already_completed')

    def test_network_failure_does_not_prove_revocation(self):
        import requests
        with patch('adapters.issuer.requests.put',side_effect=requests.Timeout):
            with self.assertRaises(requests.Timeout):
                orchestrator.issuer_adapter.lease_absent('lease','token')

    def test_permission_denial_does_not_prove_missing_lease(self):
        import requests
        response=Mock(status_code=403)
        response.raise_for_status.side_effect=requests.HTTPError
        with patch('adapters.issuer.requests.put',return_value=response):
            with self.assertRaises(requests.HTTPError):
                orchestrator.issuer_adapter.lease_absent('lease','token')

    def test_missing_lease_requires_specific_authoritative_error(self):
        response=Mock(status_code=400)
        response.json.return_value={'errors':['invalid lease']}
        with patch('adapters.issuer.requests.put',return_value=response):
            self.assertTrue(orchestrator.issuer_adapter.lease_absent('lease','token'))

    def test_candidate_expiry_erases_value_and_fails_inconclusive(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(candidate_store,'ROOT',Path(tmp)), patch.object(orchestrator,'record_evidence') as audit:
            ref=candidate_store.put('disposable-test-candidate',ttl=-1)
            with self.assertRaisesRegex(ValueError,'expired'):
                candidate_store.get(ref,'validator','unit-only')
            self.assertFalse((Path(tmp)/(ref+'.json')).exists())
            self.assertEqual(audit.call_args.args[4],'inconclusive')

    def test_candidate_store_permissions_and_no_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(candidate_store,'ROOT',Path(tmp)), patch.object(orchestrator,'record_evidence'):
            ref=candidate_store.put('disposable-test-candidate')
            self.assertEqual((Path(tmp)/(ref+'.json')).stat().st_mode & 0o777,0o600)
            self.assertEqual(candidate_store.get(ref,'validator','unit-only'),'disposable-test-candidate')
            with self.assertRaises(ValueError):candidate_store.get('../secret','validator','unit-only')

    def test_validator_unknown_target_never_connects(self):
        with patch('adapters.validator.psycopg2.connect') as connect:
            self.assertEqual(ValidatorAdapter().validate_credential('attacker:5432/db','user','test')['status'],'unsupported')
            connect.assert_not_called()

if __name__=='__main__':unittest.main()
