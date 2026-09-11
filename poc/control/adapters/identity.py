import os
import requests

class SpireIdentityAdapter:
    def set_target_policy(self, target_service_url, allowed_spiffe_ids):
        if target_service_url != 'http://spiffe-service:8444':
            raise ValueError('Unregistered policy target')
        response = requests.post(target_service_url+'/admin/policy', json={'allowed_spiffe_ids':allowed_spiffe_ids},
                                 headers={'Authorization':'Bearer '+os.environ['SPIFFE_ADMIN_TOKEN']},timeout=5)
        response.raise_for_status()
        if response.json().get('allowed') != allowed_spiffe_ids:
            raise ValueError('Target policy readback does not match intent')
        return True

    def revoke_spiffe_entry(self, entry_id=None):
        # Identity is fixed by the narrow authority, not supplied by a finding.
        response = requests.post('http://identity-authority:8445/caller/disable',
                                 headers={'Authorization':'Bearer '+os.environ['IDENTITY_AUTHORITY_TOKEN']},timeout=15)
        response.raise_for_status()
        return response.json().get('issuance_blocked') is True

    def contain_workload(self):
        caller='http://spiffe-caller:8003'
        before=requests.get(caller+'/svid_info',timeout=5)
        before.raise_for_status()
        prime=requests.get(caller+'/probe',timeout=5)
        prime.raise_for_status()
        if prime.json().get('target_status') != 200:
            raise ValueError('Existing authorized connection was not established before isolation')
        issuance_blocked=self.revoke_spiffe_entry()
        if not issuance_blocked:
            raise ValueError('Identity issuance was not disabled')
        self.set_target_policy('http://spiffe-service:8444',[])
        held=requests.get(caller+'/probe',timeout=5)
        fresh=requests.get(caller+'/probe?fresh=true',timeout=5)
        held.raise_for_status(); fresh.raise_for_status()
        held_data, fresh_data=held.json(),fresh.json()
        verified=(held_data.get('target_status')==403 and held_data.get('connection_reused') is True
                  and fresh_data.get('target_status')==403 and fresh_data.get('connection_reused') is False)
        return {'verified':verified,'issuance_blocked':issuance_blocked,
                'held_connection_denied':held_data.get('target_status')==403,
                'existing_connection_reused':held_data.get('connection_reused'),
                'fresh_connection_denied':fresh_data.get('target_status')==403,
                'retained_svid_serial':before.json().get('serial_number'),
                'retained_svid_not_after':before.json().get('not_after'),
                'certificate_revoked':False}
