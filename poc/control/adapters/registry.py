from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class RegistryAdapter(ABC):
    @abstractmethod
    def get_service(self, service_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def resolve_owner(self, service_id: str) -> Dict[str, str]:
        pass

class LocalRegistryAdapter(RegistryAdapter):
    def __init__(self, db_conn_fn):
        self.get_conn = db_conn_fn

    def get_service(self, service_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM services WHERE id = %s", (service_id,))
        res = cur.fetchone()
        cur.close()
        conn.close()
        return dict(res) if res else None

    def resolve_owner(self, service_id: str) -> Dict[str, str]:
        svc = self.get_service(service_id)
        if not svc:
            return {"owner_group": "security_fallback", "type": "fallback"}
        if svc.get("owner_group"):
            return {"owner_group": svc["owner_group"], "type": "authoritative"}
        return {"owner_group": svc.get("fallback_group", "security_fallback"), "type": "fallback"}

class ITopRegistryAdapter(RegistryAdapter):
    def __init__(self, live: bool = False):
        self.live = live

    def get_service(self, service_id: str) -> Optional[Dict[str, Any]]:
        if not self.live:
            return {"service_id": service_id, "adapter": "itop", "status": "contract_simulated"}
        raise NotImplementedError("Live iTop instance unconfigured")

    def resolve_owner(self, service_id: str) -> Dict[str, str]:
        return {"owner_group": "itop_mock_team", "type": "contract_simulated"}

class ServiceNowRegistryAdapter(RegistryAdapter):
    def __init__(self, live: bool = False):
        self.live = live

    def get_service(self, service_id: str) -> Optional[Dict[str, Any]]:
        if not self.live:
            return {"service_id": service_id, "adapter": "servicenow", "status": "pending_instance"}
        raise NotImplementedError("Live ServiceNow instance unconfigured")

    def resolve_owner(self, service_id: str) -> Dict[str, str]:
        return {"owner_group": "servicenow_pending_team", "type": "contract_pending"}
