"""Request-scoped audit correlation; propagated to synchronous handlers by Starlette."""
from contextvars import ContextVar
current_run_id = ContextVar("evidence_run_id", default=None)
current_scenario_id = ContextVar("evidence_scenario_id", default=None)
