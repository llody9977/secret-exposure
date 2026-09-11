import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

path = Path(__file__).resolve().parents[1] / "control/adapters/issuer.py"
spec = importlib.util.spec_from_file_location("session_issuer", path)
issuer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(issuer)

class SessionContainmentTests(unittest.TestCase):
    def setUp(self):
        self.adapter = object.__new__(issuer.VaultSecretIssuerAdapter)
        self.conn = MagicMock()
        self.cur = self.conn.cursor.return_value.__enter__.return_value
        self.env = patch.dict(os.environ, {"APP_DB_ADMIN_URL":"test-only"})
        self.env.start()
        self.mock = patch.object(issuer.psycopg2, "connect", return_value=self.conn)
        self.mock.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.mock.stop)

    def test_missing_backend_start_fails_closed(self):
        self.cur.fetchall.return_value = [(42, None)]
        with self.assertRaises(ValueError):
            self.adapter.capture_target_sessions("removed-user")

    def test_termination_binds_pid_and_start_after_role_removal(self):
        start = datetime.now(timezone.utc).isoformat()
        self.cur.fetchall.return_value = [(True,)]
        self.assertEqual(self.adapter.terminate_captured_sessions([(42,start)]),1)
        sql,args = self.cur.execute.call_args.args
        self.assertIn("backend_start", sql)
        self.assertNotIn("usename", sql)
        self.assertEqual(args,(42,start))

    def test_observation_failure_is_not_zero_sessions(self):
        self.cur.execute.side_effect = issuer.psycopg2.OperationalError("unavailable")
        with self.assertRaises(issuer.psycopg2.OperationalError):
            self.adapter.count_captured_sessions([(42,"2026-09-10T00:00:00+00:00")])
