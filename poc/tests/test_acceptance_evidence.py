import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('acceptance_runner', ROOT / 'scripts/run_scenarios.py')
runner_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner_module)


class EvidenceTests(unittest.TestCase):
    def test_snapshot_covers_untracked_source_and_excludes_runtime_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'source.py').write_text('one')
            (root / '.bootstrap').mkdir()
            (root / '.bootstrap/secret').write_text('sensitive')
            (root / '.env').write_text('sensitive')
            with patch.object(runner_module, 'POC_DIR', folder):
                before = runner_module.source_snapshot()
                self.assertEqual(list(before['files']), ['source.py'])
                (root / 'source.py').write_text('two')
                self.assertNotEqual(before['sha256'], runner_module.source_snapshot()['sha256'])

    def test_missing_events_makes_package_incomplete(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = runner_module.ScenarioRunner('run_test')
            runner.results['A02'] = 'PASS'
            runner.auth_headers = Mock(return_value={})
            response = Mock(status_code=200)
            response.json.return_value = [{'id': 1, 'run_id': 'run_default'}]
            with patch.object(runner_module, 'EVIDENCE_DIR', folder), patch.object(runner_module.requests, 'get', return_value=response):
                runner.save_evidence()
            self.assertTrue(runner.results['EVIDENCE'].startswith('INCOMPLETE'))
            self.assertEqual((Path(folder) / 'run_test/events.jsonl').read_text(), '')
            manifest = json.loads((Path(folder) / 'run_test/manifest.json').read_text())
            self.assertEqual(manifest['source_snapshot_sha256'], runner.source_snapshot['sha256'])

    def test_assertions_reference_only_their_scenario_events(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = runner_module.ScenarioRunner('run_test')
            runner.auth_headers = Mock(return_value={})
            runner.record_assertion('A02', 'rejected', True, {})
            response = Mock(status_code=200)
            response.json.return_value = [{'id': 10, 'run_id': 'run_test', 'scenario_id': 'A02'},
                                          {'id': 11, 'run_id': 'run_test', 'scenario_id': 'A03'}]
            with patch.object(runner_module, 'EVIDENCE_DIR', folder), patch.object(runner_module.requests, 'get', return_value=response):
                runner.save_evidence()
            self.assertEqual(runner.assertions[0]['event_ids'], [10])

    def test_failed_assertion_is_retained(self):
        runner = runner_module.ScenarioRunner('run_test')
        runner.record_assertion('A01', 'check unavailable', False, {})
        self.assertTrue(runner.scenario_failed['A01'])
