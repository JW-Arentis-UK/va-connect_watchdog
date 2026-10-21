import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from va_watchdog.update import _write_state, last_completed, update_in_progress


class UpdateStatusTests(unittest.TestCase):
    def test_prior_success_survives_queue_and_running_states(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'update-state.json'
            path.write_text(json.dumps({
                'state': 'completed', 'updated_at': '2026-10-19T12:00:00+00:00',
                'commit': 'abc1234',
            }))
            _write_state(path, 'queued', 'Waiting to start', 'codex/gui-refresh', 'abc1234')
            payload = json.loads(path.read_text())
            self.assertEqual(payload['last_completed_at'], '2026-10-19T12:00:00+00:00')
            self.assertEqual(payload['last_completed_commit'], 'abc1234')
            self.assertTrue(last_completed(payload, '20261021.1')['build'])

    def test_only_recent_queued_or_running_state_blocks_another_update(self):
        now = datetime.now(timezone.utc)
        self.assertTrue(update_in_progress({'state': 'queued', 'updated_at': now.isoformat()}))
        self.assertTrue(update_in_progress({'state': 'running', 'updated_at': now.isoformat()}))
        self.assertFalse(update_in_progress({'state': 'completed', 'updated_at': now.isoformat()}))
        self.assertFalse(update_in_progress({'state': 'running', 'updated_at': (now - timedelta(hours=1)).isoformat()}))


if __name__ == '__main__':
    unittest.main()
