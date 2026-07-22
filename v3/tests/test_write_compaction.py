from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from va_watchdog.blackbox import trim_blackbox
from va_watchdog.history import _LAST_TRIM_UNIX, trim_history


class WriteCompactionTests(unittest.TestCase):
    def test_history_does_not_rewrite_when_nothing_expires(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "history.jsonl"
            path.write_text(json.dumps({"time": "2099-01-01T00:00:00+00:00"}) + "\n", encoding="utf-8")
            cfg = {
                "events_path": str(Path(temporary) / "events.jsonl"),
                "history_path": str(path),
                "retention": {"history_retention_days": 30, "history_max_rows": 50000},
            }
            _LAST_TRIM_UNIX.clear()
            with patch("va_watchdog.history.os.replace") as replace:
                trim_history(cfg)

        replace.assert_not_called()

    def test_blackbox_compacts_in_batches(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "blackbox.jsonl"
            cfg = {
                "events_path": str(Path(temporary) / "events.jsonl"),
                "blackbox": {"path": str(path), "max_rows": 50},
            }
            rows = [json.dumps({"time": time.time(), "row": index}) for index in range(101)]
            path.write_text("\n".join(rows) + "\n", encoding="utf-8")

            trim_blackbox(cfg)

            remaining = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(remaining), 50)
            self.assertEqual(json.loads(remaining[0])["row"], 51)


if __name__ == "__main__":
    unittest.main()
