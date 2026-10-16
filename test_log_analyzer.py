import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from log_analyzer import AuthEvent, detect_alerts, parse_line


class ParseLineTests(unittest.TestCase):
    def test_parse_valid_event(self):
        event = parse_line("2026-09-01T09:00:00Z username=alice ip=192.0.2.10 status=success")
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.status, "success")
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)

    def test_ignore_comment(self):
        self.assertIsNone(parse_line("# sample comment"))

    def test_reject_invalid_status(self):
        with self.assertRaises(ValueError):
            parse_line("2026-09-01T09:00:00Z username=alice ip=192.0.2.10 status=unknown")


class DetectionTests(unittest.TestCase):
    def make_event(self, minute, status, username="admin", ip="192.0.2.15"):
        return AuthEvent(
            datetime(2026, 9, 1, 9, minute, tzinfo=timezone.utc),
            username, ip, status
        )

    def test_repeated_failures_trigger_alert(self):
        events = [self.make_event(i, "failure") for i in range(1, 6)]
        alerts = detect_alerts(events, threshold=5, window_minutes=10)
        self.assertTrue(any(a.alert_type == "repeated_failed_logins" for a in alerts))

    def test_success_after_failures_triggers_alert(self):
        events = [self.make_event(i, "failure") for i in range(1, 4)]
        events.append(self.make_event(5, "success"))
        alerts = detect_alerts(events)
        self.assertTrue(any(a.alert_type == "success_after_repeated_failures" for a in alerts))

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            detect_alerts([], threshold=1)


if __name__ == "__main__":
    unittest.main()
