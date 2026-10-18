import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from detect_auth_attacks import detect, load_events

class DetectorTests(unittest.TestCase):
    def test_sample_data_flags_one_ip_and_success(self):
        events = load_events(ROOT / "data" / "auth_events.csv")
        findings = detect(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_ip"], "10.20.5.77")
        self.assertEqual(findings[0]["failure_count_in_window"], 8)
        self.assertTrue(findings[0]["success_after_failures"])

    def test_higher_threshold_suppresses_finding(self):
        events = load_events(ROOT / "data" / "auth_events.csv")
        self.assertEqual(detect(events, threshold=9), [])

if __name__ == "__main__":
    unittest.main()
