import datetime as dt
import json
import unittest

from firewall_gui.backend.activity import summarize_journal
from firewall_gui.backend.zone_assignment import ZoneAssignmentController
from firewall_gui.widgets.pending import PendingValue


class PendingValueTests(unittest.TestCase):
    def test_draft_survives_external_change_and_can_be_discarded(self):
        value = PendingValue("public")
        value.stage("work")
        value.observe("home")
        self.assertEqual((value.applied, value.draft, value.conflict), ("home", "work", True))
        value.discard()
        self.assertEqual((value.draft, value.conflict), ("home", False))

    def test_partial_apply_can_be_retried_after_saved_state_changes(self):
        value = PendingValue("public")
        value.stage("work")
        self.assertTrue(value.begin())
        value.finish(False, "active interface still uses public")
        value.observe("work")
        self.assertFalse(value.dirty)
        self.assertTrue(value.retryable)
        self.assertTrue(value.begin())
        value.finish(True)
        self.assertEqual(value.applied_message, "Applied")


class ActivityTests(unittest.TestCase):
    NOW = dt.datetime(2026, 9, 18, 12, 0, tzinfo=dt.timezone.utc)

    def record(self, message, hours_ago):
        when = self.NOW - dt.timedelta(hours=hours_ago)
        return json.dumps({"MESSAGE": message, "__REALTIME_TIMESTAMP": str(int(when.timestamp() * 1_000_000))})

    def test_counts_only_recognized_denials_within_window(self):
        lines = [
            self.record("FINAL_REJECT: IN=wlan0 OUT= DPT=22 SRC=192.0.2.1", 0.2),
            self.record("filter_IN_public_REJECT: IN=wlan0 DPT=22", 2.5),
            self.record("STATE_INVALID_DROP: IN=wlan0 DPT=80", 23.5),
            self.record("Unrelated kernel message DPT=22", 1),
            self.record("FINAL_REJECT: IN=wlan0 DPT=99", 25),
            "not-json",
        ]
        report = summarize_journal(lines, self.NOW)
        self.assertEqual(report["total"], 3)
        self.assertEqual(report["hourly"][23], 1)
        self.assertEqual(report["hourly"][21], 1)
        self.assertEqual(report["hourly"][0], 1)
        self.assertEqual(report["top_ports"], [("22", 2), ("80", 1)])
        self.assertNotIn("SRC", json.dumps(report))


class FakeNetworkManager:
    def __init__(self):
        self.saved = {"id": "public"}
        self.active = [{"uuid": "id", "device": "wlan0"}]

    def set_connection_zone(self, uuid, zone, callback):
        self.saved[uuid] = zone
        callback(True, None)

    def get_connection_zone(self, uuid, callback):
        callback(self.saved[uuid], None)

    def get_active_connections(self, callback):
        callback(self.active, None)


class FakeFirewall:
    def __init__(self):
        self.zones = {"wlan0": "public"}
        self.fail_move = False

    def get_zone_of_interface(self, iface, callback):
        callback(self.zones[iface], None)

    def change_zone_of_interface(self, zone, iface, callback):
        if self.fail_move:
            callback(False, "move denied")
        else:
            self.zones[iface] = zone
            callback(True, None)


class ZoneAssignmentTests(unittest.TestCase):
    def test_saves_profile_and_verifies_active_zone(self):
        nm, fw = FakeNetworkManager(), FakeFirewall()
        controller = ZoneAssignmentController(nm, fw)
        events, results = [], []
        controller.connect("applied", lambda _obj, uuid, zone: events.append((uuid, zone)))
        controller.apply("id", "work", lambda ok, error: results.append((ok, error)))
        self.assertEqual(nm.saved["id"], "work")
        self.assertEqual(fw.zones["wlan0"], "work")
        self.assertEqual(events, [("id", "work")])
        self.assertEqual(results, [(True, None)])

    def test_reports_saved_only_as_partial(self):
        nm, fw = FakeNetworkManager(), FakeFirewall()
        fw.fail_move = True
        controller = ZoneAssignmentController(nm, fw)
        result = []
        controller.apply("id", "work", lambda ok, error: result.append((ok, error)))
        self.assertEqual(nm.saved["id"], "work")
        self.assertFalse(result[0][0])
        self.assertIn("Saved to profile", result[0][1])


if __name__ == "__main__":
    unittest.main()
