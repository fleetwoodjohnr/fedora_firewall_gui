import unittest

from firewall_gui.backend.errors import ProtonVpnError
from firewall_gui.backend.protonvpn import (
    KeyringProbe,
    ParsedProtonLog,
    ProtonVpnClient,
    build_diagnosis,
    parse_proton_log,
)


def log_line(time, message):
    return f"2026-09-13T{time}+00:00 | test:1 | INFO | {message}"


class ProtonLogParserTests(unittest.TestCase):
    def test_expired_certificate_is_a_credential_problem(self):
        parsed = parse_proton_log(
            log_line("10:00:00", "CONN:STATE_CHANGED | Error")
            + "\n"
            + log_line("10:00:01", "Reached connection error state: ExpiredCertificate (None)")
        )

        self.assertEqual(parsed.issue, "credential")
        self.assertEqual(parsed.connection_state, "error")
        self.assertEqual(parsed.issue_time, "2026-09-13T10:00:01+00:00")

    def test_successful_certificate_refresh_clears_credential_gate(self):
        parsed = parse_proton_log(
            log_line("10:00:00", "Reached connection error state: ExpiredCertificate (None)")
            + "\n"
            + log_line("10:01:00", "certificate_refresher: Next certificate refresh scheduled in 5 days")
        )

        self.assertEqual(parsed.issue, "none")
        self.assertIn("expired or invalid", parsed.issue_detail)

    def test_server_session_not_found_is_retryable_not_credentials(self):
        parsed = parse_proton_log(
            log_line("10:00:00", 'ErrorMessage { code: 86203, description: "session not found" }')
        )

        self.assertEqual(parsed.issue, "retryable")
        self.assertIn("not a stored-password error", parsed.issue_detail)

    def test_later_connection_clears_retry_gate_but_keeps_history(self):
        parsed = parse_proton_log(
            log_line("10:00:00", "Connect timeout")
            + "\n"
            + log_line("10:00:05", "CONN:STATE_CHANGED | Connected")
        )

        self.assertEqual(parsed.issue, "none")
        self.assertEqual(parsed.connection_state, "connected")
        self.assertEqual(parsed.issue_time, "2026-09-13T10:00:00+00:00")

    def test_unrelated_and_malformed_lines_are_ignored(self):
        parsed = parse_proton_log("not a timestamp\nserver list refreshed")

        self.assertEqual(parsed, ParsedProtonLog())


class DiagnosisTests(unittest.TestCase):
    active = [
        {
            "name": "ProtonVPN RO-FREE#24",
            "type": "wireguard",
            "uuid": "test-uuid",
            "device": "proton0",
        }
    ]

    def diagnose(self, *, active=None, connectivity="full", keyring="found", log=None, installed=True):
        return build_diagnosis(
            installed=installed,
            active_connections=self.active if active is None else active,
            connectivity=connectivity,
            keyring=KeyringProbe(keyring),
            parsed_log=log or ParsedProtonLog(),
        )

    def test_healthy_active_tunnel_enables_no_repair(self):
        result = self.diagnose()

        self.assertEqual(result.state, "connected")
        self.assertFalse(result.retry_allowed)
        self.assertFalse(result.credential_reset_allowed)

    def test_credential_error_is_the_only_state_that_enables_reset(self):
        result = self.diagnose(
            log=ParsedProtonLog(issue="credential", issue_detail="credential failure")
        )

        self.assertEqual(result.state, "credential-error")
        self.assertTrue(result.credential_reset_allowed)
        self.assertFalse(result.retry_allowed)

    def test_retryable_error_does_not_enable_reset(self):
        result = self.diagnose(
            active=[],
            log=ParsedProtonLog(issue="retryable", issue_detail="temporary session failure"),
        )

        self.assertEqual(result.state, "retryable-error")
        self.assertTrue(result.retry_allowed)
        self.assertFalse(result.credential_reset_allowed)

    def test_limited_connected_tunnel_enables_retry(self):
        result = self.diagnose(connectivity="limited")

        self.assertEqual(result.state, "connected-limited")
        self.assertTrue(result.retry_allowed)
        self.assertFalse(result.credential_reset_allowed)

    def test_locked_keyring_never_enables_destructive_reset(self):
        result = self.diagnose(active=[], keyring="locked")

        self.assertEqual(result.state, "keyring-locked")
        self.assertFalse(result.credential_reset_allowed)

    def test_signed_out_and_missing_install_are_explained(self):
        signed_out = self.diagnose(active=[], keyring="missing")
        missing = self.diagnose(active=[], installed=False)

        self.assertEqual(signed_out.state, "signed-out")
        self.assertEqual(missing.state, "not-installed")


class FakeNetworkManager:
    def __init__(self, active=None):
        self.active = active or []

    def get_active_connections(self, callback):
        callback(self.active, None)

    def get_connectivity(self, callback):
        callback({"state": "connected", "connectivity": "full"}, None)


class RepairHarness(ProtonVpnClient):
    def __init__(self, active=None):
        super().__init__(FakeNetworkManager(active), log_path="/file/that/does/not/exist")
        self.commands = []
        self.stop_error = None
        self.command_errors = {}
        self.launch_error = None
        self.launches = 0

    def _stop_proton_gui(self, callback):
        callback(self.stop_error is None, self.stop_error)

    def _run_cli(self, args, callback):
        command = tuple(args)
        self.commands.append(command)
        callback("", self.command_errors.get(command))

    def _launch_proton_gui(self):
        self.launches += 1
        return self.launch_error


class RepairWorkflowTests(unittest.TestCase):
    active = [
        {
            "name": "ProtonVPN Test",
            "type": "wireguard",
            "uuid": "test-uuid",
            "device": "proton0",
        }
    ]

    def capture(self):
        result = []
        return result, lambda ok, error: result.append((ok, error))

    def test_retry_disconnects_active_tunnel_then_connects_and_reopens(self):
        client = RepairHarness(self.active)
        result, callback = self.capture()

        client.retry_connection(callback)

        self.assertEqual(client.commands, [("disconnect",), ("connect",)])
        self.assertEqual(client.launches, 1)
        self.assertEqual(result, [(True, None)])

    def test_retry_skips_disconnect_when_no_tunnel_is_active(self):
        client = RepairHarness()
        result, callback = self.capture()

        client.retry_connection(callback)

        self.assertEqual(client.commands, [("connect",)])
        self.assertEqual(result, [(True, None)])

    def test_reset_uses_only_official_signout_and_reopens(self):
        client = RepairHarness(self.active)
        result, callback = self.capture()

        client.reset_credentials(callback)

        self.assertEqual(client.commands, [("signout",)])
        self.assertEqual(client.launches, 1)
        self.assertEqual(result, [(True, None)])

    def test_failed_verified_shutdown_runs_no_cli_command(self):
        client = RepairHarness()
        client.stop_error = ProtonVpnError("refused")
        result, callback = self.capture()

        client.reset_credentials(callback)

        self.assertEqual(client.commands, [])
        self.assertEqual(client.launches, 0)
        self.assertFalse(result[0][0])

    def test_cli_failure_still_reopens_proton_and_returns_error(self):
        client = RepairHarness()
        expected = ProtonVpnError("connect failed")
        client.command_errors[("connect",)] = expected
        result, callback = self.capture()

        client.retry_connection(callback)

        self.assertEqual(client.launches, 1)
        self.assertEqual(result, [(False, expected)])


if __name__ == "__main__":
    unittest.main()
