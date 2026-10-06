import datetime as dt
import unittest

from trackingos.models import ActionRequest
from trackingos.policy import evaluate

from support import grant_for, private_dir, scope_for


NOW = dt.datetime(2026, 10, 6, tzinfo=dt.timezone.utc)


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = private_dir()
        sample = __import__("pathlib").Path(self.data) / "sample.bin"
        sample.write_bytes(b"abc")
        self.sample = str(sample)
        self.scope = scope_for(self.data)

    def request(self, **kwargs: object) -> ActionRequest:
        values = dict(
            tool="recorder",
            target="ip:203.0.113.10",
            scope=self.scope,
            arguments=(),
            timeout_s=5,
        )
        values.update(kwargs)
        return ActionRequest(**values)  # type: ignore[arg-type]

    def test_request_has_no_authorisation_flag(self) -> None:
        self.assertNotIn("authorised", ActionRequest.__dataclass_fields__)
        self.assertNotIn("allow_active", ActionRequest.__dataclass_fields__)
        self.assertNotIn("allow_network", ActionRequest.__dataclass_fields__)

    def test_missing_grant_and_bad_shapes(self) -> None:
        self.assertEqual(evaluate(self.request(), None, None, NOW).reason, "tool_unknown")
        self.assertEqual(evaluate(self.request(tool="Bad Tool"), None, None, NOW).reason, "tool_name_invalid")
        self.assertEqual(evaluate(self.request(timeout_s=0), None, None, NOW).reason, "timeout_invalid")
        self.assertEqual(evaluate(self.request(arguments=("a\x00b",)), None, None, NOW).reason, "arguments_invalid")
        self.assertEqual(evaluate(self.request(target="8.8.8.8"), None, None, NOW).reason, "target_invalid")
        self.assertEqual(evaluate(self.request(target="ip:0.0.0.0"), None, None, NOW).reason, "target_invalid")

    def test_scope_and_grant_narrowing(self) -> None:
        from trackingos.models import ToolSpec

        passive = ToolSpec("recorder", "/usr/bin/recorder", "passive", "none", "none", "")
        active = ToolSpec("nmap", "/usr/bin/nmap", "active", "required", "none", "")
        grant = grant_for(self.scope)
        self.assertTrue(evaluate(self.request(), passive, grant, NOW).allowed)
        denied = evaluate(self.request(target="ip:8.8.8.8"), passive, grant, NOW)
        self.assertEqual(denied.reason, "target_out_of_scope")
        self.assertEqual(evaluate(self.request(target="host:other.example"), passive, grant, NOW).reason, "target_out_of_scope")
        self.assertEqual(evaluate(self.request(target="host:localhost"), passive, grant, NOW).reason, "target_out_of_scope")
        self.assertEqual(
            evaluate(self.request(tool="nmap"), active, grant, NOW).reason,
            "active_not_authorised",
        )
        widened = grant_for(self.scope, allow_active=True, allow_network=True)
        # The grant cannot widen a scope that forbids active work.
        self.assertEqual(
            evaluate(self.request(tool="nmap"), active, widened, NOW).reason,
            "active_not_authorised",
        )
        live = scope_for(self.data, allow_active=True)
        live_grant = grant_for(live, allow_active=True, allow_network=False)
        self.assertEqual(
            evaluate(self.request(tool="nmap", scope=live), active, live_grant, NOW).reason,
            "network_not_authorised",
        )
        networked = grant_for(live, allow_active=True, allow_network=True)
        decision = evaluate(self.request(tool="nmap", scope=live), active, networked, NOW)
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.isolate_network)
        local = evaluate(self.request(), passive, grant_for(self.scope, allow_network=True), NOW)
        self.assertTrue(local.isolate_network)

    def test_grant_window_and_path_confinement(self) -> None:
        from trackingos.models import ToolSpec

        tool = ToolSpec("sha256sum", "/usr/bin/sha256sum", "passive", "none", "absolute-only", "")
        grant = grant_for(self.scope)
        expired = grant_for(self.scope, not_after=dt.datetime(2020, 1, 2, tzinfo=dt.timezone.utc))
        self.assertEqual(
            evaluate(self.request(tool="sha256sum"), tool, expired, NOW).reason,
            "grant_expired",
        )
        early = grant_for(self.scope, not_before=dt.datetime(2090, 1, 1, tzinfo=dt.timezone.utc))
        self.assertEqual(
            evaluate(self.request(tool="sha256sum"), tool, early, NOW).reason,
            "grant_not_yet_valid",
        )
        ok = evaluate(
            self.request(tool="sha256sum", target=f"path:{self.sample}", arguments=(self.sample,)),
            tool,
            grant,
            NOW,
        )
        self.assertTrue(ok.allowed)
        outside = "/etc/passwd"
        denied = evaluate(
            self.request(tool="sha256sum", target=f"path:{outside}", arguments=(outside,)),
            tool,
            grant,
            NOW,
        )
        self.assertEqual(denied.reason, "path_out_of_scope")
        link = __import__("pathlib").Path(self.data) / "escape"
        link.symlink_to("/etc/passwd")
        via_link = evaluate(
            self.request(tool="sha256sum", target=f"path:{link}", arguments=(str(link),)),
            tool,
            grant,
            NOW,
        )
        self.assertEqual(via_link.reason, "path_out_of_scope")

    def test_policy_does_not_resolve_dns(self) -> None:
        source = (ROOT() / "src" / "trackingos" / "policy.py").read_text(encoding="utf-8")
        self.assertNotIn("getaddrinfo", source)
        self.assertNotIn("socket.", source)


def ROOT():
    from pathlib import Path

    return Path(__file__).resolve().parents[1]


if __name__ == "__main__":
    unittest.main()
