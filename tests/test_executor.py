import hashlib
import json
import os
import socket
import threading
import time
import unittest
from pathlib import Path

from trackingos.evidence import CaseStore
from trackingos.executor import execute
from trackingos.fsutil import UnsafePathError
from trackingos.models import ActionRequest, ToolSpec
from trackingos.registry import ToolRegistry

from support import grant_for, install_recorder, private_dir, registry_for, scope_for


class ExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(private_dir())
        self.tools = Path(private_dir())
        self.data = Path(private_dir())
        self.recorder = install_recorder(self.tools)
        self.scope = scope_for(str(self.data))
        self.grant = grant_for(self.scope)
        self.registry = registry_for(self.recorder)
        self._old_secret = os.environ.get("SECRET_TOKEN")
        os.environ["SECRET_TOKEN"] = "super-secret-arg"

    def tearDown(self) -> None:
        if self._old_secret is None:
            os.environ.pop("SECRET_TOKEN", None)
        else:
            os.environ["SECRET_TOKEN"] = self._old_secret

    def run_action(self, arguments: tuple[str, ...], **kwargs: object):
        request = ActionRequest(
            tool=kwargs.pop("tool", "recorder"),  # type: ignore[arg-type]
            target=kwargs.pop("target", "ip:203.0.113.10"),  # type: ignore[arg-type]
            scope=kwargs.pop("scope", self.scope),  # type: ignore[arg-type]
            arguments=arguments,
            timeout_s=kwargs.pop("timeout_s", 5),  # type: ignore[arg-type]
            max_output_bytes=kwargs.pop("max_output_bytes", 1024 * 1024),  # type: ignore[arg-type]
        )
        return execute(
            request,
            kwargs.pop("registry", self.registry),  # type: ignore[arg-type]
            kwargs.pop("grant", self.grant),  # type: ignore[arg-type]
            cancel=kwargs.pop("cancel", None),  # type: ignore[arg-type]
            term_grace_s=kwargs.pop("term_grace_s", 0.4),  # type: ignore[arg-type]
            now=kwargs.pop("now", None),  # type: ignore[arg-type]
        )

    def test_arguments_are_not_a_shell_and_env_is_scrubbed(self) -> None:
        marker = self.tmp / "injected"
        payload_arg = f"$(touch {marker}); rm -rf /"
        result = self.run_action(("report", payload_arg, ";touch"))
        self.assertTrue(result.executed, result.reason)
        self.assertEqual(result.exit_code, 0)
        report = json.loads(result.stdout.decode())
        self.assertIn(payload_arg, report["argv"])
        self.assertNotIn("-c", report["argv"])
        self.assertFalse(report["argv"][0].endswith("/sh"))
        self.assertFalse(report["secret_present"])
        self.assertEqual(report["path"], "/usr/bin:/bin")
        self.assertFalse(marker.exists())
        self.assertNotIn("SECRET_TOKEN", report["env_keys"])
        parent_token = os.environ.get("GH_TOKEN")
        if parent_token:
            leaked = parent_token.encode() in result.stdout or parent_token.encode() in result.stderr
            self.assertFalse(leaked, "parent credential appeared in tool output")
        self.assertTrue(result.network_isolated)

    def test_denial_does_not_start_the_process(self) -> None:
        marker = self.tmp / "should-not-run"
        result = self.run_action(("marker", str(marker)), grant=None)
        self.assertFalse(result.executed)
        self.assertEqual(result.reason, "missing_grant")
        self.assertFalse(marker.exists())
        active = registry_for(self.recorder, operation="active", network="required")
        marker2 = self.tmp / "active"
        denied = self.run_action(("marker", str(marker2)), registry=active, grant=self.grant)
        self.assertEqual(denied.reason, "active_not_authorised")
        self.assertFalse(marker2.exists())
        marker3 = self.tmp / "target"
        outside = self.run_action(("marker", str(marker3)), target="ip:8.8.8.8")
        self.assertEqual(outside.reason, "target_out_of_scope")
        self.assertFalse(marker3.exists())

    def test_cancel_before_start_and_during_sleep(self) -> None:
        marker = self.tmp / "cancel"
        preset = threading.Event()
        preset.set()
        before = self.run_action(("marker", str(marker)), cancel=preset, timeout_s=30)
        self.assertEqual(before.reason, "cancelled")
        self.assertFalse(before.executed)
        self.assertFalse(marker.exists())
        cancel = threading.Event()
        box: dict[str, object] = {}

        def runner() -> None:
            box["result"] = self.run_action(("sleep", "30"), cancel=cancel, timeout_s=30)

        thread = threading.Thread(target=runner)
        thread.start()
        time.sleep(0.25)
        cancel.set()
        thread.join(8)
        self.assertFalse(thread.is_alive())
        result = box["result"]
        self.assertTrue(result.cancelled)  # type: ignore[attr-defined]
        self.assertTrue(result.executed)  # type: ignore[attr-defined]
        self.assertLess(time.monotonic(), time.monotonic() + 1)

    def test_timeout_kills_process_group_even_if_term_is_ignored(self) -> None:
        started = time.monotonic()
        result = self.run_action(("trap-sleep", "30"), timeout_s=0.4)
        elapsed = time.monotonic() - started
        self.assertTrue(result.timed_out)
        self.assertTrue(result.executed)
        self.assertLess(elapsed, 6)
        started = time.monotonic()
        spawned = self.run_action(("spawn-sleep", "30"), timeout_s=0.4)
        self.assertTrue(spawned.timed_out)
        child = int(spawned.stdout.splitlines()[0])
        self.assertFalse(os.path.exists(f"/proc/{child}"))
        self.assertLess(time.monotonic() - started, 6)

    def test_output_is_bounded(self) -> None:
        started = time.monotonic()
        result = self.run_action(("flood", "3000000"), max_output_bytes=100_000, timeout_s=10)
        self.assertTrue(result.stdout_truncated)
        self.assertLessEqual(len(result.stdout), 100_000)
        self.assertEqual(result.reason, "output_limited")
        self.assertLess(time.monotonic() - started, 8)

    def test_network_isolation_and_explicit_network_grant(self) -> None:
        host, port, listener = _listen()
        try:
            isolated = self.run_action(("connect", host, str(port)), grant=grant_for(self.scope, allow_network=True))
            self.assertTrue(isolated.executed, isolated.reason)
            self.assertIn(b"blocked", isolated.stdout)
            self.assertNotIn(b"connected", isolated.stdout)
            self.assertTrue(isolated.network_isolated)
            live_scope = scope_for(str(self.data), allow_active=True, cidrs=("127.0.0.1/32",))
            live_grant = grant_for(live_scope, allow_active=True, allow_network=True)
            live_registry = registry_for(self.recorder, operation="active", network="required")
            opened = self.run_action(
                ("connect", host, str(port)),
                scope=live_scope,
                grant=live_grant,
                registry=live_registry,
                target="ip:127.0.0.1",
            )
            self.assertTrue(opened.executed, opened.reason)
            self.assertIn(b"connected", opened.stdout)
            self.assertFalse(opened.network_isolated)
            blocked = self.run_action(
                ("connect", host, str(port)),
                scope=live_scope,
                grant=grant_for(live_scope, allow_active=True, allow_network=False),
                registry=live_registry,
                target="ip:127.0.0.1",
            )
            self.assertEqual(blocked.reason, "network_not_authorised")
            self.assertFalse(blocked.executed)
        finally:
            listener.close()

    def test_failure_exit_and_missing_or_unsafe_tool(self) -> None:
        failed = self.run_action(("fail",))
        self.assertTrue(failed.executed)
        self.assertEqual(failed.exit_code, 7)
        self.assertIn(b"nope", failed.stderr)
        missing = ToolRegistry(
            (ToolSpec("ghost", "/usr/bin/trackingos-missing-tool", "passive", "none", "none", ""),),
            ("/usr/bin",),
        )
        result = self.run_action(("report",), registry=missing, tool="ghost")
        self.assertEqual(result.reason, "tool_unavailable")
        self.assertFalse(result.executed)
        unsafe = install_recorder(self.tools, "unsafe.py")
        os.chmod(unsafe, 0o777)
        bad = ToolRegistry(
            (ToolSpec("unsafe", str(unsafe), "passive", "none", "none", ""),),
            (str(self.tools),),
        )
        with self.assertRaises(UnsafePathError):
            bad.open_executable(bad.get("unsafe"))  # type: ignore[arg-type]

    def test_action_record_omits_argument_values(self) -> None:
        secret = "super-secret-arg"
        result = self.run_action(("report", secret))
        store = CaseStore(str(self.data))
        case_id = store.create_case("Action", "Sam")
        record = {
            "schema": 1,
            "action_id": result.action_id,
            "tool": result.tool,
            "target": result.target,
            "scope_id": result.scope_id,
            "subject": result.subject,
            "client_reference": "",
            "started_at": result.started_at,
            "ended_at": result.ended_at,
            "executed": result.executed,
            "reason": result.reason,
            "exit_code": result.exit_code,
            "timed_out": False,
            "cancelled": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout_sha256": result.stdout_sha256,
            "stderr_sha256": result.stderr_sha256,
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
            "network_isolated": result.network_isolated,
            "argument_count": result.argument_count,
            "argument_sha256": result.argument_sha256,
        }
        store.record_action(case_id, record, result.stdout, result.stderr)
        raw = (Path(self.data) / case_id / "actions" / f"{result.action_id}.json").read_bytes()
        self.assertNotIn(secret.encode(), raw)
        self.assertIn(result.argument_sha256.encode(), raw)
        expected = hashlib.sha256(json.dumps(["report", secret], separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(result.argument_sha256, expected)
        store.close()

    def test_real_sha256sum_when_present(self) -> None:
        sha = "/usr/bin/sha256sum"
        if not os.access(sha, os.X_OK):
            self.skipTest("sha256sum is not installed")
        sample = self.data / "sample.bin"
        sample.write_bytes(b"trackingos")
        spec = ToolSpec("sha256sum", sha, "passive", "none", "absolute-only", "hash")
        registry = ToolRegistry((spec,), ("/usr/bin",))
        scope = scope_for(str(self.data))
        result = self.run_action(
            (str(sample),),
            tool="sha256sum",
            target=f"path:{sample}",
            scope=scope,
            grant=grant_for(scope),
            registry=registry,
        )
        self.assertTrue(result.executed, result.reason)
        self.assertEqual(result.exit_code, 0)
        digest = hashlib.sha256(b"trackingos").hexdigest()
        self.assertTrue(result.stdout.decode().startswith(digest))
        self.assertTrue(result.network_isolated)


def _listen() -> tuple[str, int, socket.socket]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    sock.settimeout(2)
    port = sock.getsockname()[1]
    threading.Thread(target=_accept, args=(sock,), daemon=True).start()
    return "127.0.0.1", port, sock


def _accept(sock: socket.socket) -> None:
    try:
        conn, _addr = sock.accept()
        conn.close()
    except OSError:
        pass


if __name__ == "__main__":
    unittest.main()
