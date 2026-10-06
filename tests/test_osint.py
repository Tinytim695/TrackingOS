import datetime as dt
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from trackingos.evidence import CaseStore, CollisionError
from trackingos.models import AuthorizationGrant
from trackingos.osint import (
    authorize_dns,
    decide_target,
    dns_lookup,
    load_programs,
    make_program,
    program_from_document,
    save_program,
    system_resolver,
)

from support import ROOT, private_dir, write_private

NOW = dt.datetime(2026, 10, 7, tzinfo=dt.timezone.utc)


def _program(**kwargs: object):
    values = dict(
        program_id="PROG-0123456789ABCDEF",
        case_id="TOS-20261007-ABCDEF01",
        name="Example",
        platform="hackerone",
        in_scope_domains=["*.example.com", "example.com"],
        out_of_scope_domains=["admin.example.com"],
        in_scope_cidrs=["203.0.113.0/24"],
        out_of_scope_cidrs=["203.0.113.5/32"],
        allow_dns=True,
        created_at="2026-10-07T00:00:00Z",
    )
    values.update(kwargs)
    return make_program(**values)  # type: ignore[arg-type]


def _grant(allow_network: bool = True) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id="GRT-0123456789ABCDEF",
        scope_id="lab-a",
        subject="investigator",
        allow_active=False,
        allow_network=allow_network,
        not_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_after=dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc),
    )


class ScopeTests(unittest.TestCase):
    def test_wildcard_boundaries_and_explicit_exclusions(self) -> None:
        program = _program()
        self.assertTrue(decide_target(program, "host:www.example.com").allowed)
        self.assertTrue(decide_target(program, "host:WWW.Example.COM").allowed)
        self.assertTrue(decide_target(program, "url:https://api.example.com/v1").allowed)
        self.assertTrue(decide_target(program, "host:example.com").allowed)
        self.assertEqual(decide_target(program, "host:example.com.evil.com").reason, "out_of_scope")
        self.assertEqual(decide_target(program, "host:notexample.com").reason, "out_of_scope")
        self.assertEqual(decide_target(program, "host:admin.example.com").reason, "explicitly_out_of_scope")
        apex_only = _program(in_scope_domains=["*.example.com"], out_of_scope_domains=[])
        self.assertFalse(decide_target(apex_only, "host:example.com").allowed)
        self.assertTrue(decide_target(program, "ip:203.0.113.10").allowed)
        self.assertEqual(decide_target(program, "ip:8.8.8.8").reason, "out_of_scope")
        self.assertEqual(decide_target(program, "ip:203.0.113.5").reason, "explicitly_out_of_scope")
        self.assertTrue(decide_target(program, "url:https://203.0.113.10/admin").allowed)

    def test_rejects_broad_or_smuggled_targets(self) -> None:
        with self.assertRaises(ValueError):
            _program(in_scope_domains=["*.com"])
        with self.assertRaises(ValueError):
            _program(in_scope_domains=["*.github.io"])
        with self.assertRaises(ValueError):
            _program(in_scope_cidrs=["0.0.0.0/0"])
        with self.assertRaises(ValueError):
            _program(in_scope_cidrs=["10.0.0.0/8"])
        program = _program()
        for target in (
            "url:https://user:pass@example.com/",
            "url:https://example.com%2eevil.com/",
            "url:http://example.com\\@evil.com/",
            "host:ex ample.com",
            "host:xn--e",
            "url:file:///etc/passwd",
            "url:https://example.com.evil.com/",
        ):
            with self.subTest(target=target):
                try:
                    decision = decide_target(program, target)
                except ValueError:
                    continue
                self.assertFalse(decision.allowed)

    def test_dns_does_not_resolve_when_refused(self) -> None:
        program = _program()
        called = {"n": 0}

        def resolver(host: str) -> tuple[str, ...]:
            called["n"] += 1
            raise AssertionError(host)

        refused = dns_lookup(program, "host:admin.example.com", _grant(), now=NOW, resolver=resolver)
        self.assertFalse(refused["executed"])
        self.assertEqual(called["n"], 0)
        no_grant = authorize_dns(program, "host:www.example.com", None, NOW)
        self.assertEqual(no_grant.reason, "missing_grant")
        quiet = _program(allow_dns=False)
        self.assertEqual(authorize_dns(quiet, "host:www.example.com", _grant(), NOW).reason, "dns_not_authorised")
        self.assertEqual(
            authorize_dns(program, "host:www.example.com", _grant(False), NOW).reason,
            "network_not_authorised",
        )
        expired = AuthorizationGrant(
            "GRT-0123456789ABCDEF",
            "lab-a",
            "investigator",
            False,
            True,
            dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
            dt.datetime(2020, 1, 2, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(authorize_dns(program, "host:www.example.com", expired, NOW).reason, "grant_expired")

    def test_resolved_addresses_are_not_promoted_into_scope(self) -> None:
        program = _program(in_scope_cidrs=[])
        result = dns_lookup(
            program,
            "host:www.example.com",
            _grant(),
            now=NOW,
            resolver=lambda _host: ("203.0.113.10", "8.8.8.8"),
        )
        self.assertTrue(result["executed"])
        self.assertEqual(result["outside_cidr"], ["203.0.113.10", "8.8.8.8"])

    def test_program_round_trip_refuses_active_and_overwrite(self) -> None:
        root = private_dir()
        with CaseStore(root) as store:
            case_id = store.create_case("Bounty", "Sam")
            program = _program(case_id=case_id)
            save_program(store, program)
            with self.assertRaises(CollisionError):
                save_program(store, program)
            loaded = load_programs(store, case_id)
        self.assertEqual(loaded[0].program_id, program.program_id)
        self.assertFalse(loaded[0].to_document()["allow_active"])
        document = program.to_document()
        document["allow_active"] = True
        with self.assertRaises(ValueError):
            program_from_document(document)
        self.assertIsNotNone(system_resolver)


class CliOsintTests(unittest.TestCase):
    def test_check_command_makes_no_dns_query(self) -> None:
        root = Path(private_dir())
        store = root / "cases"
        store.mkdir(mode=0o700)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        case = _run(
            ["case", "create", "--store", str(store), "--title", "Bounty", "--investigator", "Sam"],
            env,
        )
        self.assertEqual(case.returncode, 0, case.stderr)
        case_id = case.stdout.strip().splitlines()[0]
        added = _run(
            [
                "osint",
                "program",
                "--store",
                str(store),
                "--case",
                case_id,
                "--name",
                "Example",
                "--platform",
                "hackerone",
                "--domain",
                "*.example.com",
                "--out-domain",
                "admin.example.com",
            ],
            env,
        )
        self.assertEqual(added.returncode, 0, added.stderr)
        self.assertIn("allow_active: no", added.stdout)
        allowed = _run(
            ["osint", "check", "--store", str(store), "--case", case_id, "--target", "host:www.example.com"],
            env,
        )
        denied = _run(
            ["osint", "check", "--store", str(store), "--case", case_id, "--target", "host:admin.example.com"],
            env,
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertIn("allowed: yes", allowed.stdout)
        self.assertEqual(denied.returncode, 3, denied.stderr)
        self.assertIn("explicitly_out_of_scope", denied.stdout)
        brief = _run(["osint", "brief", "--store", str(store), "--case", case_id], env)
        self.assertIn("allow_active: no", brief.stdout)
        # A denied DNS lookup is recorded and does not require a successful query.
        grant = root / "grant.json"
        write_private(
            grant,
            json.dumps(
                {
                    "grant_id": "GRT-0123456789ABCDEF",
                    "scope_id": "lab-a",
                    "subject": "investigator",
                    "allow_active": False,
                    "allow_network": True,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                }
            ),
        )
        looked = _run(
            [
                "osint",
                "dns",
                "--store",
                str(store),
                "--case",
                case_id,
                "--grant",
                str(grant),
                "--target",
                "host:evil.example",
            ],
            env,
        )
        self.assertEqual(looked.returncode, 3, looked.stderr + looked.stdout)
        self.assertIn("reason: out_of_scope", looked.stdout)
        self.assertIn("evidence_id:", looked.stdout)


def _run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "trackingos", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


if __name__ == "__main__":
    unittest.main()
