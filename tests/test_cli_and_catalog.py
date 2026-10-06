import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from trackingos.build_host import REQUIRED_COMMANDS, assess_build_host
from trackingos.evidence import CaseStore
from trackingos.loaders import load_grant, load_scope
from trackingos.registry import ToolRegistry

from support import ROOT, install_recorder, private_dir, write_private


class CatalogTests(unittest.TestCase):
    def test_ready_host_is_not_an_iso_build(self) -> None:
        report = assess_build_host(lambda name: f"/usr/bin/{name}")
        self.assertTrue(report["iso_build_ready"])
        self.assertFalse(report["iso_built"])
        self.assertEqual(tuple(report["commands"]), REQUIRED_COMMANDS)

    def test_package_tiers_do_not_claim_availability(self) -> None:
        document = json.loads((ROOT / "config" / "package-tiers.json").read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], 1)
        names = []
        for tool in document["tools"]:
            names.append(tool["name"])
            self.assertIn(tool["tier"], {"core", "extended", "specialist", "lab"})
            self.assertEqual(tool["availability"], "unverified")
            self.assertNotIn("0.0.0.0/0", json.dumps(tool))
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("nmap", names)
        self.assertIn("yara", names)
        self.assertIn("metasploit", names)
        metasploit = next(item for item in document["tools"] if item["name"] == "metasploit")
        self.assertEqual(metasploit["tier"], "lab")
        masscan = next(item for item in document["tools"] if item["name"] == "masscan")
        self.assertEqual(masscan["tier"], "lab")

    def test_source_has_no_shell_execution(self) -> None:
        root = ROOT / "src" / "trackingos"
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text, path.name)
            self.assertNotIn("os.system(", text, path.name)
            self.assertNotIn("subprocess.getoutput", text, path.name)
            self.assertNotIn("subprocess.getstatusoutput", text, path.name)
        executor = (root / "executor.py").read_text(encoding="utf-8")
        self.assertIn("shell=False", executor)


class LoaderTests(unittest.TestCase):
    def test_grant_must_be_private_and_boolean(self) -> None:
        root = Path(private_dir())
        data = Path(private_dir())
        scope_path = root / "scope.json"
        grant_path = root / "grant.json"
        write_private(
            scope_path,
            json.dumps(
                {
                    "scope_id": "lab-a",
                    "network_cidrs": ["203.0.113.0/24"],
                    "hostnames": ["Lab.Example"],
                    "local_roots": [str(data)],
                    "labs": ["lab-a"],
                    "allow_active": False,
                }
            ),
            0o644,
        )
        scope = load_scope(str(scope_path))
        self.assertEqual(scope.hostnames, ("lab.example",))
        write_private(
            grant_path,
            json.dumps(
                {
                    "grant_id": "GRT-0123456789ABCDEF",
                    "scope_id": "lab-a",
                    "subject": "investigator",
                    "allow_active": "true",
                    "allow_network": False,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                }
            ),
        )
        with self.assertRaises(ValueError):
            load_grant(str(grant_path))
        os.chmod(grant_path, 0o600)
        # Replace with a real boolean but group-readable mode.
        grant_path.unlink()
        write_private(
            grant_path,
            json.dumps(
                {
                    "grant_id": "GRT-0123456789ABCDEF",
                    "scope_id": "lab-a",
                    "subject": "investigator",
                    "allow_active": False,
                    "allow_network": False,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                }
            ),
            0o640,
        )
        with self.assertRaises(Exception):
            load_grant(str(grant_path))
        wide = root / "wide.json"
        write_private(
            wide,
            json.dumps(
                {
                    "scope_id": "lab-a",
                    "network_cidrs": [],
                    "hostnames": [],
                    "local_roots": ["/"],
                    "labs": [],
                    "allow_active": False,
                }
            ),
            0o644,
        )
        with self.assertRaises(ValueError):
            load_scope(str(wide))


class CliTests(unittest.TestCase):
    def test_case_evidence_and_denied_action_are_recorded(self) -> None:
        root = Path(private_dir())
        store = root / "cases"
        store.mkdir(mode=0o700)
        tools = Path(private_dir())
        data = Path(private_dir())
        recorder = install_recorder(tools)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        case = _run(
            ["case", "create", "--store", str(store), "--title", "Desk", "--investigator", "Sam"],
            env,
        )
        self.assertEqual(case.returncode, 0, case.stderr)
        case_id = case.stdout.strip()
        sample = data / "note.txt"
        sample.write_text("hello")
        added = _run(
            [
                "evidence",
                "add",
                "--store",
                str(store),
                "--case",
                case_id,
                "--file",
                str(sample),
                "--source",
                "desk",
            ],
            env,
        )
        self.assertEqual(added.returncode, 0, added.stderr)
        evidence_id = added.stdout.strip()
        verified = _run(
            ["evidence", "verify", "--store", str(store), "--case", case_id, "--evidence", evidence_id],
            env,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        scope = root / "scope.json"
        grant = root / "grant.json"
        registry = root / "registry.json"
        from support import write_private as write

        write(
            scope,
            json.dumps(
                {
                    "scope_id": "lab-a",
                    "network_cidrs": ["203.0.113.0/24"],
                    "hostnames": [],
                    "local_roots": [str(data)],
                    "labs": ["lab-a"],
                    "allow_active": False,
                }
            ),
            0o644,
        )
        write(
            grant,
            json.dumps(
                {
                    "grant_id": "GRT-0123456789ABCDEF",
                    "scope_id": "lab-a",
                    "subject": "investigator",
                    "allow_active": False,
                    "allow_network": False,
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2099-01-01T00:00:00Z",
                }
            ),
        )
        write(
            registry,
            json.dumps(
                {
                    "schema": 1,
                    "allowed_executable_roots": [str(tools)],
                    "tools": [
                        {
                            "name": "recorder",
                            "executable": str(recorder),
                            "operation": "passive",
                            "network": "none",
                            "path_policy": "none",
                            "summary": "fixture",
                        }
                    ],
                }
            ),
            0o644,
        )
        marker = root / "nope"
        denied = _run(
            [
                "action",
                "run",
                "--store",
                str(store),
                "--case",
                case_id,
                "--registry",
                str(registry),
                "--scope",
                str(scope),
                "--grant",
                str(grant),
                "--tool",
                "recorder",
                "--target",
                "ip:8.8.8.8",
                "--",
                "marker",
                str(marker),
            ],
            env,
        )
        self.assertEqual(denied.returncode, 3, denied.stderr + denied.stdout)
        self.assertIn("reason: target_out_of_scope", denied.stdout)
        self.assertFalse(marker.exists())
        with CaseStore(str(store)) as cases:
            actions = cases.timeline(case_id)
        self.assertTrue(any(item["kind"] == "action" and item["executed"] is False for item in actions))
        loaded = ToolRegistry.load(str(registry))
        self.assertEqual(loaded.names(), ("recorder",))


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
