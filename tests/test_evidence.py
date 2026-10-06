import os
import stat
import threading
import unittest
from pathlib import Path

from trackingos.evidence import CaseStore, CollisionError
from trackingos.fsutil import UnsafePathError

from support import private_dir


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = private_dir()
        self.store = CaseStore(self.root)

    def tearDown(self) -> None:
        self.store.close()

    def test_round_trip_permissions_and_timeline(self) -> None:
        case_id = self.store.create_case("Intrusion 14", "A. Investigator", "desk review")
        evidence_id = self.store.add_evidence_bytes(
            case_id, b"disk-image", "operator", "image.bin"
        )
        self.store.add_note(case_id, "First look is clean.", "A. Investigator")
        self.store.add_finding(case_id, "No malware hash hit", "YARA core rules.", "A. Investigator")
        report = self.store.verify_evidence(case_id, evidence_id)
        self.assertTrue(report.ok, report.problems)
        payload = Path(self.root) / case_id / "evidence" / evidence_id / "payload"
        self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((Path(self.root) / case_id).stat().st_mode), 0o700)
        kinds = {item["kind"] for item in self.store.timeline(case_id)}
        self.assertEqual(kinds, {"case", "evidence", "finding", "note"})

    def test_file_ingest_and_refuse_symlink_source(self) -> None:
        case_id = self.store.create_case("File", "Sam")
        source = Path(self.root) / "source.bin"
        source.write_bytes(b"abc")
        evidence_id = self.store.add_evidence_file(case_id, source, "copy")
        self.assertTrue(self.store.verify_evidence(case_id, evidence_id).ok)
        link = Path(self.root) / "linked"
        link.symlink_to(source)
        with self.assertRaises(UnsafePathError):
            self.store.add_evidence_file(case_id, link, "copy")

    def test_never_overwrites_evidence(self) -> None:
        case_id = self.store.create_case("Collision", "Sam")
        evidence_id = "EV-0123456789ABCDEF"
        self.store.add_evidence_bytes(case_id, b"original", "lab", "a.bin", evidence_id=evidence_id)
        with self.assertRaises(CollisionError):
            self.store.add_evidence_bytes(case_id, b"replaced", "lab", "a.bin", evidence_id=evidence_id)
        self.assertTrue(self.store.verify_evidence(case_id, evidence_id).ok)
        payload = Path(self.root) / case_id / "evidence" / evidence_id / "payload"
        self.assertEqual(payload.read_bytes(), b"original")

    def test_detects_tamper(self) -> None:
        case_id = self.store.create_case("Tamper", "Sam")
        evidence_id = self.store.add_evidence_bytes(case_id, b"original", "lab", "a.bin")
        payload = Path(self.root) / case_id / "evidence" / evidence_id / "payload"
        payload.write_bytes(b"mutated!")
        report = self.store.verify_evidence(case_id, evidence_id)
        self.assertFalse(report.ok)
        self.assertIn("sha256 mismatch", report.problems)

    def test_refuses_symlink_layout_and_traversal(self) -> None:
        case_id = self.store.create_case("Layout", "Sam")
        outside = Path(self.root) / "outside"
        outside.mkdir()
        canary = outside / "canary"
        canary.write_text("safe")
        evidence = Path(self.root) / case_id / "evidence"
        real = Path(self.root) / "real-evidence"
        os.rename(evidence, real)
        os.symlink(outside, evidence)
        with self.assertRaises(UnsafePathError):
            self.store.add_evidence_bytes(case_id, b"x", "lab", "a.bin")
        self.assertEqual(list(outside.iterdir()), [canary])
        self.assertEqual(canary.read_text(), "safe")
        with self.assertRaises(ValueError):
            self.store.create_case("Bad", "Sam", case_id="../TOS-00000000-00000000")
        with self.assertRaises(ValueError):
            self.store.create_case("Bad", "Sam", case_id="TOS-20260101-ABC")

    def test_refuses_symlink_or_world_writable_root(self) -> None:
        link = Path(self.root) / "alias"
        os.symlink(self.root, link)
        with self.assertRaises(UnsafePathError):
            CaseStore(link)
        os.chmod(self.root, 0o707)
        with self.assertRaises(UnsafePathError):
            CaseStore(self.root)

    def test_payload_symlink_is_not_followed(self) -> None:
        case_id = self.store.create_case("Payload", "Sam")
        evidence_id = self.store.add_evidence_bytes(case_id, b"original", "lab", "a.bin")
        payload = Path(self.root) / case_id / "evidence" / evidence_id / "payload"
        payload.unlink()
        payload.symlink_to("/etc/passwd")
        with self.assertRaises(UnsafePathError):
            self.store.verify_evidence(case_id, evidence_id)

    def test_concurrent_evidence_ids_do_not_collide(self) -> None:
        case_id = self.store.create_case("Parallel", "Sam")
        found: list[str] = []
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                found.append(self.store.add_evidence_bytes(case_id, b"x", "lab", "a.bin"))
            except BaseException as exc:  # noqa: BLE001 - collect and fail the test
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(found), len(set(found)))


if __name__ == "__main__":
    unittest.main()
