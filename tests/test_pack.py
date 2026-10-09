"""Ordinary local fixtures. No external data, network, archive extraction or execution."""

import hashlib
import io
import json
import os
import tempfile
import unittest
from collections import UserList
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from evidence_pack import (
    CreationIncompleteError,
    DestinationExistsError,
    InputError,
    create_pack,
    load_findings,
    verify_pack,
)
from evidence_pack._paths import CHUNK_SIZE, portable_path
from evidence_pack.cli import main
from evidence_pack.core import DECLARATION, TAG_FILES


class PackTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        # Resolve OS aliases in the fixture root (e.g. macOS /var -> /private/var).
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "nota.txt").write_text("Evidencia sintética.\n", encoding="utf-8")
        self.destination = self.root / "pack"
        self.findings = {"OBS-001": ["nota.txt"]}

    def tearDown(self):
        self.temporary.cleanup()

    def create(self):
        return create_pack(self.source, self.destination, self.findings)

    def codes(self):
        return {issue.code for issue in verify_pack(self.destination).issues}

    def refresh_tagmanifest(self):
        entries = []
        for name in sorted(TAG_FILES):
            digest = hashlib.sha256((self.destination / name).read_bytes()).hexdigest()
            entries.append(f"{digest}  {name}\n")
        (self.destination / "tagmanifest-sha256.txt").write_text("".join(entries), encoding="utf-8")

    def test_round_trip_and_source_unchanged(self):
        before = (self.source / "nota.txt").read_bytes()
        report = self.create()
        self.assertTrue(report.valid)
        self.assertEqual(report.payload_files, 1)
        self.assertEqual(report.payload_bytes, len(before))
        self.assertEqual(report.findings, 1)
        self.assertEqual(report.referenced_files, 1)
        self.assertEqual(before, (self.source / "nota.txt").read_bytes())
        self.assertEqual(report, verify_pack(self.destination))
        self.assertEqual(
            {p.name for p in self.destination.iterdir()},
            {"data", *TAG_FILES, "tagmanifest-sha256.txt"},
        )

    def test_manifest_is_sha256_of_raw_bytes(self):
        (self.source / "nota.txt").write_bytes(b"\x00\xff\r\n\x00")
        self.create()
        expected = hashlib.sha256(b"\x00\xff\r\n\x00").hexdigest()
        self.assertEqual(
            (self.destination / "manifest-sha256.txt").read_text(), f"{expected}  data/nota.txt\n"
        )

    def test_nested_unicode_space_and_zero_byte_files(self):
        folder = self.source / "área común"
        folder.mkdir()
        (folder / "vacío.txt").write_bytes(b"")
        self.findings["OBS-002"] = ["área común/vacío.txt"]
        self.assertTrue(self.create().valid)

    def test_streaming_file_larger_than_buffer(self):
        large = b"01234567" * (CHUNK_SIZE // 8 + 73)
        (self.source / "large.bin").write_bytes(large)
        self.findings["OBS-002"] = ["large.bin"]
        report = self.create()
        self.assertTrue(report.valid)
        self.assertEqual((self.destination / "data/large.bin").read_bytes(), large)

    def test_unreferenced_payload_is_allowed_and_counted(self):
        (self.source / "context.txt").write_text("context", encoding="utf-8")
        report = self.create()
        self.assertEqual((report.payload_files, report.referenced_files), (2, 1))

    def test_deterministic_bytes_and_reports(self):
        report = self.create()
        other = self.root / "pack-two"
        second = create_pack(self.source, other, self.findings)
        self.assertEqual(report.to_dict(), second.to_dict())
        for file in self.destination.rglob("*"):
            if file.is_file():
                self.assertEqual(
                    file.read_bytes(), (other / file.relative_to(self.destination)).read_bytes()
                )

    def test_existing_empty_destination_is_not_replaced(self):
        self.destination.mkdir()
        with self.assertRaises(DestinationExistsError):
            self.create()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_existing_destination_file_is_untouched(self):
        self.destination.write_text("keep", encoding="utf-8")
        with self.assertRaises(DestinationExistsError):
            self.create()
        self.assertEqual(self.destination.read_text(), "keep")

    def test_overlap_is_rejected_before_creation(self):
        for target in (self.source, self.source / "inside", self.root):
            with self.subTest(target=target), self.assertRaises(InputError) as caught:
                create_pack(self.source, target, self.findings)
            self.assertEqual(caught.exception.issue.code, "overlapping_paths")
        self.assertFalse((self.source / "inside").exists())

    def test_source_must_be_directory(self):
        with self.assertRaises(InputError):
            create_pack(self.source / "nota.txt", self.destination, self.findings)
        self.assertFalse(self.destination.exists())

    def test_missing_parent_is_rejected(self):
        with self.assertRaises(InputError):
            create_pack(self.source, self.root / "absent" / "pack", self.findings)
        self.assertFalse((self.root / "absent").exists())

    def test_invalid_input_findings_do_not_create_destination(self):
        cases = [
            {},
            {"": ["nota.txt"]},
            {"A": []},
            {"A": "nota.txt"},
            {"A": [1]},
            {"A": ["nota.txt", "nota.txt"]},
            {"A": ["missing"]},
            {"A": ["../nota.txt"]},
            {"A": ["data/nota.txt"]},
            {"ñ": ["nota.txt"]},
        ]
        for findings in cases:
            with self.subTest(findings=findings), self.assertRaises(InputError):
                create_pack(self.source, self.destination, findings)
            self.assertFalse(self.destination.exists())

    def test_nonportable_paths_are_rejected(self):
        cases = [
            "",
            "/etc/passwd",
            "../a",
            "a/../b",
            "a//b",
            "a/./b",
            "a/",
            "C:/a",
            "a\\b",
            "a%20b",
            "a\nb",
            "a\rb",
            "a\tb",
            "a\u2028b",
            "e\u0301.txt",
            " a",
            "a ",
            "a.",
            "a/CON.txt",
            "LPT1",
            "com².txt",
            "aux .txt",
            "a\x00b",
            "a\u200eb",
            "a?b",
            "a\udcff",
        ]
        for value in cases:
            with self.subTest(path=repr(value)), self.assertRaises(InputError):
                portable_path(value)

    def test_casefold_collision_is_rejected(self):
        other = self.source / "NOTA.TXT"
        other.write_text("other", encoding="utf-8")
        if len(list(self.source.iterdir())) < 2:
            self.skipTest("Filesystem does not allow case-distinct names")
        with self.assertRaises(InputError) as caught:
            self.create()
        self.assertEqual(caught.exception.issue.code, "path_collision")

    def test_directory_casefold_collision_is_rejected(self):
        (self.source / "Folder").mkdir()
        try:
            (self.source / "folder").mkdir()
        except FileExistsError:
            self.skipTest("Filesystem does not allow case-distinct names")
        with self.assertRaises(InputError) as caught:
            self.create()
        self.assertEqual(caught.exception.issue.code, "path_collision")

    def make_link(self, target, link, *, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable in this environment")

    def test_source_symlink_file_and_directory_rejected(self):
        self.make_link(self.source / "nota.txt", self.source / "link")
        with self.assertRaises(InputError) as caught:
            self.create()
        self.assertEqual(caught.exception.issue.code, "unsupported_entry")
        (self.source / "link").unlink()
        self.make_link(self.root, self.source / "link", directory=True)
        with self.assertRaises(InputError):
            self.create()

    def test_source_symlink_root_rejected(self):
        alias = self.root / "alias"
        self.make_link(self.source, alias, directory=True)
        with self.assertRaises(InputError):
            create_pack(alias, self.destination, self.findings)

    def test_destination_symlink_or_ancestor_rejected(self):
        alias = self.root / "alias"
        self.make_link(self.source, alias, directory=True)
        with self.assertRaises(InputError):
            create_pack(self.source, alias / "pack", self.findings)
        self.make_link(self.root / "not-here", self.destination)
        with self.assertRaises(DestinationExistsError):
            self.create()

    def test_hardlinks_rejected(self):
        try:
            os.link(self.source / "nota.txt", self.source / "hardlink")
        except OSError:
            self.skipTest("Hardlinks unavailable")
        with self.assertRaises(InputError) as caught:
            self.create()
        self.assertEqual(caught.exception.issue.code, "unsupported_entry")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation unavailable")
    def test_fifo_rejected_without_opening(self):
        os.mkfifo(self.source / "pipe")
        with self.assertRaises(InputError):
            self.create()

    def test_partial_creation_is_retained_and_invalid(self):
        with (
            patch("evidence_pack.core._write_new", side_effect=OSError("simulated disk failure")),
            self.assertRaises(CreationIncompleteError),
        ):
            self.create()
        self.assertTrue(self.destination.exists())
        self.assertFalse((self.destination / "bagit.txt").exists())
        self.assertFalse(verify_pack(self.destination).valid)
        self.assertTrue((self.source / "nota.txt").exists())

    def test_source_mutation_is_reported(self):
        from evidence_pack import core

        original_inventory = core.inventory
        calls = 0

        def mutate(root):
            nonlocal calls
            calls += 1
            if calls == 2:
                (self.source / "nota.txt").write_text("changed", encoding="utf-8")
            return original_inventory(root)

        with (
            patch("evidence_pack.core.inventory", side_effect=mutate),
            self.assertRaises(CreationIncompleteError) as caught,
        ):
            self.create()
        self.assertEqual(caught.exception.__cause__.issue.code, "source_changed")
        self.assertFalse((self.destination / "bagit.txt").exists())

    def test_modified_payload_fails(self):
        self.create()
        (self.destination / "data/nota.txt").write_text("changed", encoding="utf-8")
        self.assertIn("checksum_mismatch", self.codes())

    def test_missing_and_unlisted_payload(self):
        self.create()
        (self.destination / "data/nota.txt").unlink()
        (self.destination / "data/extra.txt").write_bytes(b"x")
        self.assertTrue(
            {"missing_payload", "unlisted_payload", "missing_reference"} <= self.codes()
        )

    def test_changed_index_is_covered_by_tag_manifest(self):
        self.create()
        index = self.destination / "index.json"
        data = json.loads(index.read_text())
        data["findings"] = {"OTHER": ["data/nota.txt"]}
        index.write_text(json.dumps(data), encoding="utf-8")
        self.assertIn("checksum_mismatch", self.codes())

    def test_manifest_and_index_tampering_together_is_not_authentication(self):
        self.create()
        (self.destination / "data/nota.txt").write_bytes(b"replaced")
        digest = hashlib.sha256(b"replaced").hexdigest()
        (self.destination / "manifest-sha256.txt").write_text(
            f"{digest}  data/nota.txt\n", encoding="utf-8"
        )
        self.refresh_tagmanifest()
        self.assertTrue(verify_pack(self.destination).valid)

    def test_missing_required_tag(self):
        self.create()
        (self.destination / "tagmanifest-sha256.txt").unlink()
        self.assertIn("missing_file", self.codes())

    def test_extra_tag_and_fetch_are_rejected_without_network(self):
        self.create()
        (self.destination / "fetch.txt").write_text(
            "https://example.invalid/ 1 data/a\n", encoding="utf-8"
        )
        self.assertIn("unexpected_file", self.codes())

    def test_extra_root_directory_rejected(self):
        self.create()
        (self.destination / "extra").mkdir()
        self.assertIn("unexpected_directory", self.codes())

    def test_symlink_bag_payload_rejected(self):
        self.create()
        target = self.destination / "data/nota.txt"
        target.unlink()
        self.make_link(self.source / "nota.txt", target)
        self.assertIn("unsupported_entry", self.codes())

    def test_index_duplicate_json_keys_rejected(self):
        self.create()
        (self.destination / "index.json").write_text(
            '{"profile":"evidence-pack/1","findings":{"A":["data/nota.txt"],"A":["data/nota.txt"]}}',
            encoding="utf-8",
        )
        self.refresh_tagmanifest()
        self.assertIn("invalid_index", self.codes())

    def test_manifest_duplicate_and_traversal_rejected(self):
        self.create()
        file = self.destination / "manifest-sha256.txt"
        original = file.read_text()
        file.write_text(original + original, encoding="utf-8")
        self.assertIn("duplicate_manifest_entry", self.codes())
        file.write_text("0" * 64 + "  data/../index.json\n", encoding="utf-8")
        self.assertIn("unsafe_path", self.codes())

    def test_tag_manifest_cannot_reference_payload_or_itself(self):
        self.create()
        for path in ("data/nota.txt", "tagmanifest-sha256.txt"):
            (self.destination / "tagmanifest-sha256.txt").write_text(
                "0" * 64 + f"  {path}\n", encoding="utf-8"
            )
            self.assertIn("invalid_manifest", self.codes())

    def test_omitted_tag_manifest_entry_rejected(self):
        self.create()
        tags = self.destination / "tagmanifest-sha256.txt"
        tags.write_text(
            "".join(
                line
                for line in tags.read_text().splitlines(keepends=True)
                if not line.endswith("  index.json\n")
            ),
            encoding="utf-8",
        )
        self.assertIn("unlisted_tag", self.codes())

    def test_uppercase_digests_and_crlf_are_accepted(self):
        self.create()
        manifest = self.destination / "manifest-sha256.txt"
        digest, path = manifest.read_text().strip().split("  ")
        manifest.write_bytes(f"{digest.upper()}\t{path}\r\n".encode())
        (self.destination / "bagit.txt").write_bytes(DECLARATION.replace(b"\n", b"\r\n"))
        self.refresh_tagmanifest()
        self.assertTrue(verify_pack(self.destination).valid)

    def test_invalid_declaration_rejected(self):
        self.create()
        (self.destination / "bagit.txt").write_bytes(DECLARATION.replace(b"1.0", b"0.97"))
        self.assertIn("unsupported_declaration", self.codes())

    def test_malformed_utf8_metadata_becomes_report(self):
        self.create()
        (self.destination / "index.json").write_bytes(b"\xff")
        self.assertIn("invalid_index", self.codes())
        (self.destination / "manifest-sha256.txt").write_bytes(b"\xff")
        self.assertIn("invalid_manifest", self.codes())

    def test_metadata_limit(self):
        self.create()
        with patch("evidence_pack.core.INDEX_LIMIT", 5):
            self.assertIn("resource_limit", self.codes())

    def test_tree_entry_limit(self):
        with (
            patch("evidence_pack._paths.MAX_ENTRIES", 0),
            self.assertRaises(InputError) as caught,
        ):
            self.create()
        self.assertEqual(caught.exception.issue.code, "resource_limit")

    def test_output_entry_overhead_checked_before_reserving(self):
        with (
            patch("evidence_pack._paths.MAX_ENTRIES", 5),
            self.assertRaises(InputError) as caught,
        ):
            self.create()
        self.assertEqual(caught.exception.issue.code, "resource_limit")
        self.assertFalse(self.destination.exists())
        with patch("evidence_pack._paths.MAX_ENTRIES", 6):
            self.assertTrue(self.create().valid)

    def test_output_path_depth_checked_before_reserving(self):
        with (
            patch("evidence_pack._paths.MAX_DEPTH", 1),
            self.assertRaises(InputError) as caught,
        ):
            self.create()
        self.assertEqual(caught.exception.issue.code, "resource_limit")
        self.assertFalse(self.destination.exists())

    def test_output_manifest_size_checked_before_reserving(self):
        with (
            patch("evidence_pack.core.MANIFEST_LIMIT", 1),
            self.assertRaises(InputError) as caught,
        ):
            self.create()
        self.assertEqual(caught.exception.issue.code, "resource_limit")
        self.assertFalse(self.destination.exists())

    def test_empty_directories_are_not_preserved(self):
        (self.source / "empty").mkdir()
        self.create()
        self.assertFalse((self.destination / "data/empty").exists())

    def test_only_rfc_line_separators_accepted(self):
        self.create()
        manifest = self.destination / "manifest-sha256.txt"
        manifest.write_text(manifest.read_text().replace("\n", "\u2028"), encoding="utf-8")
        self.assertIn("unsafe_path", self.codes())

    def test_invalid_unicode_roots_return_typed_results(self):
        for root in ("bad\x00root", "bad\ud800root"):
            with self.subTest(root=repr(root)):
                self.assertEqual(verify_pack(root).issues[0].code, "unsafe_path")
                with self.assertRaises(InputError):
                    load_findings(root)
                with self.assertRaises(InputError):
                    create_pack(root, self.destination, self.findings)

    def test_python_api_accepts_nonstring_sequences(self):
        report = create_pack(self.source, self.destination, {"F1": UserList(["nota.txt"])})
        self.assertTrue(report.valid)

    def test_missing_bag_returns_invalid_report(self):
        report = verify_pack(self.destination)
        self.assertFalse(report.valid)
        self.assertEqual(report.issues[0].code, "io_error")

    def test_load_findings_rejects_duplicate_and_symlink(self):
        source = self.root / "findings.json"
        source.write_text('{"A":["nota.txt"],"A":["nota.txt"]}', encoding="utf-8")
        with self.assertRaises(InputError):
            load_findings(source)
        alias = self.root / "alias.json"
        self.make_link(source, alias)
        with self.assertRaises(InputError):
            load_findings(alias)

    def test_cli_exit_codes_and_json(self):
        config = self.root / "findings.json"
        config.write_text(json.dumps(self.findings), encoding="utf-8")
        stream = io.StringIO()
        with redirect_stdout(stream):
            status = main(
                ["create", str(self.source), str(self.destination), "--findings", str(config)]
            )
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(stream.getvalue())["valid"])
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify", str(self.destination)]), 0)
            self.assertEqual(
                main(
                    ["create", str(self.source), str(self.destination), "--findings", str(config)]
                ),
                2,
            )
            (self.destination / "data/nota.txt").write_bytes(b"changed")
            self.assertEqual(main(["verify", str(self.destination)]), 1)


if __name__ == "__main__":
    unittest.main()
