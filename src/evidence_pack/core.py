"""Create and verify one intentionally restricted BagIt-based profile."""

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import _paths
from ._paths import (
    CHUNK_SIZE,
    checked_absolute,
    inventory,
    open_regular,
    portable_path,
    read_bytes,
    snapshot,
)
from .models import (
    CreationIncompleteError,
    DestinationExistsError,
    EvidencePackError,
    InputError,
    Issue,
    VerificationReport,
)

PROFILE = "evidence-pack/1"
DECLARATION = b"BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n"
TAG_FILES = frozenset({"bagit.txt", "manifest-sha256.txt", "index.json"})
ROOT_FILES = TAG_FILES | {"tagmanifest-sha256.txt"}
INDEX_LIMIT = 1024 * 1024
MANIFEST_LIMIT = 16 * 1024 * 1024
_FINDING_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_MANIFEST_LINE = re.compile(r"([0-9a-fA-F]{64})[ \t]+([^ \t].*)\Z")


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(
                "invalid_index", "Duplicate JSON object keys are unsupported.", "index.json"
            )
        result[key] = value
    return result


def _decode_json(data: bytes) -> object:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError(
            "invalid_index", "Expected well-formed UTF-8 JSON without a BOM.", "index.json"
        ) from exc


def _findings(value: object, available: set[str], *, payload_prefix: bool) -> dict[str, list[str]]:
    if not isinstance(value, Mapping) or not value:
        raise InputError(
            "invalid_index",
            "Expected a nonempty mapping of finding IDs to path lists.",
            "index.json",
        )
    result: dict[str, list[str]] = {}
    for finding, paths in value.items():
        if not isinstance(finding, str) or not _FINDING_ID.fullmatch(finding):
            raise InputError(
                "invalid_index",
                "Finding IDs must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}.",
                "index.json",
            )
        if (
            not isinstance(paths, Sequence)
            or isinstance(paths, (str, bytes, bytearray))
            or not paths
        ):
            raise InputError(
                "invalid_index", "Each finding needs a nonempty list of paths.", "index.json"
            )
        normalized = []
        for path in paths:
            if not isinstance(path, str):
                raise InputError("invalid_index", "Index paths must be strings.", "index.json")
            portable_path(path)
            if payload_prefix and not path.startswith("data/"):
                raise InputError(
                    "invalid_index", "Stored index paths must start with data/.", "index.json"
                )
            if path not in available:
                raise InputError(
                    "missing_reference", "Index references an absent payload file.", path
                )
            normalized.append(path if payload_prefix else f"data/{path}")
        if len(set(normalized)) != len(normalized):
            raise InputError(
                "invalid_index", "Duplicate paths within a finding are unsupported.", "index.json"
            )
        result[finding] = sorted(normalized)
    return dict(sorted(result.items()))


def load_findings(path: str | os.PathLike[str]) -> dict[str, list[str]]:
    """Read a CLI input object mapping IDs to source-relative paths, without following links."""
    try:
        source = checked_absolute(path)
        value = _decode_json(read_bytes(source.parent, source.name, INDEX_LIMIT))
        if not isinstance(value, dict):
            raise InputError(
                "invalid_index",
                "Expected a JSON object of finding IDs and path lists.",
                "index.json",
            )
        # Full structural and reference validation occurs in create_pack.
        return value
    except OSError as exc:
        raise InputError("io_error", os.strerror(exc.errno or 5), "index.json") from exc


def _hash(root: Path, path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open_regular(root, path) as stream:
        before = snapshot(os.fstat(stream.fileno()))
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
        if snapshot(os.fstat(stream.fileno())) != before:
            raise InputError("source_changed", "File changed during hashing.", path)
    return digest.hexdigest(), size


def _write_new(path: Path, content: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(content)


def _manifest(entries: Mapping[str, str]) -> bytes:
    return "".join(f"{digest}  {path}\n" for path, digest in sorted(entries.items())).encode(
        "utf-8"
    )


def create_pack(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    findings: Mapping[str, Sequence[str]],
) -> VerificationReport:
    """Copy a stable directory into a new bag; never replace an existing destination.

    Input paths in findings are relative to source. Existing output, symlinks,
    hard links, nonportable names, collisions and overlapping roots are rejected.
    Failure after exclusive mkdir leaves the owned partial directory for inspection.
    """
    reserved = False
    try:
        source_path = checked_absolute(source)
        destination_path = checked_absolute(destination, must_exist=False)
        portable_path(destination_path.name)
        if (
            source_path == destination_path
            or source_path in destination_path.parents
            or destination_path in source_path.parents
            or any(os.path.samefile(source_path, parent) for parent in destination_path.parents)
        ):
            raise InputError("overlapping_paths", "Source and destination must not overlap.")
        if os.path.lexists(destination_path):
            raise DestinationExistsError(
                "destination_exists", "Destination already exists; nothing was changed."
            )
        files, _ = inventory(source_path)
        output_directories = {"data"}
        estimated_manifest_bytes = 0
        for relative in files:
            output_path = portable_path(f"data/{relative}")
            parts = output_path.split("/")
            output_directories.update("/".join(parts[:i]) for i in range(1, len(parts)))
            estimated_manifest_bytes += 67 + len(output_path.encode("utf-8"))
        if len(files) + len(output_directories) + len(ROOT_FILES) > _paths.MAX_ENTRIES:
            raise InputError("resource_limit", "Output tree would exceed the profile entry limit.")
        if estimated_manifest_bytes > MANIFEST_LIMIT:
            raise InputError(
                "resource_limit", "Output manifest would exceed 16 MiB.", "manifest-sha256.txt"
            )
        index = {
            "profile": PROFILE,
            "findings": _findings(findings, set(files), payload_prefix=False),
        }
        index_bytes = _json_bytes(index)
        if len(index_bytes) > INDEX_LIMIT:
            raise InputError("resource_limit", "Serialized index exceeds 1 MiB.", "index.json")
        try:
            destination_path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise DestinationExistsError(
                "destination_exists", "Destination already exists; nothing was changed."
            ) from exc
        reserved = True
        (destination_path / "data").mkdir(mode=0o700)
        entries: dict[str, str] = {}
        for relative, before in files.items():
            target = destination_path / "data" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with open_regular(source_path, relative) as original, target.open("xb") as output:
                if snapshot(os.fstat(original.fileno())) != snapshot(before):
                    raise InputError(
                        "source_changed", "Source changed after the initial inventory.", relative
                    )
                while chunk := original.read(CHUNK_SIZE):
                    digest.update(chunk)
                    output.write(chunk)
                if snapshot(os.fstat(original.fileno())) != snapshot(before):
                    raise InputError("source_changed", "Source changed during copying.", relative)
            entries[f"data/{relative}"] = digest.hexdigest()
        # Detect ordinary additions/removals/changes during the copy. This is not
        # an atomic snapshot or protection against an actively mutating producer.
        after_files, _ = inventory(source_path)
        if {p: snapshot(s) for p, s in after_files.items()} != {
            p: snapshot(s) for p, s in files.items()
        }:
            raise InputError("source_changed", "Source tree changed during copying.")
        manifest_bytes = _manifest(entries)
        if len(manifest_bytes) > MANIFEST_LIMIT:
            raise InputError(
                "resource_limit", "Serialized manifest exceeds 16 MiB.", "manifest-sha256.txt"
            )
        _write_new(destination_path / "manifest-sha256.txt", manifest_bytes)
        _write_new(destination_path / "index.json", index_bytes)
        tags = {
            "bagit.txt": hashlib.sha256(DECLARATION).hexdigest(),
            "manifest-sha256.txt": hashlib.sha256(manifest_bytes).hexdigest(),
            "index.json": hashlib.sha256(index_bytes).hexdigest(),
        }
        _write_new(destination_path / "tagmanifest-sha256.txt", _manifest(tags))
        # Written last; absence means incomplete. This is not an atomic publish.
        _write_new(destination_path / "bagit.txt", DECLARATION)
        report = verify_pack(destination_path)
        if not report.valid:
            raise InputError(
                "post_create_verification_failed",
                "The newly created bag did not pass verification.",
            )
        return report
    except (EvidencePackError, OSError) as exc:
        if reserved:
            cause = exc.issue.code if isinstance(exc, EvidencePackError) else "io_error"
            raise CreationIncompleteError(
                "creation_incomplete",
                f"Creation stopped ({cause}); a partial destination remains. Inspect it manually.",
            ) from exc
        if isinstance(exc, EvidencePackError):
            raise
        raise InputError("io_error", os.strerror(exc.errno or 5)) from exc


def _parse_manifest(data: bytes, *, tag: bool) -> dict[str, str]:
    label = "tagmanifest-sha256.txt" if tag else "manifest-sha256.txt"
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise InputError("invalid_manifest", "Manifest must be UTF-8.", label) from exc
    entries: dict[str, str] = {}
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    for line in lines:
        match = _MANIFEST_LINE.fullmatch(line)
        if not match:
            raise InputError(
                "invalid_manifest",
                "Expected a SHA-256 hex digest and relative path per line.",
                label,
            )
        digest, path = match.groups()
        portable_path(path)
        if (tag and path not in TAG_FILES) or (not tag and not path.startswith("data/")):
            raise InputError(
                "invalid_manifest", "Manifest path is outside the allowed profile scope.", path
            )
        if path in entries:
            raise InputError(
                "duplicate_manifest_entry", "Manifest path is listed more than once.", path
            )
        entries[path] = digest.lower()
    return entries


def verify_pack(path: str | os.PathLike[str]) -> VerificationReport:
    """Read-only verification of this profile, never a general BagIt validator."""
    issues: list[Issue] = []
    payload_count = payload_bytes = finding_count = reference_count = 0
    try:
        root = checked_absolute(path)
        files, directories = inventory(root)
        payload = {name for name in files if name.startswith("data/")}
        payload_count = len(payload)
        payload_bytes = sum(files[name].st_size for name in payload)
        for required in sorted(ROOT_FILES - set(files)):
            issues.append(Issue(required, "missing_file", "Required profile file is missing."))
        if "data" not in directories:
            issues.append(
                Issue("data", "missing_directory", "Required payload directory is missing.")
            )
        for name in sorted(set(files) - ROOT_FILES - payload):
            issues.append(Issue(name, "unexpected_file", "File is outside the supported profile."))
        for name in sorted(directories):
            if name != "data" and not name.startswith("data/"):
                issues.append(
                    Issue(
                        name, "unexpected_directory", "Directory is outside the supported profile."
                    )
                )
        if issues:
            return VerificationReport(tuple(sorted(issues)), payload_count, payload_bytes)
        declaration = read_bytes(root, "bagit.txt", 1024)
        if declaration not in (DECLARATION, DECLARATION.replace(b"\n", b"\r\n")):
            issues.append(
                Issue(
                    "bagit.txt",
                    "unsupported_declaration",
                    "Profile requires BagIt 1.0 with UTF-8 and standard field spelling.",
                )
            )
        expected_payload = _parse_manifest(
            read_bytes(root, "manifest-sha256.txt", MANIFEST_LIMIT), tag=False
        )
        expected_tags = _parse_manifest(
            read_bytes(root, "tagmanifest-sha256.txt", MANIFEST_LIMIT), tag=True
        )
        for name in sorted(payload - set(expected_payload)):
            issues.append(
                Issue(name, "unlisted_payload", "Payload file is not listed in the manifest.")
            )
        for name in sorted(set(expected_payload) - payload):
            issues.append(
                Issue(name, "missing_payload", "Manifest references an absent payload file.")
            )
        for name in sorted(TAG_FILES - set(expected_tags)):
            issues.append(
                Issue(name, "unlisted_tag", "Required tag is not listed in the tag manifest.")
            )
        for name, expected in sorted((expected_payload | expected_tags).items()):
            if name in files:
                actual, _ = _hash(root, name)
                if actual != expected:
                    issues.append(
                        Issue(
                            name, "checksum_mismatch", "SHA-256 differs from the recorded manifest."
                        )
                    )
        index = _decode_json(read_bytes(root, "index.json", INDEX_LIMIT))
        if (
            not isinstance(index, dict)
            or set(index) != {"profile", "findings"}
            or index["profile"] != PROFILE
        ):
            raise InputError(
                "invalid_index",
                "Index requires exactly profile and findings with profile evidence-pack/1.",
                "index.json",
            )
        findings = _findings(index["findings"], payload, payload_prefix=True)
        finding_count = len(findings)
        reference_count = len({p for paths in findings.values() for p in paths})
        after_files, after_dirs = inventory(root)
        if after_dirs != directories or {p: snapshot(s) for p, s in after_files.items()} != {
            p: snapshot(s) for p, s in files.items()
        }:
            issues.append(Issue(".", "source_changed", "Bag changed during verification."))
    except EvidencePackError as exc:
        issues.append(exc.issue)
    except OSError as exc:
        issues.append(Issue(".", "io_error", os.strerror(exc.errno or 5)))
    return VerificationReport(
        tuple(sorted(issues)), payload_count, payload_bytes, finding_count, reference_count
    )
