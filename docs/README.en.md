# evidence-pack-py

Create and verify local evidence directories with SHA-256 manifests and a finding-to-file index. Python 3.12+, no runtime dependencies.

[Español](../README.md) · [Profile details, Spanish](perfil.md)

## Purpose and limits

A finding can refer to multiple files; one file can support multiple findings. This package copies a stable source directory into a new directory and checks it against the stored manifests.

Verification establishes integrity relative to those manifests. It does not prove authorship, truth, provenance, a trusted timestamp, chain of custody or legal validity. Replacing both content and manifests consistently can produce a passing report. No signatures or custom cryptographic protocol are added.

## Quick start

From a checkout, in a Python 3.12+ virtual environment:

```sh
python -m pip install -e .
evidence-pack create examples/payload example-pack --findings examples/findings.json
evidence-pack verify example-pack
```

`python -m evidence_pack` is equivalent. The destination must not exist and its parent must exist. Use a new destination when repeating the example.

The input findings JSON maps IDs to source-relative paths:

```json
{"OBS-001": ["observacion.txt"]}
```

All regular source files are copied, including hidden and unreferenced files. Review the directory before sharing it. Empty directories are omitted; use a placeholder file if they must be represented. Permissions, ownership, timestamps, ACLs, extended attributes and alternate filesystem metadata are not preserved.

The output contains `data/`, `bagit.txt`, `manifest-sha256.txt`, `tagmanifest-sha256.txt` and `index.json`. The payload manifest covers all files under `data/`; the tag manifest covers the declaration, payload manifest and index. The stored index has exactly this shape:

```json
{
  "findings": {"OBS-001": ["data/observacion.txt"]},
  "profile": "evidence-pack/1"
}
```

IDs match `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` and are case-sensitive. At least one finding is required, each with a nonempty list of unique paths to existing files. Sharing a file between findings is allowed. Unreferenced context files are also allowed and still hashed.

## Python API

```python
from evidence_pack import create_pack, verify_pack

created = create_pack("source", "delivery-001", {"OBS-001": ["note.txt"]})
assert created.valid
report = verify_pack("delivery-001")
print(report.to_dict())
```

`VerificationReport` is immutable and exposes `valid`, `payload_files`, `payload_bytes`, `findings`, `referenced_files` and `issues`. Issues contain `code`, `path` and `message`. Counts can be partial if a structural error prevents further inspection. `valid` means valid for this profile only.

Expected verification format/I/O errors produce a report. Creation and findings-file loading raise subclasses of `EvidencePackError`: `InputError`, `DestinationExistsError` or `CreationIncompleteError`, each with an `issue` field. The last class preserves the original cause and means a newly reserved, possibly incomplete destination remains for manual inspection.

CLI output is JSON. Exit codes: `0` for successful creation/verification, `1` for a failed verification including I/O errors, `2` for input/creation errors. CLI argument parsing errors use stderr and are not JSON. Stable trees produce deterministic bytes and sorted reports without timestamps or absolute root paths; OS error wording can vary.

## File policy

- Local stable directories and regular files only. Symbolic links, reparse points, hard links and special files are rejected, including links in root-argument ancestors.
- No network retrieval, archive extraction or content execution.
- Relative `/`-separated paths must already be NFC-normalized. Absolute paths, parent traversal, empty components, backslashes, `%`, controls, nonportable characters, reserved device names and casefold collisions are rejected. Names are not silently rewritten.
- Source and destination must not overlap. An existing destination is never reused, even if empty.
- Exclusive `mkdir` reserves the destination. The declaration is written last, followed by verification. This is not atomic publication, a transaction or crash-durability protection.
- Failed attempts are not deleted automatically. Inspect the partial directory manually and use a different destination to retry. Interruptions can leave an incomplete directory without a final report.
- Use private, stable directories without concurrent writers. Ordinary changes are checked through metadata and inventories, but the operation is not an atomic snapshot or a sandbox against hostile concurrent filesystem mutation.

Limits: 100,000 filesystem entries per tree; 64 path components including `data/`; 255 UTF-8 bytes per component and 4096 per relative path; 1 MiB index; 16 MiB per manifest. Payload bytes stream in 1 MiB blocks with no package-imposed file-size limit. Metadata and inventories are held in memory within those limits. OS limits may be lower.

The implementation uses portable Python interfaces for Windows, macOS and Linux. This delivery was tested on Linux/Python 3.12 only; other systems need independent validation. Avoid linked root aliases such as macOS `/var`; select the physical path.

## BagIt scope and development

The layout is a restricted profile of [BagIt 1.0, RFC 8493](https://www.rfc-editor.org/rfc/rfc8493.html). This tool only handles SHA-256, UTF-8 and its own index; it is not a general BagIt validator or a full RFC implementation. Valid BagIt bags with additional algorithms, tag files or other supported-by-BagIt names may be rejected.

[bagit-python](https://github.com/LibraryOfCongress/bagit-python) is an optional independent verifier of generated samples. None of its code is copied into this package and it is not a runtime dependency.

```sh
python -m unittest discover -s tests -v
```

Tests use synthetic temporary fixtures only. They cover corruption, missing references, duplicate index keys, path policy, collisions, links, resource limits and incomplete creation. They are neither security certification nor full BagIt conformance testing. No remote CI is configured in this initial version; see [local verification](verificacion.md).

## License

Copyright 2026 mat-l-dev. Licensed under the [Apache License 2.0](../LICENSE). See the full license text for its permissions, conditions, and limitations.
