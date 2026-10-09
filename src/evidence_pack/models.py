"""Stable, serializable results and typed exceptions."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True, order=True)
class Issue:
    """A machine-readable finding; paths are relative to the inspected tree."""

    path: str
    code: str
    message: str


class EvidencePackError(Exception):
    """Base for expected input and filesystem failures."""

    def __init__(self, code: str, message: str, path: str = ".") -> None:
        self.issue = Issue(path, code, message)
        super().__init__(f"{code}: {path}: {message}")


class InputError(EvidencePackError):
    """Invalid path, unsupported filesystem entry, or invalid index input."""


class DestinationExistsError(EvidencePackError):
    """The destination was already present; it has not been modified."""


class CreationIncompleteError(EvidencePackError):
    """Creation failed after reserving a new destination; inspect it manually."""


@dataclass(frozen=True)
class VerificationReport:
    """Results are deterministic for an unchanged tree, without wall-clock fields."""

    issues: tuple[Issue, ...] = ()
    payload_files: int = 0
    payload_bytes: int = 0
    findings: int = 0
    referenced_files: int = 0

    @property
    def valid(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, object]:
        return {
            "profile": "evidence-pack/1",
            "valid": self.valid,
            "payload_files": self.payload_files,
            "payload_bytes": self.payload_bytes,
            "findings": self.findings,
            "referenced_files": self.referenced_files,
            "issues": [asdict(issue) for issue in sorted(self.issues)],
        }
