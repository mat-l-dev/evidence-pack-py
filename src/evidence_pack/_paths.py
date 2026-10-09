"""Conservative, portable path policy; not a hostile-filesystem sandbox."""

import os
import stat
import unicodedata
from pathlib import Path
from typing import BinaryIO

from .models import InputError

MAX_ENTRIES = 100_000
MAX_DEPTH = 64
MAX_PATH_BYTES = 4096
CHUNK_SIZE = 1024 * 1024
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
_RESERVED |= {f"{prefix}{n}" for prefix in ("COM", "LPT") for n in "123456789¹²³"}


def portable_path(value: str) -> str:
    """Validate without silently normalizing or rewriting an identifier."""
    if not isinstance(value, str) or not value:
        raise InputError("unsafe_path", "Expected a nonempty relative path.")
    if unicodedata.normalize("NFC", value) != value:
        raise InputError("unsafe_path", "Path must already be NFC-normalized.", value)
    if any(
        unicodedata.category(c).startswith("C") or unicodedata.category(c) in {"Zl", "Zp"}
        for c in value
    ):
        raise InputError(
            "unsafe_path", "Control, format and surrogate characters are unsupported.", value
        )
    if len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise InputError("resource_limit", "Path exceeds the profile byte limit.", value)
    parts = value.split("/")
    if len(parts) > MAX_DEPTH:
        raise InputError("resource_limit", "Path exceeds the profile depth limit.", value)
    for part in parts:
        if part in ("", ".", "..") or part != part.strip() or part.endswith("."):
            raise InputError(
                "unsafe_path", "Empty, dot or padded path components are unsupported.", value
            )
        if any(c in part for c in '\\%<>:"|?*'):
            raise InputError(
                "unsafe_path", "Path contains an unsupported portable filename character.", value
            )
        if part.split(".")[0].rstrip(" ").upper() in _RESERVED:
            raise InputError("unsafe_path", "Reserved device filenames are unsupported.", value)
        if len(part.encode("utf-8")) > 255:
            raise InputError("resource_limit", "Filename component exceeds 255 UTF-8 bytes.", value)
    return value


def check_entry(path: Path, label: str) -> os.stat_result:
    info = path.lstat()
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    if stat.S_ISLNK(info.st_mode) or reparse:
        raise InputError(
            "unsupported_entry", "Symbolic links and reparse points are unsupported.", label
        )
    if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
        raise InputError(
            "unsupported_entry", "Only regular files and directories are supported.", label
        )
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise InputError("unsupported_entry", "Hard-linked files are unsupported.", label)
    return info


def checked_absolute(value: str | os.PathLike[str], *, must_exist: bool = True) -> Path:
    try:
        raw = os.fspath(value)
        if not isinstance(raw, str) or "\x00" in raw:
            raise ValueError("Root path must be a string without NUL.")
        raw.encode("utf-8")
        path = Path(raw)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise InputError("unsafe_path", "Root path must be valid Unicode without NUL.") from exc
    if ".." in path.parts:
        raise InputError("unsafe_path", "Parent traversal in root arguments is unsupported.")
    path = path.absolute()
    for candidate in reversed((path, *path.parents)):
        if candidate == path and not must_exist:
            continue
        check_entry(candidate, ".")
    return path


def snapshot(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def inventory(root: Path) -> tuple[dict[str, os.stat_result], set[str]]:
    """Walk without following links, detecting casefold collisions per directory."""
    if not stat.S_ISDIR(check_entry(root, ".").st_mode):
        raise InputError("not_directory", "Expected a directory.")
    files: dict[str, os.stat_result] = {}
    directories: set[str] = set()
    pending = [(root, "")]
    count = 0
    while pending:
        folder, prefix = pending.pop()
        check_entry(folder, prefix or ".")
        # Sort only after enforcing the entry cap, bounding the in-memory listing.
        with os.scandir(folder) as iterator:
            children = []
            for entry in iterator:
                count += 1
                if count > MAX_ENTRIES:
                    raise InputError(
                        "resource_limit", "Tree exceeds 100000 entries.", prefix or "."
                    )
                children.append(entry.name)
        seen: set[str] = set()
        for name in sorted(children):
            relative = portable_path(f"{prefix}/{name}" if prefix else name)
            folded = name.casefold()
            if folded in seen:
                raise InputError(
                    "path_collision", "Names collide under Unicode case folding.", relative
                )
            seen.add(folded)
            info = check_entry(folder / name, relative)
            if stat.S_ISDIR(info.st_mode):
                directories.add(relative)
                pending.append((folder / name, relative))
            else:
                files[relative] = info
    return dict(sorted(files.items())), directories


def open_regular(root: Path, relative: str) -> BinaryIO:
    portable_path(relative)
    path = root.joinpath(*relative.split("/"))
    # Recheck ancestors immediately before opening. Concurrent hostile mutation
    # cannot be excluded portably; callers must provide a stable private tree.
    for parent in reversed(path.parents):
        if parent == root or root in parent.parents:
            check_entry(parent, "." if parent == root else parent.relative_to(root).as_posix())
    before = check_entry(path, relative)
    if not stat.S_ISREG(before.st_mode):
        raise InputError("unsupported_entry", "Expected a regular file.", relative)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or snapshot(opened) != snapshot(before):
            raise InputError("source_changed", "File changed while it was being opened.", relative)
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def read_bytes(root: Path, relative: str, limit: int) -> bytes:
    with open_regular(root, relative) as stream:
        before = snapshot(os.fstat(stream.fileno()))
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise InputError("resource_limit", "Metadata exceeds the profile size limit.", relative)
        if snapshot(os.fstat(stream.fileno())) != before:
            raise InputError("source_changed", "File changed during reading.", relative)
        return data
