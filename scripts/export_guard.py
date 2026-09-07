#!/usr/bin/env python3
"""Fail-closed source and distribution boundary checks for badass-runner."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import urllib.parse
import zipfile
import ipaddress
from pathlib import Path, PurePosixPath

# This is deliberately anchored to this checked-in script, never to cwd or git.
SOURCE_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).with_name("export_allowlist.json")
EXCLUDED_SOURCE_DIRS = {".git", "tests", "build", "dist", ".pytest_cache", "__pycache__"}
# Repository-control data is never part of a Python export; it is ignored only
# while collecting the fixed canonical development root, never in staged mode.
LOCAL_DISCOVERY_FILES = {".gitignore"}
PRIVATE_HOST = re.compile(
    r"(?:^|[./@-])(?:internal|private|backend|staging|prod)(?:[.-]|$)"
    r"|(?:\.internal|\.local|\.localhost|\.cluster\.local)$",
    re.I,
)
SECRET = re.compile(
    r"""(?ix)
    (?:api[_-]?key|secret|password|passwd|token|credential|private[_-]?key)
    \s*(?:=|:)\s*["'](?!YOURTOKEN\b|\[REDACTED\]|\.\.\.)[A-Za-z0-9_./+=:-]{12,}["']
    |-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----
    |(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}
    |pypi-[A-Za-z0-9_-]{20,}
    |AKIA[0-9A-Z]{16}
    |(?:https?://)[^/\s:@]+:[^/\s@]+@
    """
)
TRAVERSAL = "." * 2 + "/"


class GuardError(Exception):
    pass


def load_manifest() -> set[str]:
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuardError(f"cannot read deterministic manifest: {exc}") from exc
    return set(item for group in data.values() for item in group)


def allowed(rel: str, patterns: set[str]) -> bool:
    path = PurePosixPath(rel)
    for pattern in patterns:
        if path.match(pattern):
            return True
        # The manifest's ** means this package directory and all descendants.
        if "/**/" in pattern and path.match(pattern.replace("/**/", "/")):
            return True
    return False


def allowed_directory(rel: str, patterns: set[str]) -> bool:
    """Only directories needed to reach allowlisted files may exist."""
    directory = PurePosixPath(rel)
    for pattern in patterns:
        parts: list[str] = []
        for part in PurePosixPath(pattern).parts:
            if any(char in part for char in "*?["):
                break
            parts.append(part)
        fixed = PurePosixPath(*parts)
        if directory == fixed or directory in fixed.parents or fixed in directory.parents:
            return True
    return False


def safe_name(name: str) -> str:
    """Archive names must be relative, normalized POSIX paths."""
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise GuardError(f"unsafe archive path: {name!r}")
    return path.as_posix().rstrip("/")


def scan_text(text: str, label: str, python: bool = False) -> None:
    if SECRET.search(text):
        raise GuardError(f"possible secret or credential URL in {label}")
    # Public documentation may describe localhost and the public cloud host only.
    for url in re.findall(r"https?://[^\s`\"')]+", text):
        try:
            host = urllib.parse.urlsplit(url).hostname
        except ValueError as exc:
            raise GuardError(f"malformed URL in {label}: {url}") from exc
        if not host:
            raise GuardError(f"URL has no hostname in {label}: {url}")
        if host not in {"badass-sec.com", "localhost", "127.0.0.1"} and PRIVATE_HOST.search(host):
            raise GuardError(f"private/internal host in {label}: {host}")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            # Literal loopback is part of the runner's public local-endpoint contract.
            if host != "127.0.0.1" and not address.is_global:
                raise GuardError(f"non-public IP address in {label}: {host}")
    # Paths referring outside the release tree can expose sibling private code.
    traversal_text = text
    if label == "docs/security-model.md":
        traversal_text = traversal_text.replace("." * 2 + "/SECURITY.md", "")
    if TRAVERSAL in traversal_text or re.search(
        r"""(?ix)
        (?:^|[\s"'(=])(?:/|[A-Z]:\\)(?:home|root|etc|tmp|backend|frontend|scanners|app)(?:[/\\])
        |(?:^|[\s"'(=])(?:backend|frontend|scanners|app|badass-connector)(?:[/\\])
        """,
        traversal_text,
    ):
        raise GuardError(f"private traversal reference in {label}")
    if not python:
        return
    try:
        tree = ast.parse(text, filename=label)
    except SyntaxError as exc:
        raise GuardError(f"unparseable Python in {label}: {exc}") from exc
    importlib_aliases = {"importlib"}
    builtins_aliases = {"builtins"}
    dynamic_import_aliases = {"__import__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_aliases.add(alias.asname or alias.name)
                elif alias.name == "builtins":
                    builtins_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        dynamic_import_aliases.add(alias.asname or alias.name)
            elif node.module == "builtins":
                for alias in node.names:
                    if alias.name == "__import__":
                        dynamic_import_aliases.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = ([node.module] if node.module else []) + [
                alias.name for alias in node.names
            ]
        elif isinstance(node, ast.Call):
            is_import = (
                isinstance(node.func, ast.Name)
                and node.func.id in dynamic_import_aliases
            ) or (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in importlib_aliases
                and node.func.attr == "import_module"
            ) or (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in builtins_aliases
                and node.func.attr == "__import__"
            )
            if is_import and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                names = [node.args[0].value]
        for name in names:
            segments = set(name.split("."))
            first = name.split(".", 1)[0]
            if first in {"backend", "frontend", "scanners", "app"} or segments & {"policy", "evaluator", "catalog"}:
                raise GuardError(f"private import {name!r} in {label}")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise GuardError(f"unreadable or undecodable file {path}: {exc}") from exc


def source_files(root: Path, patterns: set[str], discovery: bool = False, staging: bool = False) -> dict[str, str]:
    result: dict[str, str] = {}
    if root.is_symlink():
        raise GuardError(f"source root may not be a symlink: {root}")
    try:
        root.resolve(strict=True)
    except OSError as exc:
        raise GuardError(f"unresolvable source root: {root}: {exc}") from exc
    try:
        entries = list(root.rglob("*"))
    except OSError as exc:
        raise GuardError(f"cannot enumerate {root}: {exc}") from exc
    for item in entries:
        rel = item.relative_to(root).as_posix()
        if discovery and any(part in EXCLUDED_SOURCE_DIRS or part.endswith(".egg-info") for part in PurePosixPath(rel).parts):
            continue
        if discovery and rel in LOCAL_DISCOVERY_FILES:
            continue
        if item.is_symlink():
            raise GuardError(f"symlink is forbidden: {rel}")
        if item.is_dir():
            if not discovery and not allowed_directory(rel, patterns):
                raise GuardError(f"unexpected source directory: {rel}")
            continue
        if not item.is_file():
            raise GuardError(f"non-regular entry is forbidden: {rel}")
        if not allowed(rel, patterns):
            raise GuardError(f"unexpected source file: {rel}")
        text = read_text(item)
        if staging and rel == "pyproject.toml":
            text = re.sub(r"(?ms)^\[tool\.uv\.sources\]\n.*?(?=^\[|\Z)", "", text)
        scan_text(text, rel, rel.endswith(".py"))
        result[rel] = text
    return result


def stage(destination: Path) -> None:
    patterns = load_manifest()
    destination.mkdir(parents=True, exist_ok=False)
    for rel, text in source_files(SOURCE_ROOT, patterns, discovery=True, staging=True).items():
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # A staged artifact must not retain a path escape to the sibling protocol tree.
        if rel == "pyproject.toml":
            text = re.sub(r"(?ms)^\[tool\.uv\.sources\]\n.*?(?=^\[|\Z)", "", text)
            target.write_text(text, encoding="utf-8")
        else:
            shutil.copyfile(SOURCE_ROOT / rel, target)


def guard_source(root: Path) -> None:
    # Only the fixed development root may omit known generated/test directories.
    source_files(root, load_manifest(), discovery=root.resolve() == SOURCE_ROOT)


def wheel_guard(path: Path, source: dict[str, str]) -> None:
    seen: set[str] = set()
    file_members: set[str] = set()
    package_members: set[str] = set()
    record_name = None
    version = re.search(r"^version\s*=\s*\"([^\"]+)\"", source["pyproject.toml"], re.M)
    if not version:
        raise GuardError("cannot determine staged version")
    dist_root = f"badass_runner-{version.group(1)}.dist-info"
    allowed_metadata = {
        f"{dist_root}/licenses/LICENSE",
        f"{dist_root}/METADATA",
        f"{dist_root}/WHEEL",
        f"{dist_root}/entry_points.txt",
        f"{dist_root}/top_level.txt",
        f"{dist_root}/RECORD",
    }
    expected_files = {
        name
        for name in source
        if name.startswith("badass_runner/") and name.endswith(".py")
    } | allowed_metadata
    allowed_directories = {
        parent.as_posix()
        for name in expected_files
        for parent in PurePosixPath(name).parents
        if parent.as_posix() != "."
    }
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = safe_name(info.filename)
            if name in seen:
                raise GuardError(f"duplicate wheel member: {name}")
            seen.add(name)
            parts = PurePosixPath(name).parts
            file_type = (info.external_attr >> 16) & 0o170000
            if info.is_dir():
                if file_type not in (0, 0o040000):
                    raise GuardError(f"non-directory wheel member: {name}")
                if name not in allowed_directories:
                    raise GuardError(f"unexpected wheel directory: {name}")
                continue
            if file_type not in (0, 0o100000):
                raise GuardError(f"non-regular wheel member: {name}")
            file_members.add(name)
            if not (
                parts[0] == "badass_runner"
                or parts[0] == dist_root
            ):
                raise GuardError(f"unexpected wheel member: {name}")
            if parts[0] == "badass_runner":
                if not name.endswith(".py") or name not in source:
                    raise GuardError(f"unexpected wheel package member: {name}")
                text = archive.read(info).decode("utf-8")
                scan_text(text, name, True)
                if text != source[name]:
                    raise GuardError(f"wheel source differs from manifest: {name}")
                package_members.add(name)
            elif parts[0] == dist_root:
                if name not in allowed_metadata:
                    raise GuardError(f"unexpected wheel metadata member: {name}")
                if len(parts) == 2 and parts[1] == "RECORD":
                    record_name = name
                else:
                    try:
                        scan_text(archive.read(info).decode("utf-8"), name)
                    except UnicodeDecodeError as exc:
                        raise GuardError(f"undecodable wheel member: {name}") from exc
            else:
                raise GuardError(f"unexpected wheel member: {name}")
        if package_members != {name for name in source if name.startswith("badass_runner/") and name.endswith(".py")}:
            raise GuardError("wheel package does not exactly match source manifest")
        if not record_name:
            raise GuardError("wheel has no RECORD")
        record = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
        if any(len(row) != 3 for row in record):
            raise GuardError("malformed wheel RECORD")
        listed = {safe_name(row[0]) for row in record if row}
        if listed != file_members:
            raise GuardError("wheel RECORD does not exactly describe members")
        if len(listed) != len(record):
            raise GuardError("duplicate wheel RECORD entry")
        for member, digest, size in record:
            if member == record_name:
                if digest or size:
                    raise GuardError("RECORD self entry must be empty")
                continue
            if not digest.startswith("sha256=") or not size.isdigit():
                raise GuardError(f"invalid RECORD digest for {member}")
            content = archive.read(member)
            expected = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
            if digest != f"sha256={expected}" or int(size) != len(content):
                raise GuardError(f"RECORD mismatch for {member}")


def sdist_guard(path: Path, source: dict[str, str]) -> None:
    version = re.search(r"^version\s*=\s*\"([^\"]+)\"", source["pyproject.toml"], re.M)
    if not version:
        raise GuardError("cannot determine version")
    root = f"badass_runner-{version.group(1)}"
    generated_files = {
        "PKG-INFO",
        "setup.cfg",
        "badass_runner.egg-info/PKG-INFO",
        "badass_runner.egg-info/SOURCES.txt",
        "badass_runner.egg-info/dependency_links.txt",
        "badass_runner.egg-info/entry_points.txt",
        "badass_runner.egg-info/requires.txt",
        "badass_runner.egg-info/top_level.txt",
    }
    possible_files = set(source) | generated_files
    allowed_directories = {root} | {
        f"{root}/{parent.as_posix()}"
        for name in possible_files
        for parent in PurePosixPath(name).parents
        if parent.as_posix() != "."
    }
    seen: set[str] = set()
    package_members: set[str] = set()
    with tarfile.open(path, "r:*") as archive:
        for info in archive.getmembers():
            name = safe_name(info.name)
            if name in seen:
                raise GuardError(f"duplicate sdist member: {name}")
            seen.add(name)
            parts = PurePosixPath(name).parts
            if not parts or parts[0] != root:
                raise GuardError(f"unexpected sdist root: {name}")
            if info.isdir():
                if name not in allowed_directories:
                    raise GuardError(f"unexpected sdist directory: {name}")
                continue
            if not info.isfile():
                raise GuardError(f"non-regular sdist member: {name}")
            rel = "/".join(parts[1:])
            if not rel:
                raise GuardError(f"unexpected sdist file at root: {name}")
            # setuptools places generated PKG-INFO at the sdist root as well.
            generated_metadata = rel in generated_files
            if not generated_metadata and not allowed(rel, load_manifest()):
                raise GuardError(f"unexpected sdist member: {rel}")
            data = archive.extractfile(info)
            if data is None:
                raise GuardError(f"unreadable sdist member: {name}")
            try:
                text = data.read().decode("utf-8")
            except UnicodeDecodeError as exc:
                raise GuardError(f"undecodable sdist member: {name}") from exc
            scan_text(text, name, rel.endswith(".py"))
            if not generated_metadata and rel.endswith(".py") and text != source.get(rel):
                raise GuardError(f"sdist source differs from manifest: {rel}")
            if not generated_metadata and rel.endswith(".py"):
                package_members.add(rel)
    if package_members != {name for name in source if name.startswith("badass_runner/") and name.endswith(".py")}:
        raise GuardError("sdist package does not exactly match source manifest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    stage_p = sub.add_parser("stage")
    stage_p.add_argument("destination", type=Path)
    source_p = sub.add_parser("source")
    source_p.add_argument("directory", type=Path, nargs="?", default=SOURCE_ROOT)
    artifact_p = sub.add_parser("artifact")
    artifact_p.add_argument("--source", required=True, type=Path)
    artifact_p.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "stage":
            stage(args.destination)
        elif args.command == "source":
            guard_source(args.directory)
        else:
            # Build tools add build/dist/egg-info after the prior strict source gate.
            source = source_files(args.source, load_manifest(), discovery=True)
            for artifact in args.artifacts:
                if artifact.suffix == ".whl":
                    wheel_guard(artifact, source)
                elif artifact.name.endswith((".tar.gz", ".tgz", ".tar")):
                    sdist_guard(artifact, source)
                else:
                    raise GuardError(f"unsupported artifact: {artifact}")
    # Scanner implementation errors must never turn a release check into a pass.
    except Exception as exc:
        print(f"EXPORT GUARD FAILED: {exc}", file=sys.stderr)
        return 1
    print("EXPORT GUARD PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())