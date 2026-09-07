#!/usr/bin/env python3
"""Build, inspect, reproduce, and clean-install the public runner release.

All scratch state is deliberately created below the operating system temporary
directory.  This program is a release proof, not a developer build command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


RUNNER = Path(__file__).resolve().parents[1]
REPOSITORY = RUNNER.parent
PROTOCOL = REPOSITORY / "badass-runner-protocol"
GUARD = RUNNER / "scripts" / "export_guard.py"
EPOCH = "1704067200"


class GateError(RuntimeError):
    pass


def safe_temp_root() -> Path:
    """Resolve the process temp root and reject repository-contained scratch."""
    root = Path(tempfile.gettempdir()).resolve()
    if root == REPOSITORY or REPOSITORY in root.parents:
        raise GateError("temporary directory must be outside the monorepo")
    if not root.is_dir():
        raise GateError(f"temporary directory does not exist: {root}")
    return root


def child_env() -> dict[str, str]:
    """Return only non-sensitive process settings needed by build tools."""
    allowed = {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NIX_SSL_CERT_FILE",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    temp_root = str(safe_temp_root())
    env.update({"TMPDIR": temp_root, "TMP": temp_root, "TEMP": temp_root})
    env["SOURCE_DATE_EPOCH"] = EPOCH
    env["UV_CACHE_DIR"] = str(safe_temp_root() / "badass-uv-cache")
    return env


def run(args: list[str], cwd: Path) -> None:
    result = subprocess.run(args, cwd=cwd, env=child_env(), text=True, capture_output=True)
    if result.returncode:
        raise GateError(
            "command failed: " + " ".join(args) + "\n" + result.stdout + result.stderr
        )


def require_out(path: Path) -> Path:
    path = path.resolve()
    if path == REPOSITORY or REPOSITORY in path.parents:
        raise GateError("output directory must be outside the monorepo")
    path.mkdir(parents=True, exist_ok=True)
    return path


def copy_protocol(destination: Path) -> Path:
    """Copy only the protocol package inputs; never build around repository state."""
    if not PROTOCOL.is_dir():
        raise GateError("checked-in badass-runner-protocol package is missing")
    destination.mkdir()
    for rel in ("pyproject.toml", "README.md"):
        source = PROTOCOL / rel
        if not source.is_file() or source.is_symlink():
            raise GateError(f"unsafe protocol input: {rel}")
        shutil.copyfile(source, destination / rel)
    source_root = PROTOCOL / "src"
    if not source_root.is_dir() or source_root.is_symlink():
        raise GateError("unsafe protocol src input")
    for item in sorted(source_root.rglob("*")):
        rel = item.relative_to(PROTOCOL)
        if "__pycache__" in rel.parts or any(
            part.endswith(".egg-info") for part in rel.parts
        ):
            continue
        target = destination / rel
        if item.is_symlink() or not (item.is_dir() or item.is_file()):
            raise GateError(f"unsafe protocol input: {rel}")
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.suffix == ".py":
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target)
        else:
            raise GateError(f"unexpected protocol input: {rel}")
    return destination


def safe_member(name: str) -> str:
    path = PurePosixPath(name.rstrip("/"))
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise GateError(f"unsafe archive member {name!r}")
    return path.as_posix()


def artifact_manifest(path: Path, distribution: str, kind: str, version: str) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    if kind == "wheel":
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                mode = (info.external_attr >> 16) & 0o170000
                member_type = "directory" if info.is_dir() else "file"
                if member_type == "file" and mode not in (0, 0o100000):
                    raise GateError(f"unsafe wheel member type: {info.filename}")
                if member_type == "directory" and mode not in (0, 0o040000):
                    raise GateError(f"unsafe wheel member type: {info.filename}")
                data = b"" if member_type == "directory" else archive.read(info)
                members.append({"path": safe_member(info.filename), "type": member_type,
                                "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    else:
        with tarfile.open(path, "r:*") as archive:
            for info in archive.getmembers():
                if not (info.isfile() or info.isdir()):
                    raise GateError(f"unsafe sdist member type: {info.name}")
                member_type = "file" if info.isfile() else "directory"
                extracted = archive.extractfile(info) if info.isfile() else None
                data = extracted.read() if extracted else b""
                members.append({"path": safe_member(info.name), "type": member_type,
                                "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    if len({m["path"] for m in members}) != len(members):
        raise GateError(f"duplicate archive member in {path.name}")
    return {"distribution": distribution, "kind": kind, "version": version,
            "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "members": sorted(members, key=lambda item: (item["path"], item["type"]))}


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def built_artifacts(folder: Path, distribution: str) -> tuple[Path, Path]:
    wheels = sorted(folder.glob("*.whl"))
    sdists = sorted(folder.glob("*.tar.gz"))
    uv_ignore = folder / ".gitignore"
    if uv_ignore.exists() and uv_ignore.read_bytes() != b"*":
        raise GateError(f"{distribution} build produced an unexpected .gitignore")
    unexpected = sorted(
        path
        for path in folder.iterdir()
        if path.is_file() and path not in {*wheels, *sdists, uv_ignore}
    )
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        raise GateError(
            f"{distribution} build must produce exactly one wheel and one sdist"
        )
    return wheels[0], sdists[0]


def build_once(output: Path) -> dict[str, dict[str, Any]]:
    """Build the two distributions from independently staged, approved inputs."""
    output = require_out(output)
    work = Path(tempfile.mkdtemp(prefix="badass-release-", dir=safe_temp_root()))
    try:
        runner_stage = work / "runner"
        protocol_stage = copy_protocol(work / "protocol")
        run([sys.executable, str(GUARD), "stage", str(runner_stage)], RUNNER)
        run([sys.executable, str(GUARD), "source", str(runner_stage)], RUNNER)
        runner_project = (runner_stage / "pyproject.toml").read_text(encoding="utf-8")
        if "[tool.uv.sources]" in runner_project or 'badass-runner-protocol==0.1.0' not in runner_project:
            raise GateError("runner stage retained workspace override or lost exact protocol pin")
        protocol_out, runner_out = work / "protocol-dist", work / "runner-dist"
        protocol_out.mkdir()
        runner_out.mkdir()
        run(["uv", "build", "--out-dir", str(protocol_out)], protocol_stage)
        run(["uv", "build", "--out-dir", str(runner_out)], runner_stage)
        runner_files = built_artifacts(runner_out, "badass-runner")
        run([sys.executable, str(GUARD), "artifact", "--source", str(runner_stage),
             *(str(p) for p in runner_files)], RUNNER)
        records: dict[str, dict[str, Any]] = {}
        for distribution, folder, version in (("badass-runner-protocol", protocol_out, "0.1.0"),
                                               ("badass-runner", runner_out, "0.4.0")):
            files = built_artifacts(folder, distribution)
            for source in files:
                kind = "wheel" if source.suffix == ".whl" else "sdist"
                name = f"{distribution}-{kind}"
                if name in records:
                    raise GateError(f"duplicate logical artifact: {name}")
                target = output / source.name
                shutil.copyfile(source, target)
                manifest = artifact_manifest(target, distribution, kind, version)
                write_manifest(output / f"{name}.manifest.json", manifest)
                records[name] = manifest
        return records
    finally:
        shutil.rmtree(work, ignore_errors=True)


def content(manifest: dict[str, Any]) -> dict[str, Any]:
    result = dict(manifest)
    result.pop("artifact_sha256", None)
    return result


def verify(output: Path) -> dict[str, Any]:
    first, second = output / "first", output / "second"
    first.mkdir(parents=True, exist_ok=True)
    second.mkdir(parents=True, exist_ok=True)
    one, two = build_once(first), build_once(second)
    if set(one) != set(two) or any(content(one[key]) != content(two[key]) for key in one):
        raise GateError("reproducibility failure: normalized artifact manifests differ")
    byte_identical = all(one[key]["artifact_sha256"] == two[key]["artifact_sha256"] for key in one)
    proof = {"content_manifests_equal": True, "byte_identical": byte_identical,
             "comparison": "byte-identical" if byte_identical else "normalized-content-only"}
    write_manifest(output / "reproducibility.json", proof)
    return proof


def clean_install(artifacts: Path) -> None:
    protocol = next(artifacts.glob("badass_runner_protocol-*.whl"), None)
    runner = next(artifacts.glob("badass_runner-*.whl"), None)
    if protocol is None or runner is None:
        raise GateError("clean-install requires protocol and runner wheels")
    root = Path(
        tempfile.mkdtemp(prefix="badass-clean-install-", dir=safe_temp_root())
    )
    try:
        venv_dir = root / "venv"
        venv.EnvBuilder(with_pip=True).create(venv_dir)
        python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        # Both project distributions are explicit local wheels. Pip may resolve only
        # their ordinary declared third-party dependencies from the package index.
        run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--isolated",
                "--disable-pip-version-check",
                "--no-input",
                "--index-url",
                "https://pypi.org/simple",
                str(protocol),
                str(runner),
            ],
            root,
        )
        code = r"""
import importlib.util, pathlib, subprocess, sys
import badass_runner, badass_runner_protocol
from importlib.metadata import distribution
site = pathlib.Path(badass_runner.__file__).resolve().parent.parent
repository = pathlib.Path(sys.argv[1]).resolve()
assert all(
    repository != pathlib.Path(item).resolve()
    and repository not in pathlib.Path(item).resolve().parents
    for item in sys.path
    if item
)
for module in (badass_runner, badass_runner_protocol):
    origin = pathlib.Path(module.__file__).resolve()
    if site not in origin.parents: raise AssertionError("module outside venv site-packages")
    if repository == origin or repository in origin.parents: raise AssertionError("module resolved from monorepo")
for name in ("badass-runner", "badass-runner-protocol"):
    dist = distribution(name)
    text = "\n".join((site / f).read_text(errors="ignore") for f in (dist.files or []) if (site / f).is_file())
    if str(repository) in text or "badass-release-" in text: raise AssertionError("forbidden build path in metadata")
requirements = [x.replace(" ", "") for x in (distribution("badass-runner").metadata.get_all("Requires-Dist") or [])]
assert "badass-runner-protocol==0.1.0" in requirements
assert all(importlib.util.find_spec(x) is None for x in ("back"+"end", "front"+"end", "scan"+"ners", "app"))
payload={"schema_version":2,"path":"/","method":"GET","request_body":{},"authorized_headers":None,"non_mutating":True,"requires_isolated_fixture":False,"isolated_fixture":False,"unauthorized_variants":[{"name":"none","headers":{},"request_body":None,"non_mutating":None,"requires_isolated_fixture":None}]}
from badass_runner.harness.enforcement import deserialize_enforcement_probe
assert deserialize_enforcement_probe(payload) == payload
try: deserialize_enforcement_probe(dict(payload, extra=True))
except ValueError: pass
else: raise AssertionError("protocol accepted unknown field")
entrypoint = pathlib.Path(sys.executable).with_name("badass-runner")
version = subprocess.run([str(entrypoint),"--version"], check=True, text=True, capture_output=True)
assert version.stdout.strip() == "badass-runner, version 0.4.0"
help_result = subprocess.run([str(entrypoint),"--help"], check=True, text=True, capture_output=True)
assert "Commands:" in help_result.stdout and "start" in help_result.stdout
"""
        run([str(python), "-c", code, str(REPOSITORY.resolve())], root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "verify", "all"):
        item = sub.add_parser(name)
        item.add_argument("--output", type=Path, required=True)
    install = sub.add_parser("clean-install")
    install.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build_once(args.output)
        elif args.command == "verify":
            verify(require_out(args.output))
        elif args.command == "clean-install":
            clean_install(args.artifacts.resolve())
        else:
            output = require_out(args.output)
            verify(output)
            clean_install(output / "first")
    except (GateError, OSError, subprocess.SubprocessError, StopIteration) as exc:
        print(f"RELEASE GATE FAILED: {exc}", file=sys.stderr)
        return 1
    print("RELEASE GATE PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())