"""Fake released-Tethers bundles for discovery/protocol/doctor tests.

These are *fakes*: they let the suite prove Permission Slip's consumption
boundary deterministically on any host, including failure modes a healthy
machine cannot produce. Real released-product proof lives in
``tests/test_product_proof.py``.
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

FAKE_PRODUCT_VERSION = "9.9.9"
GATE_MODES = (
    "ok",
    "wrong_protocol",
    "wrong_schema",
    "malformed",
    "exits",
    "silent",
    "provider_calls",
    "cli_error",
)

_GATE_SCRIPT = '''\
import json, sys

MODE = {mode!r}
PRODUCT_VERSION = {version!r}
HELLO = {{
    "authority_granted": False,
    "features": ["prepare", "approval_decision", "commit", "outcome", "status", "shutdown"],
    "gate_instance_id": "gate_fake_0000",
    "git_sha": None,
    "product_version": PRODUCT_VERSION,
    "protocol": "tethers.authority/1",
    "protocol_versions": ["tethers.authority/1"],
    "provider_invocations": 0,
}}


def emit(payload, schema="tethers.authority/1"):
    payload = dict(payload)
    payload["request_id"] = request_id
    if MODE == "wrong_schema":
        payload["schema"] = "tethers.authority/2"
    else:
        payload["schema"] = schema
    sys.stdout.write(json.dumps(payload) + "\\n")
    sys.stdout.flush()


def main():
    args = sys.argv[1:]
    if "--version" in args:
        sys.stdout.write("tethers " + PRODUCT_VERSION + "\\n")
        return 0
    if "describe" in args:
        sys.stdout.write(json.dumps({{
            "schema": "tethers.cli/1",
            "command": "describe",
            "status": "ok",
            "exit_code": 0,
            "data": {{
                "schema": "tethers.describe/1",
                "version": PRODUCT_VERSION,
                "cli_schema": "tethers.cli/1",
                "supported_protocol_versions": ["0.1"],
                "supported_language_versions": ["0.1"],
            }},
        }}) + "\\n")
        return 0
    if "gate" not in args:
        return 0

    if MODE == "exits":
        return 0
    if MODE == "malformed":
        sys.stdout.write("this is not json\\n")
        sys.stdout.flush()
        return 0

    if MODE == "silent":
        while True:
            line = sys.stdin.readline()
            if not line:
                return 0

    global request_id
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            return 0
        request_id = request.get("request_id")
        operation = request.get("operation")
        if operation == "hello":
            result = dict(HELLO)
            if MODE == "wrong_protocol":
                result["protocol"] = "tethers.authority/2"
                result["protocol_versions"] = ["tethers.authority/2"]
            if MODE == "provider_calls":
                result["provider_invocations"] = 3
            if MODE == "cli_error":
                emit({{"status": "error", "error": {{"code": "FAKE", "message": "fake"}}}},
                     schema="tethers.cli/1")
            else:
                emit({{"status": "ok", "result": result}})
        elif operation == "shutdown":
            emit({{"status": "ok", "result": {{"shutdown": True, "provider_invocations": 0}}}})
            return 0
        else:
            emit({{"status": "error",
                   "error": {{"code": "FAKE_UNSUPPORTED", "message": "unsupported"}}}})
    return 0


request_id = None
if __name__ == "__main__":
    raise SystemExit(main())
'''


def _launcher(directory: Path, script: Path) -> Path:
    """Create a real process launcher for ``script`` on this platform."""
    if sys.platform == "win32":
        launcher = directory / "tethers.cmd"
        launcher.write_text(
            "@echo off\r\n"
            f'"{sys.executable}" "{script}" %*\r\n',
            encoding="ascii",
        )
        return launcher
    launcher = directory / "tethers"
    launcher.write_text(
        "#!/bin/sh\n" f'exec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
    )
    launcher.chmod(0o755)
    return launcher


def make_fake_gate(directory: Path, mode: str = "ok") -> Path:
    """Write a fake Gate executable into ``directory``; returns its path."""
    if mode not in GATE_MODES:  # pragma: no cover - guard against typos
        raise ValueError(f"unknown fake gate mode {mode!r}")
    directory.mkdir(parents=True, exist_ok=True)
    script = directory / "_fake_tethers_gate.py"
    script.write_text(
        _GATE_SCRIPT.format(mode=mode, version=FAKE_PRODUCT_VERSION),
        encoding="utf-8",
        newline="\n",
    )
    return _launcher(directory, script)


def make_engine(directory: Path, name: str = "tethers-engine") -> Path:
    """Write a dummy matching engine file (the fake Gate ignores it)."""
    directory.mkdir(parents=True, exist_ok=True)
    engine = directory / (name + (".exe" if sys.platform == "win32" else ""))
    engine.write_bytes(b"fake-tethers-core-engine\n")
    return engine


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_release_manifest(bundle_root: Path, files: list[Path]) -> Path:
    lines = [
        f"{sha256(file)}  {file.relative_to(bundle_root).as_posix()}" for file in files
    ]
    manifest = bundle_root / "SHA256SUMS"
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return manifest


def make_release_bundle(
    bundle_root: Path,
    *,
    gate_mode: str = "ok",
    engine: bool = True,
    manifest: bool = True,
    tamper: bool = False,
) -> Path:
    """Build a bundle shaped like a real released Tethers runtime.

    Layout mirrors the shipped product: ``bin/tethers`` + matching engine
    beside it, with a ``SHA256SUMS`` manifest at the bundle root.
    """
    bin_dir = bundle_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    gate = make_fake_gate(bin_dir, gate_mode)
    engine_path = make_engine(bin_dir) if engine else None

    if manifest:
        files = [gate]
        if engine_path is not None:
            files.append(engine_path)
        write_release_manifest(bundle_root, files)
        if tamper:
            # Rebuild the engine after the manifest so its hash no longer matches.
            engine_path.write_bytes(b"tampered-tethers-core-engine\n")  # type: ignore[union-attr]
    return bundle_root


def bundle_env(bundle_root: Path) -> dict[str, str]:
    """Environment that makes ``bundle_root`` the *only* discovery source."""
    bin_dir = bundle_root / "bin"
    return {
        "PATH": str(bin_dir),
        "LOCALAPPDATA": str(bundle_root / "_no_install_root"),
    }


def isolated_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """An environment that cannot accidentally find a real Tethers."""
    env = {
        "PATH": str(Path(__file__).parent / "_definitely_absent_tethers_path"),
        "LOCALAPPDATA": str(Path(__file__).parent / "_definitely_absent_install_root"),
        "ProgramFiles": str(Path(__file__).parent / "_definitely_absent_pf"),
    }
    if extra:
        env.update(extra)
    return env


def copy_engine(source_bundle: Path, target_bundle: Path) -> Path:
    return shutil.copy(source_bundle / "bin" / engine_name(), target_bundle / "bin")


def engine_name() -> str:
    return "tethers-engine.exe" if sys.platform == "win32" else "tethers-engine"
