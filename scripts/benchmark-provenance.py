#!/usr/bin/env python3
"""Capture benchmark inputs and machine metadata without collecting credentials."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile


def output(*command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    return result.stdout.decode("utf-8", errors="replace").strip()


root, destination = (Path(value).resolve() for value in sys.argv[1:3])
mode, threads, repetitions, features = sys.argv[3:7]
metadata = {
    "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "repository": str(root),
    "revision": output("git", "-C", str(root), "rev-parse", "HEAD"),
    "branch": output("git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"),
    "mode": mode,
    "rayon_threads": int(threads),
    "repetitions": int(repetitions),
    "cargo_features": features,
    "params_directory": os.environ.get("PARAMS_DIR"),
    "profile": "release",
    "platform": platform.platform(),
    "machine": platform.machine(),
    "logical_cpus": os.cpu_count(),
    "rustc": output("rustc", "-Vv"),
    "cargo": output("cargo", "-V"),
    "build_environment": {key: os.environ[key] for key in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_BUILD_JOBS",
        "CARGO_TARGET_DIR", "CC", "CXX", "CFLAGS", "CXXFLAGS"
    ) if key in os.environ},
    "timing": "CSV durations come from the Rust harness; runner timestamps are provenance only",
}
if platform.system() == "Darwin":
    metadata["cpu"] = output("sysctl", "-n", "machdep.cpu.brand_string")
    metadata["memory_bytes"] = output("sysctl", "-n", "hw.memsize")
elif platform.system() == "Linux":
    metadata["cpu"] = output("lscpu")
    metadata["memory"] = Path("/proc/meminfo").read_text() if Path("/proc/meminfo").exists() else "unknown"

(destination / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
(destination / "git-status-before.txt").write_text(output("git", "-C", str(root), "status", "--short") + "\n")
with (destination / "source.patch").open("wb") as stream:
    subprocess.run(["git", "-C", str(root), "diff", "--binary", "HEAD", "--"], stdout=stream, check=True)


def git_paths(*arguments):
    result = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", *arguments])
    return [Path(os.fsdecode(value)) for value in result.split(b"\0") if value]


tracked = git_paths()
untracked = git_paths("--others", "--exclude-standard")
hashes = {}
included_untracked = []
for relative in sorted(set(tracked + untracked)):
    path = root / relative
    if not path.is_file() or destination == path.resolve() or destination in path.resolve().parents:
        continue
    # Inputs and code only: exclude unrelated local binaries, keys, and secrets.
    if path.suffix not in {".rs", ".toml", ".lock", ".config", ".json", ".sh", ".py"} and path.name != "rust-toolchain":
        continue
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    hashes[str(relative)] = hasher.hexdigest()
    if relative in untracked:
        included_untracked.append(relative)
(destination / "input-sha256.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n")
# New regression/source files are not represented in git diff until tracked.
with tarfile.open(destination / "untracked-inputs.tar.gz", "w:gz") as archive:
    for relative in included_untracked:
        archive.add(root / relative, arcname=str(relative), recursive=False)
for relative in ("Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml", "halo2-base/Cargo.toml", "halo2-ecc/Cargo.toml"):
    path = root / relative
    if path.is_file():
        target = destination / "manifests" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
