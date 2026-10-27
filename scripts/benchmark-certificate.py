#!/usr/bin/env python3
"""Run one isolated Certificate benchmark process per config row and repetition."""
import argparse
import csv
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time

CONFIG_FIELDS = (
    "name", "degree", "lookup_bits", "quorum", "num_lotteries",
    "num_signers", "merkle_depth", "target", "seed",
)
CSV_FIELDS = CONFIG_FIELDS + (
    "num_advice", "num_lookup_advice", "num_fixed", "keygen_fixture_s",
    "prover_fixture_s", "keygen_build_s", "srs_s", "vk_s", "pk_s",
    "prover_build_s", "proof_generation_s", "proof_total_s", "verify_s", "proof_size_bytes",
)
INTEGER_METRICS = {"num_advice", "num_lookup_advice", "num_fixed", "proof_size_bytes"}
TEST_NAME = "bn254::tests::certificate_bench::bench_certificate"
PASS_SUMMARY = re.compile(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;(?: finished in .*)?$", re.MULTILINE)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def load_configs(path):
    rows = []
    names = set()
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=unique_object)
            if not isinstance(row, dict) or set(row) != set(CONFIG_FIELDS):
                raise ValueError("expected exactly the nine Certificate config fields")
            if not isinstance(row["name"], str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", row["name"]) is None:
                raise ValueError("name must contain 1..64 ASCII letters, digits, underscores or hyphens")
            if row["name"] in names:
                raise ValueError(f"duplicate config name: {row['name']}")
            if row["target"] not in ("max", "half"):
                raise ValueError("target must be max or half")
            for name in set(CONFIG_FIELDS) - {"name", "target"}:
                if type(row[name]) is not int or not 0 <= row[name] <= 2**64 - 1:
                    raise ValueError(f"{name} must be an unsigned 64-bit integer")
            if not 10 <= row["degree"] <= 24 or not 0 < row["lookup_bits"] < row["degree"]:
                raise ValueError("require degree 10..24 and 0 < lookup_bits < degree")
            if not 1 <= row["num_lotteries"] <= 1_000_000:
                raise ValueError("num_lotteries must be 1..1000000")
            if not 1 <= row["quorum"] <= min(4096, row["num_lotteries"]):
                raise ValueError("require quorum 1..4096 and quorum <= num_lotteries")
            if row["merkle_depth"] > 20 or not 1 <= row["num_signers"] <= 2 ** row["merkle_depth"]:
                raise ValueError("require merkle_depth <= 20 and 1 <= num_signers <= 2^merkle_depth")
        except (ValueError, TypeError) as error:
            raise ValueError(f"Invalid Certificate config row {line_number}: {error}") from error
        names.add(row["name"])
        rows.append({field: row[field] for field in CONFIG_FIELDS})
    if not rows:
        raise ValueError("Empty Certificate config")
    return rows


def validate_csv(path, config):
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(CSV_FIELDS):
            raise ValueError("Certificate CSV header does not match the complete expected schema")
        rows = list(reader)
    if len(rows) != 1 or None in rows[0] or any(value is None for value in rows[0].values()):
        raise ValueError("Expected exactly one complete Certificate CSV row per process")
    row = rows[0]
    for field in CONFIG_FIELDS:
        if row[field] != str(config[field]):
            raise ValueError(f"Certificate CSV config mismatch for {field}: {row[field]!r}")
    for field in CSV_FIELDS[len(CONFIG_FIELDS):]:
        value = row[field]
        if field in INTEGER_METRICS:
            if re.fullmatch(r"[0-9]+", value) is None or int(value) <= 0:
                raise ValueError(f"Invalid positive integer metric {field}: {value!r}")
        else:
            try:
                number = float(value)
            except ValueError as error:
                raise ValueError(f"Invalid numeric metric {field}: {value!r}") from error
            if not math.isfinite(number) or number < 0:
                raise ValueError(f"Invalid nonnegative finite metric {field}: {value!r}")
    total = float(row["proof_total_s"])
    parts = float(row["prover_build_s"]) + float(row["proof_generation_s"])
    # Rust emits nine decimal places, so allow only the accumulated rounding error.
    if not math.isclose(total, parts, rel_tol=0, abs_tol=0.000000002):
        raise ValueError("proof_total_s does not equal prover_build_s + proof_generation_s")
    return row


def measured_process(command, cwd, environment, log_path):
    """wait4 reports this child's peak, independent of build and prior children."""
    system = platform.system()
    if system not in ("Darwin", "Linux") or not hasattr(os, "wait4"):
        raise RuntimeError("Certificate peak RSS measurement requires macOS or Linux wait4")
    started = time.perf_counter()
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            while True:
                try:
                    _, status, usage = os.wait4(process.pid, 0)
                    break
                except InterruptedError:
                    continue
        except BaseException:
            # Cancellation must not leave a large proving process behind.
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                _, stopped_status, _ = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(stopped_status)
            except ChildProcessError:
                pass
            raise
        process.returncode = os.waitstatus_to_exitcode(status)
    return {
        "exit_code": process.returncode,
        "process_wall_seconds": time.perf_counter() - started,
        "peak_rss_bytes": int(usage.ru_maxrss) * (1 if system == "Darwin" else 1024),
        "measurement": "wait4 for the direct Rust test process; excludes Cargo/build",
        "wall_time_scope": "whole test process, including fixture creation, SRS, keygen, proof, verification, and startup",
        "platform": system,
    }


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_executable_hash(executable, expected):
    if not executable.is_file() or file_sha256(executable) != expected:
        raise RuntimeError("Built test executable changed during the benchmark; measurements are invalid")


def build_executable(root, destination, cargo_args):
    command = ["cargo", *cargo_args, "--no-run", "--message-format=json"]
    log_path = destination / "build.log"
    with log_path.open("wb") as log:
        result = subprocess.run(command, cwd=root / "halo2-ecc", stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Certificate build failed; see {log_path}")
    executables = set()
    for line in log_path.read_text(errors="replace").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if (isinstance(item, dict) and item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "halo2_ecc"
                and item.get("profile", {}).get("test") is True and item.get("executable")):
            executables.add(item["executable"])
    if len(executables) != 1:
        raise RuntimeError(f"Expected one halo2-ecc test executable, found {len(executables)}; see {log_path}")
    executable = Path(executables.pop()).resolve()
    if not executable.is_file():
        raise RuntimeError(f"Built test executable is missing: {executable}")
    command = [str(executable), TEST_NAME, "--exact", "--list"]
    discovery = subprocess.run(command, cwd=root / "halo2-ecc", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    discovery_text = discovery.stdout.decode(errors="replace")
    (destination / "discovery.log").write_text(discovery_text)
    if discovery.returncode or discovery_text.splitlines().count(f"{TEST_NAME}: test") != 1:
        raise RuntimeError(f"Exact Certificate benchmark test missing; see {destination / 'discovery.log'}")
    write_json(destination / "executable.json", {
        "path": str(executable), "sha256": file_sha256(executable),
        "build_command": ["cargo", *cargo_args, "--no-run", "--message-format=json"],
    })
    return executable


def verify_inputs(root, run_dir):
    before = json.loads((run_dir / "input-sha256.json").read_text())
    paths = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    after = {}
    for raw in paths.split(b"\0"):
        if not raw:
            continue
        relative = os.fsdecode(raw)
        path = root / relative
        if not path.is_file() or run_dir == path.resolve() or run_dir in path.resolve().parents:
            continue
        if path.suffix not in {".rs", ".toml", ".lock", ".config", ".json", ".sh", ".py"} and path.name != "rust-toolchain":
            continue
        after[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(run_dir / "input-sha256-after.json", after)
    comparison = {
        "unchanged": before == after,
        "changed": sorted(name for name in before.keys() & after.keys() if before[name] != after[name]),
        "missing": sorted(before.keys() - after.keys()),
        "added": sorted(after.keys() - before.keys()),
    }
    write_json(run_dir / "source-integrity.json", comparison)
    if before != after:
        raise RuntimeError(f"Source inputs changed during Certificate benchmark; see {run_dir / 'source-integrity.json'}")


def run_jobs(root, destination, configs, repetitions, executable, threads, allocator):
    executable_metadata = destination / "executable.json"
    expected_hash = (json.loads(executable_metadata.read_text())["sha256"]
                     if executable_metadata.exists() else file_sha256(executable))
    aggregate_fields = ("repetition", "config_row") + CSV_FIELDS + ("process_wall_seconds", "peak_rss_bytes")
    aggregate = destination / "measurements.csv"
    with aggregate.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=aggregate_fields)
        writer.writeheader()
        stream.flush()
        for repetition in range(1, repetitions + 1):
            for row_number, config in enumerate(configs, 1):
                job_dir = destination / f"repeat-{repetition:03d}" / f"row-{row_number:03d}-{config['name']}"
                job_dir.mkdir(parents=True)
                config_path = job_dir / "config.jsonl"
                config_path.write_text(json.dumps(config, separators=(",", ":")) + "\n")
                csv_path = job_dir / "measurements.csv"
                environment = os.environ.copy()
                environment.update(HALO2_BENCH_CONFIG=str(config_path), HALO2_BENCH_OUTPUT=str(csv_path), RAYON_NUM_THREADS=str(threads))
                command = [str(executable), TEST_NAME, "--ignored", "--exact", "--nocapture", "--test-threads=1"]
                metadata = {
                    "component": "certificate", "repetition": repetition, "config_row": row_number,
                    "config": config, "threads": threads, "allocator": allocator,
                    "command": command, "cwd": str(root / "halo2-ecc"), "started_utc": utc_now(),
                    "executable_sha256": expected_hash,
                    "params_directory": environment.get("PARAMS_DIR"),
                }
                write_json(job_dir / "metadata.json", metadata)
                (job_dir / "status").write_text("running\n")
                print(f"Running certificate row {row_number}/{len(configs)} ({config['name']}), repetition {repetition}/{repetitions}", flush=True)
                try:
                    require_executable_hash(executable, expected_hash)
                    resources = measured_process(command, root / "halo2-ecc", environment, job_dir / "stdout.log")
                    write_json(job_dir / "resources.json", resources)
                    require_executable_hash(executable, expected_hash)
                    if resources["exit_code"] != 0:
                        raise RuntimeError(f"Certificate test exited {resources['exit_code']}")
                    log = (job_dir / "stdout.log").read_text(errors="replace")
                    if len(PASS_SUMMARY.findall(log)) != 1:
                        raise RuntimeError("Expected exactly one passing, non-ignored Certificate benchmark test")
                    values = validate_csv(csv_path, config)
                    values.update(repetition=repetition, config_row=row_number,
                                  process_wall_seconds=resources["process_wall_seconds"], peak_rss_bytes=resources["peak_rss_bytes"])
                    writer.writerow(values)
                    stream.flush()
                    (job_dir / "status").write_text("completed\n")
                except BaseException as error:
                    (job_dir / "status").write_text(f"failed: {error}\n")
                    raise RuntimeError(f"Certificate benchmark failed; retained artifacts: {job_dir}: {error}") from error
                finally:
                    metadata["finished_utc"] = utc_now()
                    write_json(job_dir / "metadata.json", metadata)
    print(f"Certificate combined measurements: {aggregate}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, required=True)
    parser.add_argument("--threads", type=int, required=True)
    parser.add_argument("--allocator", choices=("system", "jemalloc"), required=True)
    parser.add_argument("cargo_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root, destination = args.root.resolve(), args.destination.resolve()
    if args.repetitions < 1 or args.threads < 1:
        raise ValueError("repetitions and threads must be positive")
    configs = load_configs(destination / "config.jsonl")
    cargo_args = args.cargo_args[1:] if args.cargo_args[:1] == ["--"] else args.cargo_args
    if not cargo_args or cargo_args[0] != "test":
        raise ValueError("Expected Cargo test arguments after --")
    try:
        executable = build_executable(root, destination, cargo_args)
        run_jobs(root, destination, configs, args.repetitions, executable, args.threads, args.allocator)
    finally:
        verify_inputs(root, destination.parent)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
