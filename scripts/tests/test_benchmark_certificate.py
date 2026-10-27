#!/usr/bin/env python3
"""Fast runner tests; fake Rust processes exercise isolation and failure checks."""
import contextlib
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "benchmark-certificate.py"
SPEC = importlib.util.spec_from_file_location("benchmark_certificate", MODULE_PATH)
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)
CONFIG = dict(name="smoke", degree=18, lookup_bits=16, quorum=2, num_lotteries=32,
              num_signers=4, merkle_depth=2, target="half", seed=1)


def csv_values(config):
    values = {field: str(config[field]) for field in BENCH.CONFIG_FIELDS}
    values.update({field: "1" for field in BENCH.CSV_FIELDS[len(BENCH.CONFIG_FIELDS):]})
    values["proof_total_s"] = "2"
    return values


def write_csv(path, config, **updates):
    values = csv_values(config)
    values.update(updates)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=BENCH.CSV_FIELDS)
        writer.writeheader()
        writer.writerow(values)


class CertificateRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "halo2-ecc").mkdir()
        self.destination = self.root / "artifacts" / "certificate"
        self.destination.mkdir(parents=True)
        self.executable = self.root / "fake-rust-test"
        self.executable.write_text("#!/usr/bin/env python3\n" + f'''
import csv,json,os,sys
from pathlib import Path
if "--list" in sys.argv:
    if os.environ.get("FAKE_MISSING_TEST") != "1":
        print({BENCH.TEST_NAME!r} + ": test")
    sys.exit(0)
config=json.loads(Path(os.environ["HALO2_BENCH_CONFIG"]).read_text())
fields={BENCH.CSV_FIELDS!r}
values={{field:str(config[field]) for field in fields[:9]}}
values.update({{field:"1" for field in fields[9:]}})
values["proof_total_s"]="2"
with Path(os.environ["HALO2_BENCH_OUTPUT"]).open("w",newline="") as stream:
    writer=csv.DictWriter(stream,fieldnames=fields)
    writer.writeheader()
    writer.writerow(values)
print("pid="+str(os.getpid()))
if os.environ.get("FAKE_MUTATE_EXECUTABLE") == "1":
    with Path(sys.argv[0]).open("a") as stream:
        stream.write("# changed during benchmark\\n")
if os.environ.get("FAKE_ZERO_TESTS") == "1":
    print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s")
else:
    print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s")
''')
        self.executable.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def test_schema_rejects_missing_extra_boolean_and_out_of_bounds(self):
        variants = [dict(CONFIG, typo=1), dict(CONFIG, degree=True), dict(CONFIG, seed=2**64),
                    dict(CONFIG, num_signers=5), dict(CONFIG, quorum=33), dict(CONFIG, target="arbitrary"),
                    dict(CONFIG, merkle_depth=21), dict(CONFIG, degree=25), dict(CONFIG, name="has spaces"),
                    dict(CONFIG, name="x" * 65)]
        missing = dict(CONFIG)
        del missing["seed"]
        variants.append(missing)
        path = self.root / "config.jsonl"
        for variant in variants:
            with self.subTest(variant=variant):
                path.write_text(json.dumps(variant) + "\n")
                with self.assertRaises(ValueError):
                    BENCH.load_configs(path)
        path.write_text(json.dumps(dict(CONFIG, num_signers=1, merkle_depth=0)) + "\n")
        self.assertEqual(BENCH.load_configs(path)[0]["merkle_depth"], 0)
        path.write_text(json.dumps(CONFIG)[:-1] + ',"seed":2}\n')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            BENCH.load_configs(path)
        path.write_text(json.dumps(CONFIG) + "\n" + json.dumps(CONFIG) + "\n")
        with self.assertRaisesRegex(ValueError, "duplicate config name"):
            BENCH.load_configs(path)
        path.write_text("\n" + json.dumps(CONFIG) + "\n \n")
        self.assertEqual(len(BENCH.load_configs(path)), 1)

    def test_peak_rss_uses_per_child_value_and_platform_units(self):
        for system, expected in (("Darwin", 7), ("Linux", 7 * 1024)):
            with self.subTest(system=system), patch.object(BENCH.platform, "system", return_value=system), \
                    patch.object(BENCH.subprocess, "Popen", return_value=SimpleNamespace(pid=123)), \
                    patch.object(BENCH.os, "wait4", return_value=(123, 0, SimpleNamespace(ru_maxrss=7))) as wait:
                values = BENCH.measured_process(["fake"], self.root, {}, self.root / "stdout.log")
                self.assertEqual(values["peak_rss_bytes"], expected)
                wait.assert_called_once_with(123, 0)

    def test_interrupted_wait_kills_and_reaps_child(self):
        child = SimpleNamespace(pid=123)
        with patch.object(BENCH.subprocess, "Popen", return_value=child), \
                patch.object(BENCH.os, "wait4", side_effect=[KeyboardInterrupt, (123, 9, SimpleNamespace(ru_maxrss=7))]) as wait, \
                patch.object(BENCH.os, "kill") as kill:
            with self.assertRaises(KeyboardInterrupt):
                BENCH.measured_process(["fake"], self.root, {}, self.root / "stdout.log")
            kill.assert_called_once_with(123, BENCH.signal.SIGKILL)
            self.assertEqual(wait.call_count, 2)
            self.assertEqual(child.returncode, -9)

    def test_changed_executable_rejected_with_partial_artifacts(self):
        with patch.dict(os.environ, {"FAKE_MUTATE_EXECUTABLE": "1"}), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "executable changed"):
                BENCH.run_jobs(self.root, self.destination, [CONFIG], 1, self.executable, 1, "system")
        job = next(self.destination.glob("repeat-*/row-*"))
        self.assertIn("executable changed", (job / "status").read_text())
        self.assertTrue((job / "resources.json").is_file())
        with (self.destination / "measurements.csv").open(newline="") as stream:
            self.assertEqual(list(csv.DictReader(stream)), [])

    def test_csv_rejects_config_mismatch_nan_duplicate_rows_and_wrong_total(self):
        path = self.root / "measurements.csv"
        write_csv(path, CONFIG)
        self.assertEqual(BENCH.validate_csv(path, CONFIG)["name"], "smoke")
        for updates in ({"seed": "2"}, {"num_lotteries": "33"}, {"verify_s": "NaN"},
                        {"proof_total_s": "3"}, {"proof_size_bytes": "0"}):
            with self.subTest(updates=updates):
                write_csv(path, CONFIG, **updates)
                with self.assertRaises(ValueError):
                    BENCH.validate_csv(path, CONFIG)
        write_csv(path, CONFIG)
        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines + [lines[1]]) + "\n")
        with self.assertRaises(ValueError):
            BENCH.validate_csv(path, CONFIG)

    def test_every_row_and_repetition_uses_distinct_measured_process(self):
        configs = [CONFIG, dict(CONFIG, name="second", seed=2)]
        with contextlib.redirect_stdout(io.StringIO()):
            BENCH.run_jobs(self.root, self.destination, configs, 2, self.executable, 3, "system")
        logs = sorted(self.destination.glob("repeat-*/row-*/stdout.log"))
        self.assertEqual(len(logs), 4)
        pids = {path.read_text().splitlines()[0] for path in logs}
        self.assertEqual(len(pids), 4)
        with (self.destination / "measurements.csv").open(newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual([(row["repetition"], row["name"], row["seed"]) for row in rows],
                         [("1", "smoke", "1"), ("1", "second", "2"), ("2", "smoke", "1"), ("2", "second", "2")])
        for row in rows:
            self.assertGreater(int(row["peak_rss_bytes"]), 0)
            self.assertGreater(float(row["process_wall_seconds"]), 0)
        for log in logs:
            self.assertEqual((log.parent / "status").read_text(), "completed\n")
            resource = json.loads((log.parent / "resources.json").read_text())
            self.assertEqual(resource["exit_code"], 0)
            self.assertGreater(resource["peak_rss_bytes"], 0)

    def test_zero_tests_rejected_even_with_valid_csv_and_logs_retained(self):
        with patch.dict(os.environ, {"FAKE_ZERO_TESTS": "1"}), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "exactly one passing"):
                BENCH.run_jobs(self.root, self.destination, [CONFIG], 1, self.executable, 1, "system")
        job = next(self.destination.glob("repeat-*/row-*"))
        self.assertTrue((job / "status").read_text().startswith("failed:"))
        self.assertTrue((job / "resources.json").is_file())
        self.assertTrue((job / "measurements.csv").is_file())
        with (self.destination / "measurements.csv").open(newline="") as stream:
            self.assertEqual(list(csv.DictReader(stream)), [])

    def test_build_discovery_selects_executable_and_rejects_missing_test(self):
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        cargo = fake_bin / "cargo"
        artifact = {"reason": "compiler-artifact", "target": {"name": "halo2_ecc"},
                    "profile": {"test": True}, "executable": str(self.executable)}
        cargo.write_text("#!/usr/bin/env python3\nprint(" + repr(json.dumps(artifact)) + ")\n")
        cargo.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(fake_bin) + os.pathsep + os.environ["PATH"]}):
            self.assertEqual(BENCH.build_executable(self.root, self.destination, ["test"]), self.executable)
            with patch.dict(os.environ, {"FAKE_MISSING_TEST": "1"}):
                with self.assertRaisesRegex(RuntimeError, "Exact Certificate benchmark test missing"):
                    BENCH.build_executable(self.root, self.destination, ["test"])

    def test_source_integrity_detects_changes_and_additions(self):
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        source = self.root / "input.rs"
        source.write_text("original\n")
        before = {"input.rs": hashlib.sha256(source.read_bytes()).hexdigest()}
        # The fake executable has no recognized source suffix and run artifacts are excluded.
        BENCH.write_json(self.destination.parent / "input-sha256.json", before)
        BENCH.verify_inputs(self.root, self.destination.parent)
        source.write_text("modified\n")
        (self.root / "extra.rs").write_text("new source\n")
        with self.assertRaisesRegex(RuntimeError, "Source inputs changed"):
            BENCH.verify_inputs(self.root, self.destination.parent)
        result = json.loads((self.destination.parent / "source-integrity.json").read_text())
        self.assertEqual(result["changed"], ["input.rs"])
        self.assertEqual(result["added"], ["extra.rs"])

    def test_shell_all_excludes_certificate_and_explicit_dry_run_includes_it(self):
        script = MODULE_PATH.parent / "benchmark-components.sh"
        all_output = subprocess.check_output(["bash", str(script), "smoke", "all", "--dry-run"], text=True)
        self.assertEqual(all_output.count("Component:"), 4)
        self.assertNotIn("Component: certificate", all_output)
        self.assertNotIn(BENCH.TEST_NAME, all_output)
        certificate_output = subprocess.check_output(["bash", str(script), "smoke", "certificate", "--dry-run"], text=True)
        self.assertIn(BENCH.TEST_NAME, certificate_output)
        self.assertIn("--no-run --message-format=json", certificate_output)
        self.assertIn("wait4", certificate_output)


if __name__ == "__main__":
    unittest.main()
