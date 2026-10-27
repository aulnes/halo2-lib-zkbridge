#!/usr/bin/env bash
# Run only the curated component benchmarks. Compatible with macOS Bash 3.2.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: benchmark-components.sh smoke|bench [all|msp_msm|eligibility|merkle_tree|index|certificate] [options]

  smoke                 One small real proof per selected component (not a performance study)
  bench                 The checked-in component parameter sweep
  all                   The four historical components; Certificate requires explicit selection
  certificate           One fresh process per config row and repetition, with peak RSS
  --repetitions N        Independent processes per component (Certificate: per row; default: 1)
  --threads N            Rayon worker threads (default: 1)
  --allocator NAME       system (default) or jemalloc; keep identical in comparisons
  --config FILE          Override JSONL config; only with one selected component
  --output-dir DIR       Parent directory for unique runs (default: <repo>/benchmark-runs)
  --dry-run              Print commands without building or writing artifacts
  -h, --help             Show this help

Run the constraint regressions separately before collecting measurements.
Every command uses --locked, the PSE backend, release mode, and one exact test.
USAGE
}

die() { printf 'Error: %s\n' "$*" >&2; exit 2; }
positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd -P)
mode=${1:---help}
case "$mode" in
    -h|--help) usage; exit 0 ;;
    smoke|bench) shift ;;
    *) usage >&2; die "select smoke or bench" ;;
esac
component=all
if [[ $# -gt 0 && "$1" != -* ]]; then component=$1; shift; fi
case "$component" in all|msp_msm|eligibility|merkle_tree|index|certificate) ;; *) die "unknown component: $component" ;; esac
repetitions=1
threads=1
allocator=system
output_root="$repo_root/benchmark-runs"
custom_config=
dry_run=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repetitions|--threads|--allocator|--config|--output-dir)
            [[ $# -ge 2 ]] || die "missing value for $1"
            case "$1" in
                --repetitions) repetitions=$2 ;;
                --threads) threads=$2 ;;
                --allocator) allocator=$2 ;;
                --config) custom_config=$2 ;;
                --output-dir) output_root=$2 ;;
            esac
            shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done
positive_integer "$repetitions" || die "--repetitions must be a positive integer"
positive_integer "$threads" || die "--threads must be a positive integer"
case "$allocator" in system|jemalloc) ;; *) die "--allocator must be system or jemalloc" ;; esac
if [[ -n "$custom_config" ]]; then
    [[ "$component" != all ]] || die "--config requires one component"
    [[ -f "$custom_config" ]] || die "config does not exist: $custom_config"
    custom_config=$(CDPATH= cd -- "$(dirname -- "$custom_config")" && printf '%s/%s\n' "$PWD" "$(basename -- "$custom_config")")
fi
components=(msp_msm eligibility merkle_tree index)
if [[ "$component" != all ]]; then components=("$component"); fi
features=halo2-pse,display
if [[ "$allocator" == jemalloc ]]; then features="$features,jemallocator"; fi
cargo_args=(test --manifest-path "$repo_root/Cargo.toml" -p halo2-ecc --lib --release --locked --no-default-features --features "$features")

select_component() {
    case "$1" in
        msp_msm) test_name=bn254::tests::msp::bench_msp_msm; config_name=bench_msp_msm.config ;;
        eligibility) test_name=bn254::tests::eligibility_check::bench_eligibility_check; config_name=bench_eligibility_check.config ;;
        merkle_tree) test_name=bn254::tests::merkle_tree::bench_merkle_tree; config_name=bench_merkle_tree.config ;;
        index) test_name=bn254::tests::index_check::bench_index_check; config_name=bench_index_check.config ;;
        certificate) test_name=bn254::tests::certificate_bench::bench_certificate; config_name=bench_certificate.config ;;
    esac
    config_source="$repo_root/halo2-ecc/configs/bn254/$config_name"
    if [[ "$mode" == smoke ]]; then config_source="$script_dir/configs/smoke/$1.config"; fi
    if [[ -n "$custom_config" ]]; then config_source=$custom_config; fi
    [[ -s "$config_source" ]] || die "config missing or empty: $config_source"
}

if [[ "$dry_run" == 1 ]]; then
    printf 'Working directory: %s\n' "$repo_root/halo2-ecc"
    for selected in "${components[@]}"; do
        select_component "$selected"
        printf 'Component: %s; repetitions: %s; config: %s\n' "$selected" "$repetitions" "$config_source"
        if [[ "$selected" == certificate ]]; then
            printf 'Build once: '; printf '%q ' cargo "${cargo_args[@]}" --no-run --message-format=json; printf '\n'
            printf 'Then each config row/repetition: RAYON_NUM_THREADS=%q HALO2_BENCH_CONFIG=%q HALO2_BENCH_OUTPUT=%q ' "$threads" '<unique-row>/config.jsonl' '<unique-row>/measurements.csv'
            printf '%q ' '<built-test-executable>' "$test_name" --ignored --exact --nocapture --test-threads=1
            printf '\nPeak RSS and process wall time: wait4 for that direct test process; no Cargo/build memory.\n'
            continue
        fi
        printf 'RAYON_NUM_THREADS=%q HALO2_BENCH_CONFIG=%q HALO2_BENCH_OUTPUT=%q ' "$threads" "$config_source" '<unique-run>/measurements.csv'
        printf '%q ' cargo "${cargo_args[@]}" "$test_name" -- --ignored --exact --nocapture --test-threads=1
        printf '\n'
    done
    exit 0
fi

for command in cargo rustc git python3; do command -v "$command" >/dev/null || die "missing command: $command"; done
[[ -s "$repo_root/Cargo.lock" ]] || die "Cargo.lock is required; do not collect results with an unpinned resolution"
mkdir -p -- "$output_root"
output_root=$(CDPATH= cd -- "$output_root" && pwd -P)
run_dir=$(mktemp -d "$output_root/$(date -u +%Y%m%dT%H%M%SZ)-${mode}.XXXXXX")
printf 'Artifacts: %s\n' "$run_dir"
printf 'running\n' > "$run_dir/status"
trap 'exit_code=$?; if [[ $exit_code -ne 0 ]]; then printf "failed (exit %s)\n" "$exit_code" > "$run_dir/status"; if [[ -n "${job_dir:-}" && -f "$job_dir/status" && $(< "$job_dir/status") == running ]]; then printf "failed (exit %s)\n" "$exit_code" > "$job_dir/status"; fi; printf "Run failed; retained artifacts: %s\n" "$run_dir" >&2; fi' EXIT

export RAYON_NUM_THREADS="$threads"
export RUST_TEST_THREADS=1
export CARGO_TERM_COLOR=never
export RUST_BACKTRACE=1
export PARAMS_DIR="$run_dir/params"
# Cargo test sets the test process cwd to the crate root; this explicit cd also
# makes direct invocations and Cargo's build environment independent of the caller.
cd -- "$repo_root/halo2-ecc"
python3 "$script_dir/benchmark-provenance.py" "$repo_root" "$run_dir" "$mode" "$threads" "$repetitions" "$features"

for selected in "${components[@]}"; do
    select_component "$selected"
    component_dir="$run_dir/$selected"
    mkdir -p -- "$component_dir"
    cp -- "$config_source" "$component_dir/config.jsonl"
    if [[ "$selected" == certificate ]]; then
        python3 "$script_dir/benchmark-certificate.py" --root "$repo_root" \
            --destination "$component_dir" --repetitions "$repetitions" \
            --threads "$threads" --allocator "$allocator" -- "${cargo_args[@]}"
        continue
    fi
    python3 - "$component_dir/config.jsonl" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
lines = path.read_text().splitlines()
if not lines:
    raise SystemExit("Empty benchmark config")
for number, line in enumerate(lines, 1):
    item = json.loads(line)
    if not isinstance(item, dict) or not all(key in item for key in ("degree", "lookup_bits")):
        raise SystemExit(f"Invalid config row {number}")
    if not (0 < item["lookup_bits"] < item["degree"]):
        raise SystemExit(f"Invalid lookup_bits/degree in row {number}")
PY
    # An incorrect Rust test filter otherwise silently succeeds with zero tests.
    cargo "${cargo_args[@]}" "$test_name" -- --exact --list > "$component_dir/discovery.log" 2>&1 || {
        cat "$component_dir/discovery.log" >&2; die "build/test discovery failed for $selected";
    }
    grep -Fqx "$test_name: test" "$component_dir/discovery.log" || die "exact benchmark test missing: $test_name"
    repetition=1
    while [[ $repetition -le $repetitions ]]; do
        job_dir="$component_dir/$(printf 'repeat-%03d' "$repetition")"
        mkdir -p -- "$job_dir"
        export HALO2_BENCH_CONFIG="$component_dir/config.jsonl"
        export HALO2_BENCH_OUTPUT="$job_dir/measurements.csv"
        {
            printf 'component=%s\nmode=%s\nrepetition=%s\nthreads=%s\nallocator=%s\n' "$selected" "$mode" "$repetition" "$threads" "$allocator"
            printf 'config=%s\noutput=%s\n' "$HALO2_BENCH_CONFIG" "$HALO2_BENCH_OUTPUT"
            printf 'command='; printf '%q ' cargo "${cargo_args[@]}" "$test_name" -- --ignored --exact --nocapture --test-threads=1; printf '\n'
            printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        } > "$job_dir/metadata.txt"
        printf 'running\n' > "$job_dir/status"
        printf '\nRunning %s (%s/%s)\n' "$selected" "$repetition" "$repetitions"
        if cargo "${cargo_args[@]}" "$test_name" -- --ignored --exact --nocapture --test-threads=1 2>&1 | tee "$job_dir/stdout.log"; then
            grep -Fq 'test result: ok. 1 passed; 0 failed;' "$job_dir/stdout.log" || die "expected exactly one passing test"
            [[ -s "$HALO2_BENCH_OUTPUT" ]] || die "benchmark did not write its isolated CSV"
            python3 - "$HALO2_BENCH_CONFIG" "$HALO2_BENCH_OUTPUT" <<'PY'
import csv, pathlib, sys
expected = len(pathlib.Path(sys.argv[1]).read_text().splitlines())
with open(sys.argv[2], newline="") as stream:
    rows = list(csv.reader(stream))
if len(rows) != expected + 1 or any(len(row) != len(rows[0]) for row in rows[1:]):
    raise SystemExit("CSV row count/shape does not match config; run is incomplete")
PY
            printf 'completed\n' > "$job_dir/status"
        else
            printf 'failed\n' > "$job_dir/status"
            die "benchmark failed: $selected repetition $repetition"
        fi
        printf 'finished_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$job_dir/metadata.txt"
        repetition=$((repetition + 1))
    done
done
git -C "$repo_root" status --short > "$run_dir/git-status-after.txt"
python3 - "$run_dir" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
hashes = {}
for path in sorted(root.rglob("*")):
    if path.is_file() and path.suffix in {".srs", ".csv", ".jsonl"}:
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        hashes[str(path.relative_to(root))] = hasher.hexdigest()
(root / "artifact-sha256.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n")
PY
printf 'completed\n' > "$run_dir/status"
printf '\nCompleted. Raw artifacts: %s\n' "$run_dir"
