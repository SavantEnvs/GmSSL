#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Run every unit-test binary built by build.sh (each carries upstream's known-answer assertions and
# returns non-zero on a mismatch) from a scratch directory, plus two known-answer probes of the CLI.
# A binary must exit 0 AND print something: a program neutered to exit(0) prints nothing and fails.
BIN="$SRC/build-tests/bin"
[ -x "$BIN/gmssl" ] || { echo "missing $BIN/gmssl: mayhem/build.sh did not build the tests" >&2; emit_ctrf gmssl-unit-tests 0 1; exit 1; }

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
export TMPDIR="$SCRATCH"

run_one() {
  local exe="$1" name dir
  name="$(basename "$exe")"
  dir="$SCRATCH/$name.d"
  mkdir -p "$dir"
  if (cd "$dir" && timeout 600 "$exe" > "$dir/stdout" 2> "$dir/stderr" < /dev/null); then
    # block_ciphertest and hextest assert silently; a pass with no output proves nothing, so it is skipped.
    if [ -s "$dir/stdout" ]; then echo "PASS $name"; else echo "SKIP $name"; fi
  else
    echo "FAIL $name"
    tail -n 20 "$dir/stdout" "$dir/stderr" 2>/dev/null | sed "s/^/    [$name] /"
  fi
}
export -f run_one
export SCRATCH

shopt -s nullglob
tests=("$BIN"/*test)
[ "${#tests[@]}" -gt 0 ] || { echo "no *test binaries in $BIN" >&2; emit_ctrf gmssl-unit-tests 0 1; exit 1; }
results="$(printf '%s\n' "${tests[@]}" | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'run_one "$1"' _ {})"
echo "$results"
passed=$(printf '%s\n' "$results" | grep -c '^PASS ' || true)
failed=$(printf '%s\n' "$results" | grep -c '^FAIL ' || true)
skipped=$(printf '%s\n' "$results" | grep -c '^SKIP ' || true)
# Upstream ships 45+ self-checking test programs at this older commit (60+ on master); far fewer passing means the build was gutted.
if [ "$passed" -lt 40 ]; then
  echo "FAIL only $passed unit tests passed with output, expected at least 40"
  failed=$((failed + 1))
fi

kat() {
  local desc="$1" want="$2" got="$3"
  if [ "$got" = "$want" ]; then passed=$((passed + 1)); echo "PASS kat: $desc"
  else failed=$((failed + 1)); echo "FAIL kat: $desc: got '$got', want '$want'"; fi
}
kat "sm3(abc)" 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0 \
  "$(printf abc | "$BIN/gmssl" sm3 2>/dev/null | tr -d '[:space:]')"
kat "sm3(empty)" 1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b \
  "$(printf '' | "$BIN/gmssl" sm3 2>/dev/null | tr -d '[:space:]')"

emit_ctrf gmssl-unit-tests "$passed" "$failed" "$skipped"
