#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

TARGETS="fuzz_pem"

# 1) The library, sanitized and with DWARF 3, as a static archive. The SIMD/assembly variants are
#    switched off so the build does not depend on the host CPU. DEBUG=0 silences error_print()'s
#    per-rejection stderr output (otherwise every rejected input prints to stderr). Only UBSan's shift-base
#    check is relaxed: GETU32-style `byte << 24` shifts into the sign bit on every SM4 key schedule and
#    ASN.1 length parse, so it fires on nearly any input and masks everything else.
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_C_COMPILER="$CC" \
	-DBUILD_SHARED_LIBS=OFF \
	-DENABLE_SM2_AMD64=OFF -DENABLE_SM3_SSE=OFF -DENABLE_SM4_AVX2=OFF -DENABLE_SM4_AESNI=OFF \
	-DCMAKE_C_FLAGS="-O1 -DDEBUG=0 $SANITIZER_FLAGS -fno-sanitize=shift-base -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake --build build-fuzz -j"$MAYHEM_JOBS" --target gmssl
LIB="$SRC/build-fuzz/bin/libgmssl.a"
# Harnesses must see the same ENABLE_* macros as the library: they change the size of X509_KEY & co.
LIB_DEFS="$(sed -n 's/^C_DEFINES = //p' build-fuzz/CMakeFiles/gmssl.dir/flags.make)"

# 2) Each harness twice: against libFuzzer and against the run-once standalone driver. lsan_off.cc turns
#    LeakSanitizer off at build time in both.
HFLAGS="-O1 -DDEBUG=0 $LIB_DEFS $SANITIZER_FLAGS $DEBUG_FLAGS -I$SRC/include -I$SRC/mayhem"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build-fuzz/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build-fuzz/standalone_main.o
for t in $TARGETS; do
	$CC $HFLAGS $LIB_FUZZING_ENGINE "mayhem/$t.c" build-fuzz/lsan_off.o "$LIB" -lpthread -ldl -lm \
		-o "/mayhem/$t"
	$CC $HFLAGS "mayhem/$t.c" build-fuzz/standalone_main.o build-fuzz/lsan_off.o "$LIB" -lpthread -ldl -lm \
		-o "/mayhem/$t-standalone"
done

# 3) The project's own unit tests and CLI, built with normal flags in a separate tree.
env -u CFLAGS -u CXXFLAGS -u LDFLAGS \
	cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
		-DCMAKE_C_FLAGS="$COVERAGE_FLAGS"
env -u CFLAGS -u CXXFLAGS -u LDFLAGS \
	cmake --build build-tests -j"$MAYHEM_JOBS"
