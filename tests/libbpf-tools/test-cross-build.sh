#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# test-cross-build.sh - Verify cross-compilation of BCC libbpf-tools.
#
# Runs on an x86_64 Debian/Ubuntu host with arm64 cross-compilation
# dependencies pre-installed. Builds a representative set of tools
# (dynamic + static) and validates the output binaries.
#
# Usage:
#   bash tests/libbpf-tools/test-cross-build.sh
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBBPF_TOOLS_DIR="$(cd "${SCRIPT_DIR}/../../libbpf-tools" && pwd)"

FAILURES=0
TESTS=0
PASS=0
SKIPS=0

CROSS_DEPS_OK=1

# Representative tools covering different BPF subsystems
TEST_TOOLS="profile execsnoop opensnoop"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${YELLOW}==> $*${NC}"; }
pass()  { echo -e "  ${GREEN}PASS${NC}: $*"; PASS=$((PASS + 1)); TESTS=$((TESTS + 1)); }
fail()  { echo -e "  ${RED}FAIL${NC}: $*"; FAILURES=$((FAILURES + 1)); TESTS=$((TESTS + 1)); }
skip()  { echo -e "  ${CYAN}SKIP${NC}: $*"; SKIPS=$((SKIPS + 1)); TESTS=$((TESTS + 1)); }

check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

check_grep() {
    local desc="$1" string="$2" pattern="$3"
    if echo "$string" | grep -qi "$pattern"; then
        pass "$desc"
    else
        fail "$desc (got: $string)"
    fi
}

cross_build() {
    local label="$1" tools="$2" extra="${3:-}"
    make clean >/dev/null 2>&1 || true
    if make CROSS_COMPILE=aarch64-linux-gnu- $extra -j"$(nproc)" $tools; then
        pass "$label succeeded"
    else
        fail "$label failed"
        return 1
    fi
}

check_arm64_elfs() {
    local tools="$1" tag="${2:-}" link_pattern="${3:-}"
    for tool in $tools; do
        if [[ ! -f "$tool" ]]; then
            fail "$tool${tag:+ $tag} binary not found"
            continue
        fi
        local file_out
        file_out=$(file "$tool" 2>/dev/null || echo "")
        check_grep "$tool${tag:+ $tag} is ELF"         "$file_out" "ELF"
        check_grep "$tool${tag:+ $tag} is ARM aarch64" "$file_out" "ARM aarch64"
        if [[ -n "$link_pattern" ]]; then
            check_grep "$tool${tag:+ $tag} is $link_pattern" "$file_out" "$link_pattern"
        fi
    done
}

# --- Test functions ---

test_prerequisites() {
    info "Test: Prerequisites"

    check "clang is installed" command -v clang
    check "llvm-strip is installed" command -v llvm-strip
    check "make is installed" command -v make

    local sysroot="/usr/lib/aarch64-linux-gnu"
    local missing=0

    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        pass "aarch64-linux-gnu-gcc is installed"
    else
        skip "aarch64-linux-gnu-gcc not installed"
        missing=1
    fi
    if [[ -f "${sysroot}/libelf.so" ]] || [[ -f "${sysroot}/libelf.a" ]]; then
        pass "libelf for arm64 exists"
    else
        skip "libelf for arm64 not installed"
        missing=1
    fi
    if [[ -f "${sysroot}/libz.so" ]] || [[ -f "${sysroot}/libz.a" ]]; then
        pass "libz for arm64 exists"
    else
        skip "libz for arm64 not installed"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        CROSS_DEPS_OK=0
        info "  Cross toolchain missing; build tests will be skipped"
        info "  See docs/cross_compile_libbpf_tools.md for install instructions"
    fi
}

test_dynamic_build() {
    local tools="$1"
    info "Test: Dynamic linking build (${tools})"
    if [[ $CROSS_DEPS_OK -eq 0 ]]; then
        skip "Dynamic build (cross toolchain not available)"
        return
    fi
    cd "$LIBBPF_TOOLS_DIR"
    if cross_build "Dynamic build" "$tools"; then
        check_arm64_elfs "$tools" "" "dynamically linked"
    fi
}

test_static_build() {
    local tools="$1"
    info "Test: Static linking build (${tools})"
    if [[ $CROSS_DEPS_OK -eq 0 ]]; then
        skip "Static build (cross toolchain not available)"
        return
    fi
    cd "$LIBBPF_TOOLS_DIR"

    if [[ ! -f /usr/lib/aarch64-linux-gnu/libzstd.a ]] && \
       ! dpkg -s libzstd-dev:arm64 >/dev/null 2>&1; then
        skip "Static build (libzstd-dev:arm64 not installed)"
        return
    fi

    if cross_build "Static build" "$tools" "EXTRA_LDFLAGS+=-static"; then
        check_arm64_elfs "$tools" "(static)" "statically linked"
    fi
}

test_clean_rebuild() {
    local tools="$1"
    info "Test: Clean rebuild via make"
    if [[ $CROSS_DEPS_OK -eq 0 ]]; then
        skip "Clean rebuild (cross toolchain not available)"
        return
    fi
    cd "$LIBBPF_TOOLS_DIR"
    if cross_build "Clean rebuild" "$tools"; then
        check_arm64_elfs "$tools" "(rebuild)"
    fi
}

# --- Main ---

main() {
    echo ""
    echo "========================================"
    echo " BCC libbpf-tools Cross-Compile Tests"
    echo " Host: $(uname -m) $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo " Target: arm64 (aarch64)"
    echo "========================================"
    echo ""

    test_prerequisites
    test_dynamic_build "$TEST_TOOLS"
    test_static_build "$TEST_TOOLS"
    test_clean_rebuild "$TEST_TOOLS"

    # Cleanup
    cd "$LIBBPF_TOOLS_DIR"
    make clean >/dev/null 2>&1 || true

    echo ""
    echo "========================================"
    echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAILURES} failed${NC}, ${CYAN}${SKIPS} skipped${NC}, ${TESTS} total"
    echo "========================================"

    if [[ $FAILURES -gt 0 ]]; then
        exit 1
    fi
}

main "$@"
