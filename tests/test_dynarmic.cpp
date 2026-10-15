#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/process.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <vector>

// Keep the pre-PAUTH Dynarmic regression suite byte-for-byte intact while
// running the Phase 22 PAUTH coverage through the same CTest target. Renaming
// the local test harness symbols lets both standalone suites share one
// translation unit without weakening or duplicating the existing CMake gate.
#define failures legacy_failures
#define expect legacy_expect
#define put_instruction legacy_put_instruction
#define main legacy_dynarmic_main
#include "test_dynarmic_legacy.inc"
#undef main
#undef put_instruction
#undef expect
#undef failures

#define failures pauth_failures
#define expect pauth_expect
#define put_instruction pauth_put_instruction
#define test_keys pauth_test_keys
#define main pauth_dynarmic_main
#include "test_dynarmic_pauth.inc"
#undef main
#undef test_keys
#undef put_instruction
#undef expect
#undef failures

int main() {
    const int legacy_result = legacy_dynarmic_main();
    const int pauth_result = pauth_dynarmic_main();
    return legacy_result == EXIT_SUCCESS && pauth_result == EXIT_SUCCESS
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
