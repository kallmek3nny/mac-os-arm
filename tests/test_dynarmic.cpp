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

#include "test_dynarmic_initializers.inc"
#include "test_dynarmic_authenticated_initializers.inc"
#include "test_dynarmic_pthread_main_thread.inc"
#include "test_dynarmic_munmap.inc"

int main() {
    const int legacy_result = legacy_dynarmic_main();
    const int pauth_result = pauth_dynarmic_main();
    const int initializer_result = dynarmic_initializer_main();
    const int authenticated_initializer_result = dynarmic_authenticated_initializer_main();
    const int pthread_main_thread_result = dynarmic_pthread_main_thread_init_main();
    const int munmap_result = dynarmic_munmap_main();
    return legacy_result == EXIT_SUCCESS &&
                   pauth_result == EXIT_SUCCESS &&
                   initializer_result == EXIT_SUCCESS &&
                   authenticated_initializer_result == EXIT_SUCCESS &&
                   pthread_main_thread_result == EXIT_SUCCESS &&
                   munmap_result == EXIT_SUCCESS
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
