#define main legacy_dyld_fixup_pauth_main
#include "test_dyld_fixup_pauth_legacy.inc"
#undef main

#include "test_dyld_auth_slots.inc"

int main() {
    const int legacy_result = legacy_dyld_fixup_pauth_main();
    const int slots_result = dyld_auth_slots_main();
    return legacy_result == EXIT_SUCCESS && slots_result == EXIT_SUCCESS
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
