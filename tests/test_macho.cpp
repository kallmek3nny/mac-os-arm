#define main legacy_macho_main
#include "test_macho_legacy.inc"
#undef main

#include "test_macho_initializers.inc"

int main() {
    const int legacy_result = legacy_macho_main();
    const int initializer_result = macho_initializers_main();
    return legacy_result == EXIT_SUCCESS && initializer_result == EXIT_SUCCESS
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
