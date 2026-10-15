#define main legacy_dyld_graph_main
#include "test_dyld_graph_legacy.inc"
#undef main

#include "test_dyld_graph_initializers.inc"

int main() {
    const int legacy_result = legacy_dyld_graph_main();
    const int initializer_result = dyld_graph_initializers_main();
    return legacy_result == EXIT_SUCCESS && initializer_result == EXIT_SUCCESS
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
