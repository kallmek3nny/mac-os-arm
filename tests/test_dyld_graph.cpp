#define main legacy_dyld_graph_main
#include "test_dyld_graph_legacy.inc"
#undef main

#include "test_dyld_graph_initializers.inc"
#include "test_dyld_initializer_plan.inc"

int main() {
    const int legacy_result = legacy_dyld_graph_main();
    const int metadata_result = dyld_graph_initializers_main();
    const int plan_result = dyld_initializer_plan_main();
    return legacy_result == EXIT_SUCCESS &&
                   metadata_result == EXIT_SUCCESS &&
                   plan_result == EXIT_SUCCESS
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
