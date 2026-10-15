#define main legacy_dyld_graph_main
#include "test_dyld_graph_legacy.inc"
#undef main

#include "test_dyld_graph_initializers.inc"
#include "test_dyld_graph_fixup_payload.inc"
#include "test_dyld_graph_fixups.inc"
#include "test_dyld_graph_fixups_edgecases.inc"
#include "test_dyld_initializer_plan.inc"
#include "test_dyld_initializer_execution.inc"
#include "test_dyld_image_initialization.inc"
#include "test_dyld_authenticated_initialization.inc"
#include "test_process_startup_initializer_context.inc"

int main() {
    const int legacy_result = legacy_dyld_graph_main();
    const int metadata_result = dyld_graph_initializers_main();
    const int fixup_payload_result = dyld_graph_fixup_payload_main();
    const int graph_fixups_result = dyld_graph_fixups_main();
    const int graph_fixups_edgecases_result = dyld_graph_fixups_edgecases_main();
    const int plan_result = dyld_initializer_plan_main();
    const int execution_result = dyld_initializer_execution_main();
    const int integration_result = dyld_image_initialization_main();
    const int authenticated_result = dyld_authenticated_initialization_main();
    const int startup_context_result = process_startup_initializer_context_main();
    return legacy_result == EXIT_SUCCESS &&
                   metadata_result == EXIT_SUCCESS &&
                   fixup_payload_result == EXIT_SUCCESS &&
                   graph_fixups_result == EXIT_SUCCESS &&
                   graph_fixups_edgecases_result == EXIT_SUCCESS &&
                   plan_result == EXIT_SUCCESS &&
                   execution_result == EXIT_SUCCESS &&
                   integration_result == EXIT_SUCCESS &&
                   authenticated_result == EXIT_SUCCESS &&
                   startup_context_result == EXIT_SUCCESS
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
