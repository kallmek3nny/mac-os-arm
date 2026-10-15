#pragma once

#include "macosarm/dyld_initializer_execution.hpp"

#include <string_view>
#include <utility>

namespace macosarm::dyld {

enum class ImageInitializationError {
    none,
    planning_failure,
    execution_failure,
};

struct ImageInitializationResult {
    ImageInitializationError error{ImageInitializationError::none};
    InitializerPlanResult planning;
    InitializerExecutionResult execution;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ImageInitializationError::none;
    }
};

// High-level image-initialization stage for an already loaded/fixed-up graph.
// Planning is completed and validated before any guest initializer executes.
// Execution then commits the per-image ledger only after every initializer for
// that image returns successfully. Guest memory/host side effects performed by
// an initializer are intentionally not advertised as transactionally reversible.
[[nodiscard]] inline ImageInitializationResult initialize_image_graph(
    const LoadedImageGraph& graph,
    CpuState& state,
    GuestAddressSpace& address_space,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    const InitializerPlanConfig& plan_config = {},
    const InitializerExecutionConfig& execution_config = {}) {
    ImageInitializationResult result;
    result.planning = plan_initializers(graph, address_space, plan_config);
    if (!result.planning) {
        result.error = ImageInitializationError::planning_failure;
        return result;
    }

    result.execution = execute_initializers(
        graph,
        result.planning.plan,
        state,
        address_space,
        backend,
        host,
        execution_config);
    if (!result.execution) {
        result.error = ImageInitializationError::execution_failure;
    }
    return result;
}

[[nodiscard]] inline std::string_view image_initialization_error_name(
    ImageInitializationError error) noexcept {
    switch (error) {
    case ImageInitializationError::none: return "none";
    case ImageInitializationError::planning_failure: return "planning_failure";
    case ImageInitializationError::execution_failure: return "execution_failure";
    }
    return "unknown";
}

} // namespace macosarm::dyld
