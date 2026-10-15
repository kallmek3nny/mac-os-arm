#pragma once

#include "macosarm/dyld_authenticated_initialization.hpp"
#include "macosarm/dyld_graph_fixups.hpp"
#include "macosarm/dyld_process_startup.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace macosarm::dyld {

struct ImageGraphBootstrapConfig {
    DependencyGraphConfig dependency_graph{};
    LoadedImageGraphFixupsConfig fixups{};
    std::size_t max_initializers{4096};
    std::size_t max_authenticated_slots{kMaxChainedFixups};
    InitializerExecutionConfig execution{};
    std::uint64_t program_vars{};
};

enum class ImageGraphBootstrapError {
    none,
    dependency_graph_failure,
    fixup_failure,
    initializer_planning_failure,
    initializer_execution_failure,
};

struct ImageGraphBootstrapResult {
    ImageGraphBootstrapError error{ImageGraphBootstrapError::none};
    DependencyGraphResult loading;
    LoadedImageGraphFixupsResult fixups;
    AuthenticatedImageInitializationResult initialization;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ImageGraphBootstrapError::none;
    }
};

[[nodiscard]] inline ImageGraphBootstrapResult bootstrap_image_graph(
    const macho::Image& root_image,
    std::span<const std::byte> root_file_bytes,
    const LoadedImage& root_mapping,
    std::string_view root_path,
    std::string_view executable_path,
    GuestAddressSpace& address_space,
    const ImageLookup& lookup,
    const ProcessStartupLayout& startup_layout,
    CpuState& state,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    const ImageGraphBootstrapConfig& config = {}) {
    ImageGraphBootstrapResult result;
    result.loading = load_dependency_graph(
        root_image,
        root_file_bytes,
        root_mapping,
        root_path,
        executable_path,
        address_space,
        lookup,
        config.dependency_graph);
    if (!result.loading) {
        result.error = ImageGraphBootstrapError::dependency_graph_failure;
        return result;
    }

    result.fixups = apply_loaded_image_graph_fixups(
        result.loading.graph,
        address_space,
        config.fixups);
    if (!result.fixups) {
        result.error = ImageGraphBootstrapError::fixup_failure;
        return result;
    }

    AuthenticatedInitializerPlanConfig plan_config;
    plan_config.max_initializers = config.max_initializers;
    plan_config.max_authenticated_slots = config.max_authenticated_slots;
    plan_config.authenticated_slots = result.fixups.authenticated_slots;
    plan_config.pointer_auth = config.fixups.pointer_auth;

    InitializerExecutionConfig execution_config = config.execution;
    execution_config.context = initializer_context_from_process_startup(
        startup_layout,
        config.program_vars);

    result.initialization = initialize_image_graph_with_pointer_auth(
        result.loading.graph,
        state,
        address_space,
        backend,
        host,
        plan_config,
        execution_config);
    if (!result.initialization) {
        result.error = result.initialization.error ==
                AuthenticatedImageInitializationError::planning_failure
            ? ImageGraphBootstrapError::initializer_planning_failure
            : ImageGraphBootstrapError::initializer_execution_failure;
    }
    return result;
}

[[nodiscard]] inline std::string_view image_graph_bootstrap_error_name(
    ImageGraphBootstrapError error) noexcept {
    switch (error) {
    case ImageGraphBootstrapError::none: return "none";
    case ImageGraphBootstrapError::dependency_graph_failure:
        return "dependency_graph_failure";
    case ImageGraphBootstrapError::fixup_failure: return "fixup_failure";
    case ImageGraphBootstrapError::initializer_planning_failure:
        return "initializer_planning_failure";
    case ImageGraphBootstrapError::initializer_execution_failure:
        return "initializer_execution_failure";
    }
    return "unknown";
}

} // namespace macosarm::dyld
