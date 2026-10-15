#pragma once

#include "macosarm/dyld_paths.hpp"
#include "macosarm/macho.hpp"

#include <cstddef>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace macosarm::dyld {

struct DependencyPlanContext {
    std::string executable_path;
    std::string image_path;
    std::vector<RunPathEntry> inherited_run_path_stack;
};

struct PlannedDependency {
    macho::DylibDependency dependency;
    std::vector<std::string> candidates;
    std::size_t ignored_runpaths{};
};

enum class DependencyPlanError {
    none,
    bad_executable_path,
    bad_image_path,
    path_resolution_failure,
};

struct DependencyPlanResult {
    static constexpr std::size_t kNoDependency = std::numeric_limits<std::size_t>::max();

    std::vector<RunPathEntry> run_path_stack;
    std::vector<PlannedDependency> dependencies;
    DependencyPlanError error{DependencyPlanError::none};
    std::size_t failed_dependency_index{kNoDependency};
    PathResolutionError path_error{PathResolutionError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == DependencyPlanError::none;
    }
};

[[nodiscard]] DependencyPlanResult plan_dependencies(
    const macho::Image& image,
    const DependencyPlanContext& context);

[[nodiscard]] std::string_view dependency_plan_error_name(DependencyPlanError error) noexcept;

} // namespace macosarm::dyld
