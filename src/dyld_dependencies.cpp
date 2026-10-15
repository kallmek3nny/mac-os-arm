#include "macosarm/dyld_dependencies.hpp"

#include <utility>

namespace macosarm::dyld {
namespace {

[[nodiscard]] bool is_absolute_file_path(std::string_view path) noexcept {
    return path.size() > 1 && path.front() == '/' && path.back() != '/';
}

} // namespace

DependencyPlanResult plan_dependencies(
    const macho::Image& image,
    const DependencyPlanContext& context) {

    DependencyPlanResult result;
    if (!is_absolute_file_path(context.executable_path)) {
        result.error = DependencyPlanError::bad_executable_path;
        return result;
    }
    if (!is_absolute_file_path(context.image_path)) {
        result.error = DependencyPlanError::bad_image_path;
        return result;
    }

    result.run_path_stack.reserve(
        image.runpaths.size() + context.inherited_run_path_stack.size());
    for (const std::string& runpath : image.runpaths) {
        result.run_path_stack.push_back(RunPathEntry{runpath, context.image_path});
    }
    result.run_path_stack.insert(
        result.run_path_stack.end(),
        context.inherited_run_path_stack.begin(),
        context.inherited_run_path_stack.end());

    PathResolutionContext path_context;
    path_context.executable_path = context.executable_path;
    path_context.loader_path = context.image_path;
    path_context.run_path_stack = result.run_path_stack;

    result.dependencies.reserve(image.dependencies.size());
    for (std::size_t index = 0; index < image.dependencies.size(); ++index) {
        const macho::DylibDependency& dependency = image.dependencies[index];
        PathResolutionResult resolved = resolve_load_path(dependency.path, path_context);
        if (!resolved) {
            result.error = DependencyPlanError::path_resolution_failure;
            result.failed_dependency_index = index;
            result.path_error = resolved.error;
            return result;
        }

        PlannedDependency planned;
        planned.dependency = dependency;
        planned.candidates = std::move(resolved.candidates);
        planned.ignored_runpaths = resolved.ignored_runpaths;
        result.dependencies.push_back(std::move(planned));
    }

    return result;
}

std::string_view dependency_plan_error_name(DependencyPlanError error) noexcept {
    switch (error) {
    case DependencyPlanError::none: return "none";
    case DependencyPlanError::bad_executable_path: return "bad_executable_path";
    case DependencyPlanError::bad_image_path: return "bad_image_path";
    case DependencyPlanError::path_resolution_failure: return "path_resolution_failure";
    }
    return "unknown";
}

} // namespace macosarm::dyld
