#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace macosarm::dyld {

// The stack is ordered exactly as dyld searches it: the current loader first,
// then each previous dependency-chain image moving outward toward the main executable.
struct RunPathEntry {
    std::string path;
    std::string owner_image_path;
};

struct PathResolutionContext {
    std::string executable_path;
    std::string loader_path;
    std::vector<RunPathEntry> run_path_stack;
};

enum class PathResolutionError {
    none,
    empty_load_path,
    bad_executable_path,
    bad_loader_path,
    no_runpaths,
    unusable_runpaths,
    malformed_token,
    unsupported_token,
    relative_path_unsupported,
};

struct PathResolutionResult {
    std::vector<std::string> candidates;
    PathResolutionError error{PathResolutionError::none};
    std::size_t ignored_runpaths{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == PathResolutionError::none;
    }
};

[[nodiscard]] PathResolutionResult resolve_load_path(
    std::string_view load_path,
    const PathResolutionContext& context);

[[nodiscard]] std::string_view path_resolution_error_name(PathResolutionError error) noexcept;

} // namespace macosarm::dyld
