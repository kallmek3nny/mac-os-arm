#pragma once

#include "macosarm/dyld_dependencies.hpp"
#include "macosarm/dyld_exports.hpp"
#include "macosarm/image_loader.hpp"

#include <cstddef>
#include <functional>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace macosarm::dyld {

enum class ImageLookupStatus {
    found,
    not_found,
    failure,
};

struct ImageLookupResult {
    ImageLookupStatus status{ImageLookupStatus::not_found};
    std::vector<std::byte> bytes;
};

using ImageLookup = std::function<ImageLookupResult(std::string_view path)>;

enum class GraphDependencyState {
    loaded,
    missing_weak,
    deferred_lazy,
};

struct GraphDependency {
    static constexpr std::size_t kNoImage = std::numeric_limits<std::size_t>::max();

    macho::DylibDependency dependency;
    GraphDependencyState state{GraphDependencyState::loaded};
    std::string resolved_path;
    std::size_t image_index{kNoImage};
};

struct GraphImage {
    std::string path;
    macho::Image image;
    LoadedImage mapping;
    std::vector<ExportSymbol> exports;
    std::vector<GraphDependency> dependencies;
    bool owns_mapping{};
};

struct LoadedImageGraph {
    std::vector<GraphImage> images;
};

struct DependencyGraphConfig {
    // Includes the root image at index zero.
    std::size_t max_images{256};
    // Maximum number of newly loaded dependency edges from the root.
    std::size_t max_depth{128};
};

enum class DependencyGraphError {
    none,
    image_limit,
    depth_limit,
    dependency_plan_failure,
    lookup_failure,
    dependency_not_found,
    parse_failure,
    exports_failure,
    load_failure,
};

struct DependencyGraphResult {
    static constexpr std::size_t kNoImage = std::numeric_limits<std::size_t>::max();
    static constexpr std::size_t kNoDependency = std::numeric_limits<std::size_t>::max();

    LoadedImageGraph graph;
    DependencyGraphError error{DependencyGraphError::none};
    std::size_t failed_image_index{kNoImage};
    std::size_t failed_dependency_index{kNoDependency};
    DependencyPlanError plan_error{DependencyPlanError::none};
    PathResolutionError path_error{PathResolutionError::none};
    macho::ErrorCode parse_error{macho::ErrorCode::none};
    ExportTrieError exports_error{ExportTrieError::none};
    LoadError load_error{LoadError::none};
    VmError vm_error{VmError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == DependencyGraphError::none;
    }
};

// Builds the dependency graph for an already parsed/root-mapped image. The root
// is recorded at index zero but is never mapped or unmapped by this function.
// Every dependency image newly accepted by the lookup callback is parsed,
// export-decoded, and mapped into the same guest address space. A failure rolls
// back every mapping created by this graph build while preserving all
// pre-existing mappings owned by the caller.
[[nodiscard]] DependencyGraphResult load_dependency_graph(
    const macho::Image& root_image,
    std::span<const std::byte> root_file_bytes,
    const LoadedImage& root_mapping,
    std::string_view root_path,
    std::string_view executable_path,
    GuestAddressSpace& address_space,
    const ImageLookup& lookup,
    const DependencyGraphConfig& config = {});

[[nodiscard]] std::string_view graph_dependency_state_name(GraphDependencyState state) noexcept;
[[nodiscard]] std::string_view dependency_graph_error_name(DependencyGraphError error) noexcept;

} // namespace macosarm::dyld
