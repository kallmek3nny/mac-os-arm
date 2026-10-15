#include "macosarm/dyld_graph.hpp"

#include <unordered_map>
#include <utility>

namespace macosarm::dyld {
namespace {

class GraphLoader {
public:
    GraphLoader(
        const macho::Image& root_image,
        std::span<const std::byte> root_file_bytes,
        const LoadedImage& root_mapping,
        std::string_view root_path,
        std::string_view executable_path,
        GuestAddressSpace& address_space,
        const ImageLookup& lookup,
        const DependencyGraphConfig& config)
        : root_image_(root_image),
          root_file_bytes_(root_file_bytes),
          root_mapping_(root_mapping),
          root_path_(root_path),
          executable_path_(executable_path),
          address_space_(address_space),
          lookup_(lookup),
          config_(config) {}

    [[nodiscard]] DependencyGraphResult run() {
        if (config_.max_images == 0) {
            result_.error = DependencyGraphError::image_limit;
            result_.failed_image_index = 0;
            return std::move(result_);
        }

        macho::InitializerMetadata root_initializer_metadata;
        if (!root_file_bytes_.empty()) {
            macho::InitializerMetadataResult root_initializers =
                macho::parse_initializer_metadata(root_file_bytes_);
            if (!root_initializers) {
                result_.error = DependencyGraphError::initializer_metadata_failure;
                result_.failed_image_index = 0;
                result_.initializer_error = root_initializers.error;
                return std::move(result_);
            }
            root_initializer_metadata = std::move(root_initializers.metadata);
        }

        ExportTrieResult root_exports = parse_image_exports(root_image_, root_file_bytes_);
        if (!root_exports) {
            result_.error = DependencyGraphError::exports_failure;
            result_.failed_image_index = 0;
            result_.exports_error = root_exports.error;
            return std::move(result_);
        }

        GraphImage root;
        root.path = std::string(root_path_);
        root.image = root_image_;
        root.initializers = std::move(root_initializer_metadata);
        root.mapping = root_mapping_;
        root.exports = std::move(root_exports.symbols);
        root.owns_mapping = false;
        result_.graph.images.push_back(std::move(root));
        path_to_index_.emplace(result_.graph.images.front().path, 0);

        const std::vector<RunPathEntry> no_inherited_runpaths;
        if (!load_dependencies(0, no_inherited_runpaths, 0)) {
            rollback();
        }
        return std::move(result_);
    }

private:
    [[nodiscard]] bool fail(
        DependencyGraphError error,
        std::size_t image_index,
        std::size_t dependency_index = DependencyGraphResult::kNoDependency) {
        result_.error = error;
        result_.failed_image_index = image_index;
        result_.failed_dependency_index = dependency_index;
        return false;
    }

    void rollback() noexcept {
        for (std::size_t image_cursor = result_.graph.images.size(); image_cursor > 1; --image_cursor) {
            const GraphImage& graph_image = result_.graph.images[image_cursor - 1];
            if (!graph_image.owns_mapping) {
                continue;
            }
            for (auto segment = graph_image.image.segments.rbegin();
                 segment != graph_image.image.segments.rend(); ++segment) {
                if (segment->vm_size != 0) {
                    (void)address_space_.unmap(segment->vm_address, segment->vm_size);
                }
            }
        }
        result_.graph.images.clear();
        path_to_index_.clear();
    }

    [[nodiscard]] bool load_dependencies(
        std::size_t image_index,
        const std::vector<RunPathEntry>& inherited_runpaths,
        std::size_t depth) {

        DependencyPlanContext context;
        context.executable_path = std::string(executable_path_);
        context.image_path = result_.graph.images[image_index].path;
        context.inherited_run_path_stack = inherited_runpaths;

        DependencyPlanResult plan = plan_dependencies(result_.graph.images[image_index].image, context);
        if (!plan) {
            result_.plan_error = plan.error;
            result_.path_error = plan.path_error;
            result_.failed_dependency_index = plan.failed_dependency_index;
            return fail(
                DependencyGraphError::dependency_plan_failure,
                image_index,
                plan.failed_dependency_index);
        }

        result_.graph.images[image_index].dependencies.reserve(plan.dependencies.size());
        for (std::size_t dependency_index = 0;
             dependency_index < plan.dependencies.size(); ++dependency_index) {
            const PlannedDependency& planned = plan.dependencies[dependency_index];

            GraphDependency edge;
            edge.dependency = planned.dependency;

            if (planned.dependency.kind == macho::DylibLoadKind::lazy) {
                edge.state = GraphDependencyState::deferred_lazy;
                result_.graph.images[image_index].dependencies.push_back(std::move(edge));
                continue;
            }

            bool located = false;
            bool already_loaded = false;
            std::size_t target_index = GraphDependency::kNoImage;
            std::string resolved_path;
            std::vector<std::byte> candidate_bytes;

            for (const std::string& candidate : planned.candidates) {
                const auto existing = path_to_index_.find(candidate);
                if (existing != path_to_index_.end()) {
                    located = true;
                    already_loaded = true;
                    target_index = existing->second;
                    resolved_path = candidate;
                    break;
                }

                if (!lookup_) {
                    return fail(DependencyGraphError::lookup_failure, image_index, dependency_index);
                }
                ImageLookupResult lookup_result = lookup_(candidate);
                switch (lookup_result.status) {
                case ImageLookupStatus::found:
                    located = true;
                    resolved_path = candidate;
                    candidate_bytes = std::move(lookup_result.bytes);
                    break;
                case ImageLookupStatus::not_found:
                    break;
                case ImageLookupStatus::failure:
                    return fail(DependencyGraphError::lookup_failure, image_index, dependency_index);
                }
                if (located) {
                    break;
                }
            }

            if (!located) {
                if (planned.dependency.kind == macho::DylibLoadKind::weak) {
                    edge.state = GraphDependencyState::missing_weak;
                    result_.graph.images[image_index].dependencies.push_back(std::move(edge));
                    continue;
                }
                return fail(DependencyGraphError::dependency_not_found, image_index, dependency_index);
            }

            if (already_loaded) {
                edge.state = GraphDependencyState::loaded;
                edge.resolved_path = std::move(resolved_path);
                edge.image_index = target_index;
                result_.graph.images[image_index].dependencies.push_back(std::move(edge));
                continue;
            }

            if (depth >= config_.max_depth) {
                return fail(DependencyGraphError::depth_limit, image_index, dependency_index);
            }
            if (result_.graph.images.size() >= config_.max_images) {
                return fail(DependencyGraphError::image_limit, image_index, dependency_index);
            }

            macho::ParseResult parsed = macho::parse(candidate_bytes);
            if (!parsed) {
                result_.parse_error = parsed.error;
                return fail(DependencyGraphError::parse_failure, image_index, dependency_index);
            }

            macho::InitializerMetadataResult initializers =
                macho::parse_initializer_metadata(candidate_bytes);
            if (!initializers) {
                result_.initializer_error = initializers.error;
                return fail(
                    DependencyGraphError::initializer_metadata_failure,
                    image_index,
                    dependency_index);
            }

            ExportTrieResult exports = parse_image_exports(parsed.image, candidate_bytes);
            if (!exports) {
                result_.exports_error = exports.error;
                return fail(DependencyGraphError::exports_failure, image_index, dependency_index);
            }

            LoadResult loaded = load_shared_image(parsed.image, candidate_bytes, address_space_);
            if (!loaded) {
                result_.load_error = loaded.error;
                result_.vm_error = loaded.vm_error;
                return fail(DependencyGraphError::load_failure, image_index, dependency_index);
            }

            GraphImage child;
            child.path = resolved_path;
            child.image = std::move(parsed.image);
            child.initializers = std::move(initializers.metadata);
            child.mapping = loaded.image;
            child.exports = std::move(exports.symbols);
            child.owns_mapping = true;

            target_index = result_.graph.images.size();
            result_.graph.images.push_back(std::move(child));
            path_to_index_.emplace(result_.graph.images[target_index].path, target_index);

            edge.state = GraphDependencyState::loaded;
            edge.resolved_path = resolved_path;
            edge.image_index = target_index;
            result_.graph.images[image_index].dependencies.push_back(std::move(edge));

            if (!load_dependencies(target_index, plan.run_path_stack, depth + 1)) {
                return false;
            }
        }

        return true;
    }

    const macho::Image& root_image_;
    std::span<const std::byte> root_file_bytes_;
    const LoadedImage& root_mapping_;
    std::string_view root_path_;
    std::string_view executable_path_;
    GuestAddressSpace& address_space_;
    const ImageLookup& lookup_;
    const DependencyGraphConfig& config_;
    DependencyGraphResult result_;
    std::unordered_map<std::string, std::size_t> path_to_index_;
};

} // namespace

DependencyGraphResult load_dependency_graph(
    const macho::Image& root_image,
    std::span<const std::byte> root_file_bytes,
    const LoadedImage& root_mapping,
    std::string_view root_path,
    std::string_view executable_path,
    GuestAddressSpace& address_space,
    const ImageLookup& lookup,
    const DependencyGraphConfig& config) {
    return GraphLoader(
        root_image,
        root_file_bytes,
        root_mapping,
        root_path,
        executable_path,
        address_space,
        lookup,
        config).run();
}

std::string_view graph_dependency_state_name(GraphDependencyState state) noexcept {
    switch (state) {
    case GraphDependencyState::loaded: return "loaded";
    case GraphDependencyState::missing_weak: return "missing_weak";
    case GraphDependencyState::deferred_lazy: return "deferred_lazy";
    }
    return "unknown";
}

std::string_view dependency_graph_error_name(DependencyGraphError error) noexcept {
    switch (error) {
    case DependencyGraphError::none: return "none";
    case DependencyGraphError::image_limit: return "image_limit";
    case DependencyGraphError::depth_limit: return "depth_limit";
    case DependencyGraphError::dependency_plan_failure: return "dependency_plan_failure";
    case DependencyGraphError::lookup_failure: return "lookup_failure";
    case DependencyGraphError::dependency_not_found: return "dependency_not_found";
    case DependencyGraphError::parse_failure: return "parse_failure";
    case DependencyGraphError::initializer_metadata_failure: return "initializer_metadata_failure";
    case DependencyGraphError::exports_failure: return "exports_failure";
    case DependencyGraphError::load_failure: return "load_failure";
    }
    return "unknown";
}

} // namespace macosarm::dyld
