#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/dyld_graph.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace macosarm::dyld {

enum class InitializerKind {
    routines64,
    mod_init_func,
};

struct PlannedInitializer {
    std::size_t image_index{};
    InitializerKind kind{InitializerKind::mod_init_func};
    std::uint64_t address{};
    std::size_t section_index{};
    std::size_t entry_index{};
};

struct InitializerPlan {
    // Images are listed once, in the order they become initialized. Images with
    // no callable initializer are still present so a later executor can commit
    // initialization state deterministically.
    std::vector<std::size_t> image_order;
    std::vector<PlannedInitializer> calls;
};

struct InitializerPlanConfig {
    std::size_t max_initializers{4096};
};

enum class InitializerPlanError {
    none,
    empty_graph,
    invalid_dependency_index,
    initializer_limit,
    pointer_read_failure,
    null_initializer,
    target_not_executable,
};

struct InitializerPlanResult {
    static constexpr std::size_t kNoImage = std::numeric_limits<std::size_t>::max();
    static constexpr std::size_t kNoSection = std::numeric_limits<std::size_t>::max();
    static constexpr std::size_t kNoEntry = std::numeric_limits<std::size_t>::max();

    InitializerPlan plan;
    InitializerPlanError error{InitializerPlanError::none};
    std::size_t failed_image_index{kNoImage};
    std::size_t failed_section_index{kNoSection};
    std::size_t failed_entry_index{kNoEntry};
    VmError vm_error{VmError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == InitializerPlanError::none;
    }
};

namespace initializer_plan_detail {

class Builder {
public:
    Builder(
        const LoadedImageGraph& graph,
        const GuestAddressSpace& address_space,
        const InitializerPlanConfig& config)
        : graph_(graph), address_space_(address_space), config_(config), states_(graph.images.size()) {}

    [[nodiscard]] InitializerPlanResult run() {
        if (graph_.images.empty()) {
            return fail(InitializerPlanError::empty_graph, InitializerPlanResult::kNoImage);
        }

        if (!visit(0)) {
            return std::move(result_);
        }

        // Upward edges intentionally do not participate in the initial recursive
        // descent. Process the deferred queue afterward, preserving first-seen
        // order while visit() breaks cycles and ignores duplicates.
        for (std::size_t cursor = 0; cursor < deferred_upward_.size(); ++cursor) {
            if (!visit(deferred_upward_[cursor])) {
                return std::move(result_);
            }
        }

        // LoadedImageGraph is normally root-reachable. Keeping this final pass
        // deterministic makes the planner robust for manually assembled graphs
        // used by embedders and tests without silently dropping a node.
        for (std::size_t image_index = 0; image_index < graph_.images.size(); ++image_index) {
            if (!visit(image_index)) {
                return std::move(result_);
            }
        }

        return std::move(result_);
    }

private:
    enum class VisitState : std::uint8_t {
        unvisited,
        visiting,
        done,
    };

    [[nodiscard]] InitializerPlanResult fail(
        InitializerPlanError error,
        std::size_t image_index,
        std::size_t section_index = InitializerPlanResult::kNoSection,
        std::size_t entry_index = InitializerPlanResult::kNoEntry,
        VmError vm_error = VmError::none) {
        result_.error = error;
        result_.failed_image_index = image_index;
        result_.failed_section_index = section_index;
        result_.failed_entry_index = entry_index;
        result_.vm_error = vm_error;
        result_.plan.image_order.clear();
        result_.plan.calls.clear();
        return std::move(result_);
    }

    [[nodiscard]] bool fail_in_place(
        InitializerPlanError error,
        std::size_t image_index,
        std::size_t section_index = InitializerPlanResult::kNoSection,
        std::size_t entry_index = InitializerPlanResult::kNoEntry,
        VmError vm_error = VmError::none) {
        result_.error = error;
        result_.failed_image_index = image_index;
        result_.failed_section_index = section_index;
        result_.failed_entry_index = entry_index;
        result_.vm_error = vm_error;
        result_.plan.image_order.clear();
        result_.plan.calls.clear();
        return false;
    }

    [[nodiscard]] bool validate_target(
        std::size_t image_index,
        std::uint64_t address,
        std::size_t section_index,
        std::size_t entry_index) {
        if (address == 0) {
            return fail_in_place(
                InitializerPlanError::null_initializer,
                image_index,
                section_index,
                entry_index);
        }

        std::array<std::byte, sizeof(std::uint32_t)> instruction{};
        const VmResult fetched = address_space_.fetch_code(address, instruction);
        if (!fetched) {
            return fail_in_place(
                InitializerPlanError::target_not_executable,
                image_index,
                section_index,
                entry_index,
                fetched.error);
        }
        return true;
    }

    [[nodiscard]] bool append_call(
        std::size_t image_index,
        InitializerKind kind,
        std::uint64_t address,
        std::size_t section_index,
        std::size_t entry_index) {
        if (result_.plan.calls.size() >= config_.max_initializers) {
            return fail_in_place(
                InitializerPlanError::initializer_limit,
                image_index,
                section_index,
                entry_index);
        }
        if (!validate_target(image_index, address, section_index, entry_index)) {
            return false;
        }
        result_.plan.calls.push_back({image_index, kind, address, section_index, entry_index});
        return true;
    }

    [[nodiscard]] bool append_image_initializers(std::size_t image_index) {
        const GraphImage& graph_image = graph_.images[image_index];

        // Legacy -init / LC_ROUTINES_64 runs before module initializer pointers.
        if (graph_image.initializers.routines.present &&
            graph_image.initializers.routines.address != 0) {
            if (!append_call(
                    image_index,
                    InitializerKind::routines64,
                    graph_image.initializers.routines.address,
                    InitializerPlanResult::kNoSection,
                    InitializerPlanResult::kNoEntry)) {
                return false;
            }
        }

        for (std::size_t section_index = 0;
             section_index < graph_image.initializers.pointer_sections.size(); ++section_index) {
            const macho::InitializerPointerSection& section =
                graph_image.initializers.pointer_sections[section_index];
            for (std::size_t entry_index = 0; entry_index < section.pointer_count(); ++entry_index) {
                const std::uint64_t offset = static_cast<std::uint64_t>(entry_index) * sizeof(std::uint64_t);
                if (offset > std::numeric_limits<std::uint64_t>::max() - section.address) {
                    return fail_in_place(
                        InitializerPlanError::pointer_read_failure,
                        image_index,
                        section_index,
                        entry_index,
                        VmError::address_overflow);
                }

                std::array<std::byte, sizeof(std::uint64_t)> encoded{};
                const VmResult read = address_space_.read(section.address + offset, encoded);
                if (!read) {
                    return fail_in_place(
                        InitializerPlanError::pointer_read_failure,
                        image_index,
                        section_index,
                        entry_index,
                        read.error);
                }

                std::uint64_t address = 0;
                for (std::size_t byte_index = 0; byte_index < encoded.size(); ++byte_index) {
                    address |= static_cast<std::uint64_t>(
                                   std::to_integer<unsigned char>(encoded[byte_index]))
                               << (byte_index * 8U);
                }
                if (!append_call(
                        image_index,
                        InitializerKind::mod_init_func,
                        address,
                        section_index,
                        entry_index)) {
                    return false;
                }
            }
        }

        result_.plan.image_order.push_back(image_index);
        return true;
    }

    [[nodiscard]] bool visit(std::size_t image_index) {
        if (image_index >= graph_.images.size()) {
            return fail_in_place(InitializerPlanError::invalid_dependency_index, image_index);
        }
        if (states_[image_index] == VisitState::done) {
            return true;
        }
        if (states_[image_index] == VisitState::visiting) {
            // Loaded-image graphs can contain dylib cycles. A back-edge does not
            // cause a second initialization and must not recurse forever.
            return true;
        }

        states_[image_index] = VisitState::visiting;
        const GraphImage& image = graph_.images[image_index];
        for (const GraphDependency& edge : image.dependencies) {
            if (edge.state != GraphDependencyState::loaded) {
                continue;
            }
            if (edge.image_index >= graph_.images.size()) {
                return fail_in_place(
                    InitializerPlanError::invalid_dependency_index,
                    image_index);
            }
            if (edge.dependency.kind == macho::DylibLoadKind::upward) {
                deferred_upward_.push_back(edge.image_index);
                continue;
            }
            if (!visit(edge.image_index)) {
                return false;
            }
        }

        if (!append_image_initializers(image_index)) {
            return false;
        }
        states_[image_index] = VisitState::done;
        return true;
    }

    const LoadedImageGraph& graph_;
    const GuestAddressSpace& address_space_;
    const InitializerPlanConfig& config_;
    std::vector<VisitState> states_;
    std::vector<std::size_t> deferred_upward_;
    InitializerPlanResult result_;
};

} // namespace initializer_plan_detail

[[nodiscard]] inline InitializerPlanResult plan_initializers(
    const LoadedImageGraph& graph,
    const GuestAddressSpace& address_space,
    const InitializerPlanConfig& config = {}) {
    return initializer_plan_detail::Builder(graph, address_space, config).run();
}

[[nodiscard]] inline std::string_view initializer_kind_name(InitializerKind kind) noexcept {
    switch (kind) {
    case InitializerKind::routines64: return "routines64";
    case InitializerKind::mod_init_func: return "mod_init_func";
    }
    return "unknown";
}

[[nodiscard]] inline std::string_view initializer_plan_error_name(InitializerPlanError error) noexcept {
    switch (error) {
    case InitializerPlanError::none: return "none";
    case InitializerPlanError::empty_graph: return "empty_graph";
    case InitializerPlanError::invalid_dependency_index: return "invalid_dependency_index";
    case InitializerPlanError::initializer_limit: return "initializer_limit";
    case InitializerPlanError::pointer_read_failure: return "pointer_read_failure";
    case InitializerPlanError::null_initializer: return "null_initializer";
    case InitializerPlanError::target_not_executable: return "target_not_executable";
    }
    return "unknown";
}

} // namespace macosarm::dyld
