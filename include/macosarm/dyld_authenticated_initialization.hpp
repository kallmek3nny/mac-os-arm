#pragma once

#include "macosarm/dyld_auth_slots.hpp"
#include "macosarm/dyld_initializer_execution.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace macosarm::dyld {

struct AuthenticatedInitializerPlanConfig {
    std::size_t max_initializers{4096};
    std::size_t max_authenticated_slots{kMaxChainedFixups};
    std::span<const AuthenticatedFixupSlot> authenticated_slots{};
    const PointerAuthenticator* pointer_auth{};
};

enum class AuthenticatedInitializerPlanError {
    none,
    base_planning_failure,
    authenticated_slot_limit,
    malformed_authenticated_slot,
    pointer_read_failure,
    null_initializer,
    pointer_auth_required,
    pointer_auth_failure,
    target_misaligned,
    target_not_executable,
    initializer_limit,
};

struct AuthenticatedInitializerPlanResult {
    static constexpr std::size_t kNoImage = std::numeric_limits<std::size_t>::max();
    static constexpr std::size_t kNoSection = std::numeric_limits<std::size_t>::max();
    static constexpr std::size_t kNoEntry = std::numeric_limits<std::size_t>::max();

    InitializerPlan plan;
    AuthenticatedInitializerPlanError error{AuthenticatedInitializerPlanError::none};
    InitializerPlanError base_error{InitializerPlanError::none};
    PointerAuthError pointer_auth_error{PointerAuthError::none};
    std::size_t failed_image_index{kNoImage};
    std::size_t failed_section_index{kNoSection};
    std::size_t failed_entry_index{kNoEntry};
    std::uint64_t failed_storage_address{};
    VmError vm_error{VmError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == AuthenticatedInitializerPlanError::none;
    }
};

namespace authenticated_initializer_detail {

[[nodiscard]] inline std::uint64_t decode_u64(
    const std::array<std::byte, sizeof(std::uint64_t)>& bytes) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return value;
}

[[nodiscard]] inline bool valid_key(PointerAuthKey key) noexcept {
    return static_cast<std::uint8_t>(key) <=
           static_cast<std::uint8_t>(PointerAuthKey::data_b);
}

class Builder {
public:
    Builder(
        const LoadedImageGraph& graph,
        const GuestAddressSpace& address_space,
        const AuthenticatedInitializerPlanConfig& config)
        : graph_(graph), address_space_(address_space), config_(config) {}

    [[nodiscard]] AuthenticatedInitializerPlanResult run() {
        if (!build_slot_index()) {
            return std::move(result_);
        }

        LoadedImageGraph ordering_graph = graph_;
        for (GraphImage& image : ordering_graph.images) {
            image.initializers.pointer_sections.clear();
        }

        InitializerPlanConfig base_config;
        base_config.max_initializers = config_.max_initializers;
        const InitializerPlanResult base =
            plan_initializers(ordering_graph, address_space_, base_config);
        if (!base) {
            result_.error = AuthenticatedInitializerPlanError::base_planning_failure;
            result_.base_error = base.error;
            result_.failed_image_index = base.failed_image_index;
            result_.failed_section_index = base.failed_section_index;
            result_.failed_entry_index = base.failed_entry_index;
            result_.vm_error = base.vm_error;
            return std::move(result_);
        }

        result_.plan.image_order = base.plan.image_order;
        std::size_t base_call_cursor = 0;
        for (std::size_t image_index : result_.plan.image_order) {
            while (base_call_cursor < base.plan.calls.size() &&
                   base.plan.calls[base_call_cursor].image_index == image_index) {
                result_.plan.calls.push_back(base.plan.calls[base_call_cursor]);
                ++base_call_cursor;
            }
            if (!append_pointer_initializers(image_index)) {
                return std::move(result_);
            }
        }

        if (base_call_cursor != base.plan.calls.size()) {
            return fail(AuthenticatedInitializerPlanError::base_planning_failure);
        }
        return std::move(result_);
    }

private:
    [[nodiscard]] AuthenticatedInitializerPlanResult fail(
        AuthenticatedInitializerPlanError error,
        std::size_t image_index = AuthenticatedInitializerPlanResult::kNoImage,
        std::size_t section_index = AuthenticatedInitializerPlanResult::kNoSection,
        std::size_t entry_index = AuthenticatedInitializerPlanResult::kNoEntry,
        std::uint64_t storage_address = 0,
        VmError vm_error = VmError::none,
        PointerAuthError pointer_auth_error = PointerAuthError::none) {
        result_.error = error;
        result_.failed_image_index = image_index;
        result_.failed_section_index = section_index;
        result_.failed_entry_index = entry_index;
        result_.failed_storage_address = storage_address;
        result_.vm_error = vm_error;
        result_.pointer_auth_error = pointer_auth_error;
        result_.plan.image_order.clear();
        result_.plan.calls.clear();
        return std::move(result_);
    }

    [[nodiscard]] bool fail_in_place(
        AuthenticatedInitializerPlanError error,
        std::size_t image_index,
        std::size_t section_index,
        std::size_t entry_index,
        std::uint64_t storage_address,
        VmError vm_error = VmError::none,
        PointerAuthError pointer_auth_error = PointerAuthError::none) {
        result_.error = error;
        result_.failed_image_index = image_index;
        result_.failed_section_index = section_index;
        result_.failed_entry_index = entry_index;
        result_.failed_storage_address = storage_address;
        result_.vm_error = vm_error;
        result_.pointer_auth_error = pointer_auth_error;
        result_.plan.image_order.clear();
        result_.plan.calls.clear();
        return false;
    }

    [[nodiscard]] bool build_slot_index() {
        if (config_.authenticated_slots.size() > config_.max_authenticated_slots) {
            result_.error = AuthenticatedInitializerPlanError::authenticated_slot_limit;
            return false;
        }

        slot_index_.reserve(config_.authenticated_slots.size());
        for (const AuthenticatedFixupSlot& slot : config_.authenticated_slots) {
            if ((slot.storage_address & (sizeof(std::uint64_t) - 1U)) != 0 ||
                !valid_key(slot.key) ||
                !slot_index_.emplace(slot.storage_address, &slot).second) {
                result_.error = AuthenticatedInitializerPlanError::malformed_authenticated_slot;
                result_.failed_storage_address = slot.storage_address;
                slot_index_.clear();
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] bool append_pointer_initializers(std::size_t image_index) {
        const GraphImage& graph_image = graph_.images[image_index];
        for (std::size_t section_index = 0;
             section_index < graph_image.initializers.pointer_sections.size(); ++section_index) {
            const macho::InitializerPointerSection& section =
                graph_image.initializers.pointer_sections[section_index];
            for (std::size_t entry_index = 0; entry_index < section.pointer_count(); ++entry_index) {
                const std::uint64_t offset =
                    static_cast<std::uint64_t>(entry_index) * sizeof(std::uint64_t);
                if (offset > std::numeric_limits<std::uint64_t>::max() - section.address) {
                    return fail_in_place(
                        AuthenticatedInitializerPlanError::pointer_read_failure,
                        image_index,
                        section_index,
                        entry_index,
                        section.address,
                        VmError::address_overflow);
                }
                const std::uint64_t storage_address = section.address + offset;

                std::array<std::byte, sizeof(std::uint64_t)> encoded{};
                const VmResult read = address_space_.read(storage_address, encoded);
                if (!read) {
                    return fail_in_place(
                        AuthenticatedInitializerPlanError::pointer_read_failure,
                        image_index,
                        section_index,
                        entry_index,
                        storage_address,
                        read.error);
                }
                if (result_.plan.calls.size() >= config_.max_initializers) {
                    return fail_in_place(
                        AuthenticatedInitializerPlanError::initializer_limit,
                        image_index,
                        section_index,
                        entry_index,
                        storage_address);
                }

                std::uint64_t address = decode_u64(encoded);
                const auto slot = slot_index_.find(storage_address);
                if (slot != slot_index_.end()) {
                    if (config_.pointer_auth == nullptr) {
                        return fail_in_place(
                            AuthenticatedInitializerPlanError::pointer_auth_required,
                            image_index,
                            section_index,
                            entry_index,
                            storage_address);
                    }
                    const AuthenticatedFixupSlot& policy = *slot->second;
                    const std::uint64_t discriminator = policy.address_diversity
                        ? PointerAuthenticator::blend_discriminator(
                              policy.storage_address, policy.diversity)
                        : static_cast<std::uint64_t>(policy.diversity);
                    const PointerAuthResult authenticated = config_.pointer_auth->authenticate(
                        address,
                        policy.key,
                        discriminator);
                    if (!authenticated) {
                        return fail_in_place(
                            AuthenticatedInitializerPlanError::pointer_auth_failure,
                            image_index,
                            section_index,
                            entry_index,
                            storage_address,
                            VmError::none,
                            authenticated.error);
                    }
                    address = authenticated.pointer;
                    if ((address & 0x3U) != 0) {
                        return fail_in_place(
                            AuthenticatedInitializerPlanError::target_misaligned,
                            image_index,
                            section_index,
                            entry_index,
                            storage_address);
                    }
                }

                if (address == 0) {
                    return fail_in_place(
                        AuthenticatedInitializerPlanError::null_initializer,
                        image_index,
                        section_index,
                        entry_index,
                        storage_address);
                }

                std::array<std::byte, sizeof(std::uint32_t)> instruction{};
                const VmResult fetched = address_space_.fetch_code(address, instruction);
                if (!fetched) {
                    return fail_in_place(
                        AuthenticatedInitializerPlanError::target_not_executable,
                        image_index,
                        section_index,
                        entry_index,
                        storage_address,
                        fetched.error);
                }

                result_.plan.calls.push_back({
                    image_index,
                    InitializerKind::mod_init_func,
                    address,
                    section_index,
                    entry_index,
                });
            }
        }
        return true;
    }

    const LoadedImageGraph& graph_;
    const GuestAddressSpace& address_space_;
    const AuthenticatedInitializerPlanConfig& config_;
    std::unordered_map<std::uint64_t, const AuthenticatedFixupSlot*> slot_index_;
    AuthenticatedInitializerPlanResult result_;
};

} // namespace authenticated_initializer_detail

[[nodiscard]] inline AuthenticatedInitializerPlanResult plan_initializers_with_pointer_auth(
    const LoadedImageGraph& graph,
    const GuestAddressSpace& address_space,
    const AuthenticatedInitializerPlanConfig& config = {}) {
    return authenticated_initializer_detail::Builder(graph, address_space, config).run();
}

enum class AuthenticatedImageInitializationError {
    none,
    planning_failure,
    execution_failure,
};

struct AuthenticatedImageInitializationResult {
    AuthenticatedImageInitializationError error{AuthenticatedImageInitializationError::none};
    AuthenticatedInitializerPlanResult planning;
    InitializerExecutionResult execution;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == AuthenticatedImageInitializationError::none;
    }
};

[[nodiscard]] inline AuthenticatedImageInitializationResult
initialize_image_graph_with_pointer_auth(
    const LoadedImageGraph& graph,
    CpuState& state,
    GuestAddressSpace& address_space,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    const AuthenticatedInitializerPlanConfig& plan_config = {},
    const InitializerExecutionConfig& execution_config = {}) {
    AuthenticatedImageInitializationResult result;
    result.planning = plan_initializers_with_pointer_auth(graph, address_space, plan_config);
    if (!result.planning) {
        result.error = AuthenticatedImageInitializationError::planning_failure;
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
        result.error = AuthenticatedImageInitializationError::execution_failure;
    }
    return result;
}

[[nodiscard]] inline std::string_view authenticated_initializer_plan_error_name(
    AuthenticatedInitializerPlanError error) noexcept {
    switch (error) {
    case AuthenticatedInitializerPlanError::none: return "none";
    case AuthenticatedInitializerPlanError::base_planning_failure: return "base_planning_failure";
    case AuthenticatedInitializerPlanError::authenticated_slot_limit: return "authenticated_slot_limit";
    case AuthenticatedInitializerPlanError::malformed_authenticated_slot: return "malformed_authenticated_slot";
    case AuthenticatedInitializerPlanError::pointer_read_failure: return "pointer_read_failure";
    case AuthenticatedInitializerPlanError::null_initializer: return "null_initializer";
    case AuthenticatedInitializerPlanError::pointer_auth_required: return "pointer_auth_required";
    case AuthenticatedInitializerPlanError::pointer_auth_failure: return "pointer_auth_failure";
    case AuthenticatedInitializerPlanError::target_misaligned: return "target_misaligned";
    case AuthenticatedInitializerPlanError::target_not_executable: return "target_not_executable";
    case AuthenticatedInitializerPlanError::initializer_limit: return "initializer_limit";
    }
    return "unknown";
}

[[nodiscard]] inline std::string_view authenticated_image_initialization_error_name(
    AuthenticatedImageInitializationError error) noexcept {
    switch (error) {
    case AuthenticatedImageInitializationError::none: return "none";
    case AuthenticatedImageInitializationError::planning_failure: return "planning_failure";
    case AuthenticatedImageInitializationError::execution_failure: return "execution_failure";
    }
    return "unknown";
}

} // namespace macosarm::dyld
