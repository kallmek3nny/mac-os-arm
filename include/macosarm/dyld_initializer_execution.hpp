#pragma once

#include "macosarm/darwin_syscall.hpp"
#include "macosarm/dyld_initializers.hpp"
#include "macosarm/mach_trap.hpp"
#include "macosarm/pointer_auth.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <vector>

namespace macosarm::dyld {

struct InitializerCallContext {
    std::uint64_t argc{};
    std::uint64_t argv{};
    std::uint64_t envp{};
    std::uint64_t apple{};
    std::uint64_t program_vars{};
};

struct InitializerExecutionConfig {
    std::uint64_t instructions_per_initializer{100'000};
    std::uint64_t total_instruction_budget{1'000'000};
    // Deliberately unmapped low-48-bit return address. This lets translated
    // PACIASP/AUTIASP prologues use the same Phase 22 software PAUTH policy
    // without mapping an artificial trampoline into the guest.
    std::uint64_t return_sentinel{0x0000fffffffffff0ULL};
    InitializerCallContext context{};
};

enum class InitializerExecutionError {
    none,
    invalid_plan,
    invalid_config,
    return_sentinel_mapped,
    target_not_executable,
    initializer_instruction_budget,
    total_instruction_budget,
    backend_contract_violation,
    exception,
    memory_fault,
    backend_error,
    syscall_error,
    mach_trap_error,
    initializer_requested_exit,
};

struct InitializerExecutionResult {
    static constexpr std::size_t kNoImage = std::numeric_limits<std::size_t>::max();
    static constexpr std::size_t kNoCall = std::numeric_limits<std::size_t>::max();

    InitializerExecutionError error{InitializerExecutionError::none};
    std::size_t failed_image_index{kNoImage};
    std::size_t failed_call_index{kNoCall};
    std::uint64_t instructions_executed{};
    std::vector<bool> initialized_images;
    VmError vm_error{VmError::none};
    SyscallDispatchError syscall_error{SyscallDispatchError::none};
    MachTrapDispatchError mach_trap_error{MachTrapDispatchError::none};
    std::int32_t exit_status{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == InitializerExecutionError::none;
    }
};

namespace initializer_execution_detail {

[[nodiscard]] inline bool address_is_mapped(
    const GuestAddressSpace& address_space,
    std::uint64_t address) {
    for (const Mapping& mapping : address_space.mappings()) {
        if (mapping.size != 0 && address >= mapping.base && address - mapping.base < mapping.size) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] inline bool plan_is_well_formed(
    const LoadedImageGraph& graph,
    const InitializerPlan& plan) {
    if (plan.image_order.size() != graph.images.size()) {
        return false;
    }

    std::vector<std::size_t> positions(
        graph.images.size(), InitializerExecutionResult::kNoImage);
    for (std::size_t order_index = 0; order_index < plan.image_order.size(); ++order_index) {
        const std::size_t image_index = plan.image_order[order_index];
        if (image_index >= graph.images.size() ||
            positions[image_index] != InitializerExecutionResult::kNoImage) {
            return false;
        }
        positions[image_index] = order_index;
    }

    std::size_t previous_position = 0;
    bool have_previous = false;
    for (const PlannedInitializer& call : plan.calls) {
        if (call.image_index >= graph.images.size()) {
            return false;
        }
        const std::size_t position = positions[call.image_index];
        if (position == InitializerExecutionResult::kNoImage ||
            (have_previous && position < previous_position)) {
            return false;
        }
        previous_position = position;
        have_previous = true;
    }
    return true;
}

class Executor {
public:
    Executor(
        const LoadedImageGraph& graph,
        const InitializerPlan& plan,
        CpuState& state,
        GuestAddressSpace& address_space,
        ExecutionBackend& backend,
        DarwinHostServices& host,
        const InitializerExecutionConfig& config)
        : graph_(graph),
          plan_(plan),
          state_(state),
          address_space_(address_space),
          backend_(backend),
          host_(host),
          config_(config) {
        result_.initialized_images.assign(graph.images.size(), false);
    }

    [[nodiscard]] InitializerExecutionResult run() {
        if (!plan_is_well_formed(graph_, plan_)) {
            return fail(InitializerExecutionError::invalid_plan);
        }
        if (config_.instructions_per_initializer == 0 ||
            config_.total_instruction_budget == 0 ||
            config_.return_sentinel == 0 ||
            (config_.return_sentinel & 0x3U) != 0 ||
            config_.return_sentinel > PointerAuthenticator::kAddressMask) {
            return fail(InitializerExecutionError::invalid_config);
        }
        if (address_is_mapped(address_space_, config_.return_sentinel)) {
            return fail(InitializerExecutionError::return_sentinel_mapped);
        }

        std::size_t call_cursor = 0;
        for (std::size_t image_index : plan_.image_order) {
            while (call_cursor < plan_.calls.size() &&
                   plan_.calls[call_cursor].image_index == image_index) {
                if (!execute_call(call_cursor, plan_.calls[call_cursor])) {
                    return std::move(result_);
                }
                ++call_cursor;
            }
            result_.initialized_images[image_index] = true;
        }

        if (call_cursor != plan_.calls.size()) {
            return fail(InitializerExecutionError::invalid_plan);
        }
        return std::move(result_);
    }

private:
    [[nodiscard]] InitializerExecutionResult fail(
        InitializerExecutionError error,
        std::size_t image_index = InitializerExecutionResult::kNoImage,
        std::size_t call_index = InitializerExecutionResult::kNoCall,
        VmError vm_error = VmError::none,
        SyscallDispatchError syscall_error = SyscallDispatchError::none,
        MachTrapDispatchError mach_trap_error = MachTrapDispatchError::none,
        std::int32_t exit_status = 0) {
        result_.error = error;
        result_.failed_image_index = image_index;
        result_.failed_call_index = call_index;
        result_.vm_error = vm_error;
        result_.syscall_error = syscall_error;
        result_.mach_trap_error = mach_trap_error;
        result_.exit_status = exit_status;
        return std::move(result_);
    }

    [[nodiscard]] bool fail_in_place(
        InitializerExecutionError error,
        std::size_t image_index,
        std::size_t call_index,
        VmError vm_error = VmError::none,
        SyscallDispatchError syscall_error = SyscallDispatchError::none,
        MachTrapDispatchError mach_trap_error = MachTrapDispatchError::none,
        std::int32_t exit_status = 0) {
        result_.error = error;
        result_.failed_image_index = image_index;
        result_.failed_call_index = call_index;
        result_.vm_error = vm_error;
        result_.syscall_error = syscall_error;
        result_.mach_trap_error = mach_trap_error;
        result_.exit_status = exit_status;
        return false;
    }

    void prepare_call(const PlannedInitializer& call) noexcept {
        state_.pc = call.address;
        state_.x[30] = config_.return_sentinel;
        state_.x[0] = config_.context.argc;
        state_.x[1] = config_.context.argv;
        state_.x[2] = config_.context.envp;
        state_.x[3] = config_.context.apple;
        state_.x[4] = config_.context.program_vars;
    }

    [[nodiscard]] bool execute_call(
        std::size_t call_index,
        const PlannedInitializer& call) {
        std::array<std::byte, sizeof(std::uint32_t)> first_instruction{};
        const VmResult fetched = address_space_.fetch_code(call.address, first_instruction);
        if (!fetched) {
            return fail_in_place(
                InitializerExecutionError::target_not_executable,
                call.image_index,
                call_index,
                fetched.error);
        }

        prepare_call(call);
        std::uint64_t call_instructions = 0;
        while (true) {
            if (call_instructions >= config_.instructions_per_initializer) {
                return fail_in_place(
                    InitializerExecutionError::initializer_instruction_budget,
                    call.image_index,
                    call_index);
            }
            if (result_.instructions_executed >= config_.total_instruction_budget) {
                return fail_in_place(
                    InitializerExecutionError::total_instruction_budget,
                    call.image_index,
                    call_index);
            }

            const ExecutionResult execution = backend_.run(state_, address_space_, 1);
            if (execution.instructions_executed > 1) {
                return fail_in_place(
                    InitializerExecutionError::backend_contract_violation,
                    call.image_index,
                    call_index);
            }

            call_instructions += execution.instructions_executed;
            result_.instructions_executed += execution.instructions_executed;

            if (state_.pc == config_.return_sentinel) {
                if (execution.reason == StopReason::instruction_budget &&
                    execution.instructions_executed == 1) {
                    return true;
                }
                return fail_in_place(
                    InitializerExecutionError::backend_contract_violation,
                    call.image_index,
                    call_index);
            }

            switch (execution.reason) {
            case StopReason::instruction_budget:
                if (execution.instructions_executed == 0) {
                    return fail_in_place(
                        InitializerExecutionError::backend_contract_violation,
                        call.image_index,
                        call_index);
                }
                break;

            case StopReason::supervisor_call: {
                if (execution.instructions_executed == 0) {
                    return fail_in_place(
                        InitializerExecutionError::backend_contract_violation,
                        call.image_index,
                        call_index);
                }

                if (decode_darwin_trap_number(state_) < 0) {
                    const MachTrapDispatchResult dispatch =
                        dispatch_mach_trap(state_, address_space_, execution, mach_context_);
                    if (!dispatch) {
                        return fail_in_place(
                            InitializerExecutionError::mach_trap_error,
                            call.image_index,
                            call_index,
                            VmError::none,
                            SyscallDispatchError::none,
                            dispatch.error);
                    }
                } else {
                    const SyscallDispatchResult dispatch =
                        dispatch_darwin_syscall(state_, address_space_, execution, host_);
                    if (!dispatch) {
                        return fail_in_place(
                            InitializerExecutionError::syscall_error,
                            call.image_index,
                            call_index,
                            VmError::none,
                            dispatch.error);
                    }
                    if (dispatch.action == SyscallAction::exit_process) {
                        return fail_in_place(
                            InitializerExecutionError::initializer_requested_exit,
                            call.image_index,
                            call_index,
                            VmError::none,
                            SyscallDispatchError::none,
                            MachTrapDispatchError::none,
                            dispatch.exit_status);
                    }
                }
                break;
            }

            case StopReason::exception:
                return fail_in_place(
                    InitializerExecutionError::exception,
                    call.image_index,
                    call_index);

            case StopReason::memory_fault:
                return fail_in_place(
                    InitializerExecutionError::memory_fault,
                    call.image_index,
                    call_index,
                    execution.vm_error);

            case StopReason::backend_error:
                return fail_in_place(
                    InitializerExecutionError::backend_error,
                    call.image_index,
                    call_index);
            }
        }
    }

    const LoadedImageGraph& graph_;
    const InitializerPlan& plan_;
    CpuState& state_;
    GuestAddressSpace& address_space_;
    ExecutionBackend& backend_;
    DarwinHostServices& host_;
    const InitializerExecutionConfig& config_;
    MachContext mach_context_;
    InitializerExecutionResult result_;
};

} // namespace initializer_execution_detail

[[nodiscard]] inline InitializerExecutionResult execute_initializers(
    const LoadedImageGraph& graph,
    const InitializerPlan& plan,
    CpuState& state,
    GuestAddressSpace& address_space,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    const InitializerExecutionConfig& config = {}) {
    return initializer_execution_detail::Executor(
        graph, plan, state, address_space, backend, host, config).run();
}

[[nodiscard]] inline std::string_view initializer_execution_error_name(
    InitializerExecutionError error) noexcept {
    switch (error) {
    case InitializerExecutionError::none: return "none";
    case InitializerExecutionError::invalid_plan: return "invalid_plan";
    case InitializerExecutionError::invalid_config: return "invalid_config";
    case InitializerExecutionError::return_sentinel_mapped: return "return_sentinel_mapped";
    case InitializerExecutionError::target_not_executable: return "target_not_executable";
    case InitializerExecutionError::initializer_instruction_budget: return "initializer_instruction_budget";
    case InitializerExecutionError::total_instruction_budget: return "total_instruction_budget";
    case InitializerExecutionError::backend_contract_violation: return "backend_contract_violation";
    case InitializerExecutionError::exception: return "exception";
    case InitializerExecutionError::memory_fault: return "memory_fault";
    case InitializerExecutionError::backend_error: return "backend_error";
    case InitializerExecutionError::syscall_error: return "syscall_error";
    case InitializerExecutionError::mach_trap_error: return "mach_trap_error";
    case InitializerExecutionError::initializer_requested_exit: return "initializer_requested_exit";
    }
    return "unknown";
}

} // namespace macosarm::dyld
