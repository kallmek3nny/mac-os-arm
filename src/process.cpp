#include "macosarm/process.hpp"

namespace macosarm {
namespace {

[[nodiscard]] ProcessResult backend_contract_error(std::uint64_t executed) noexcept {
    return {
        ProcessStopReason::backend_error,
        executed,
        0,
        VmError::none,
        SyscallDispatchError::none,
        MachTrapDispatchError::none,
    };
}

} // namespace

ProcessResult run_process(
    CpuState& state,
    GuestAddressSpace& address_space,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    MachContext& mach_context,
    std::uint64_t instruction_budget) {

    if (instruction_budget == 0) {
        return {
            ProcessStopReason::instruction_budget,
            0,
            0,
            VmError::none,
            SyscallDispatchError::none,
            MachTrapDispatchError::none,
        };
    }

    std::uint64_t remaining = instruction_budget;
    std::uint64_t total_executed = 0;

    while (remaining != 0) {
        const ExecutionResult execution = backend.run(state, address_space, remaining);
        if (execution.instructions_executed > remaining) {
            return backend_contract_error(total_executed);
        }

        remaining -= execution.instructions_executed;
        total_executed += execution.instructions_executed;

        switch (execution.reason) {
        case StopReason::instruction_budget:
            return {
                ProcessStopReason::instruction_budget,
                total_executed,
                0,
                VmError::none,
                SyscallDispatchError::none,
                MachTrapDispatchError::none,
            };

        case StopReason::supervisor_call: {
            if (execution.instructions_executed == 0) {
                return backend_contract_error(total_executed);
            }

            if (decode_darwin_trap_number(state) < 0) {
                const MachTrapDispatchResult mach_dispatch =
                    dispatch_mach_trap(state, address_space, execution, mach_context);
                if (!mach_dispatch) {
                    return {
                        ProcessStopReason::mach_trap_error,
                        total_executed,
                        0,
                        VmError::none,
                        SyscallDispatchError::none,
                        mach_dispatch.error,
                    };
                }
            } else {
                const SyscallDispatchResult dispatch =
                    dispatch_darwin_syscall(state, address_space, execution, host, mach_context);
                if (!dispatch) {
                    return {
                        ProcessStopReason::syscall_error,
                        total_executed,
                        0,
                        VmError::none,
                        dispatch.error,
                        MachTrapDispatchError::none,
                    };
                }
                if (dispatch.action == SyscallAction::exit_process) {
                    return {
                        ProcessStopReason::exited,
                        total_executed,
                        dispatch.exit_status,
                        VmError::none,
                        SyscallDispatchError::none,
                        MachTrapDispatchError::none,
                    };
                }
            }

            if (remaining == 0) {
                return {
                    ProcessStopReason::instruction_budget,
                    total_executed,
                    0,
                    VmError::none,
                    SyscallDispatchError::none,
                    MachTrapDispatchError::none,
                };
            }
            break;
        }

        case StopReason::exception:
            return {
                ProcessStopReason::exception,
                total_executed,
                0,
                VmError::none,
                SyscallDispatchError::none,
                MachTrapDispatchError::none,
            };

        case StopReason::memory_fault:
            return {
                ProcessStopReason::memory_fault,
                total_executed,
                0,
                execution.vm_error,
                SyscallDispatchError::none,
                MachTrapDispatchError::none,
            };

        case StopReason::backend_error:
            return backend_contract_error(total_executed);
        }
    }

    return {
        ProcessStopReason::instruction_budget,
        total_executed,
        0,
        VmError::none,
        SyscallDispatchError::none,
        MachTrapDispatchError::none,
    };
}

ProcessResult run_process(
    CpuState& state,
    GuestAddressSpace& address_space,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    std::uint64_t instruction_budget) {
    MachContext mach_context;
    return run_process(
        state,
        address_space,
        backend,
        host,
        mach_context,
        instruction_budget);
}

std::string_view process_stop_reason_name(ProcessStopReason reason) noexcept {
    switch (reason) {
    case ProcessStopReason::exited: return "exited";
    case ProcessStopReason::instruction_budget: return "instruction_budget";
    case ProcessStopReason::exception: return "exception";
    case ProcessStopReason::memory_fault: return "memory_fault";
    case ProcessStopReason::backend_error: return "backend_error";
    case ProcessStopReason::syscall_error: return "syscall_error";
    case ProcessStopReason::mach_trap_error: return "mach_trap_error";
    }
    return "unknown";
}

} // namespace macosarm
