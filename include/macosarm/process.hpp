#pragma once

#include "macosarm/darwin_syscall.hpp"
#include "macosarm/execution.hpp"
#include "macosarm/mach_trap.hpp"

#include <cstdint>
#include <string_view>

namespace macosarm {

enum class ProcessStopReason {
    exited,
    instruction_budget,
    exception,
    memory_fault,
    backend_error,
    syscall_error,
    mach_trap_error,
};

struct ProcessResult {
    ProcessStopReason reason{ProcessStopReason::backend_error};
    std::uint64_t instructions_executed{};
    std::int32_t exit_status{};
    VmError vm_error{VmError::none};
    SyscallDispatchError syscall_error{SyscallDispatchError::none};
    MachTrapDispatchError mach_trap_error{MachTrapDispatchError::none};
};

[[nodiscard]] ProcessResult run_process(
    CpuState& state,
    GuestAddressSpace& address_space,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    std::uint64_t instruction_budget);

[[nodiscard]] std::string_view process_stop_reason_name(ProcessStopReason reason) noexcept;

} // namespace macosarm
