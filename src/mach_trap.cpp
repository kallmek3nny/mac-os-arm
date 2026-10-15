#include "macosarm/mach_trap.hpp"

#include "macosarm/darwin_syscall.hpp"

#include <bit>
#include <cstdint>
#include <limits>

namespace macosarm {

std::optional<std::uint32_t> MachContext::allocate_reply_port() noexcept {
    if (next_reply_port_ == 0 || next_reply_port_ == std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }

    const std::uint32_t port = next_reply_port_;
    ++next_reply_port_;
    return port;
}

std::int64_t decode_darwin_trap_number(const CpuState& state) noexcept {
    return std::bit_cast<std::int64_t>(state.x[16]);
}

MachTrapDispatchResult dispatch_mach_trap(
    CpuState& state,
    GuestAddressSpace& address_space,
    const ExecutionResult& execution,
    MachContext& context) {

    (void)address_space;

    if (execution.reason != StopReason::supervisor_call) {
        return {MachTrapDispatchError::not_supervisor_call, 0, 0};
    }
    if (execution.supervisor_call != kDarwinSvcImmediate) {
        return {MachTrapDispatchError::unsupported_svc, 0, 0};
    }

    const std::int64_t trap_number = decode_darwin_trap_number(state);
    if (trap_number >= 0) {
        return {MachTrapDispatchError::not_mach_trap, trap_number, 0};
    }

    std::uint32_t port = 0;
    switch (trap_number) {
    case kMachTrapReplyPort: {
        const auto allocated = context.allocate_reply_port();
        if (!allocated.has_value()) {
            return {MachTrapDispatchError::port_namespace_exhausted, trap_number, 0};
        }
        port = *allocated;
        break;
    }
    case kMachTrapThreadSelf:
        port = context.thread_self_port();
        break;
    case kMachTrapTaskSelf:
        port = context.task_self_port();
        break;
    case kMachTrapHostSelf:
        port = context.host_self_port();
        break;
    default:
        return {MachTrapDispatchError::unsupported_trap, trap_number, 0};
    }

    state.x[0] = port;
    return {MachTrapDispatchError::none, trap_number, port};
}

std::string_view mach_trap_dispatch_error_name(MachTrapDispatchError error) noexcept {
    switch (error) {
    case MachTrapDispatchError::none: return "none";
    case MachTrapDispatchError::not_supervisor_call: return "not_supervisor_call";
    case MachTrapDispatchError::unsupported_svc: return "unsupported_svc";
    case MachTrapDispatchError::not_mach_trap: return "not_mach_trap";
    case MachTrapDispatchError::unsupported_trap: return "unsupported_trap";
    case MachTrapDispatchError::port_namespace_exhausted: return "port_namespace_exhausted";
    }
    return "unknown";
}

} // namespace macosarm
