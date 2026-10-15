#include "macosarm/mach_trap.hpp"

#include "macosarm/darwin_syscall.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace macosarm {
namespace {

[[nodiscard]] std::optional<std::uint64_t> round_up_guest_page(std::uint64_t size) noexcept {
    if (size == 0) {
        return std::nullopt;
    }

    constexpr std::uint64_t page_size = GuestAddressSpace::kPageSize;
    const std::uint64_t remainder = size % page_size;
    if (remainder == 0) {
        return size;
    }

    const std::uint64_t increment = page_size - remainder;
    if (size > std::numeric_limits<std::uint64_t>::max() - increment) {
        return std::nullopt;
    }
    return size + increment;
}

[[nodiscard]] VmResult read_guest_u64(
    const GuestAddressSpace& address_space,
    std::uint64_t address,
    std::uint64_t& value) {

    std::array<std::byte, 8> bytes{};
    const VmResult result = address_space.read(address, bytes);
    if (!result) {
        return result;
    }

    value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    }
    return {};
}

[[nodiscard]] VmResult write_guest_u64(
    GuestAddressSpace& address_space,
    std::uint64_t address,
    std::uint64_t value) {

    std::array<std::byte, 8> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
    return address_space.write(address, bytes);
}

[[nodiscard]] std::optional<std::uint64_t> find_anywhere_range(
    const GuestAddressSpace& address_space,
    std::uint64_t size) {

    std::uint64_t candidate = MachContext::kVmAnywhereBase;
    const auto mappings = address_space.mappings();

    for (const Mapping& mapping : mappings) {
        if (mapping.base > candidate) {
            const std::uint64_t gap = mapping.base - candidate;
            if (size <= gap) {
                return candidate;
            }
        }

        if (mapping.size > std::numeric_limits<std::uint64_t>::max() - mapping.base) {
            return std::nullopt;
        }
        const std::uint64_t mapping_end = mapping.base + mapping.size;
        if (mapping_end > candidate) {
            candidate = mapping_end;
        }
    }

    if (candidate > std::numeric_limits<std::uint64_t>::max() - size) {
        return std::nullopt;
    }
    return candidate;
}

[[nodiscard]] bool valid_task_target(const CpuState& state, const MachContext& context) noexcept {
    return state.x[0] == static_cast<std::uint64_t>(context.task_self_port());
}

[[nodiscard]] Protection decode_vm_protection(std::uint32_t value) noexcept {
    Protection protection = Protection::none;
    if ((value & kMachVmProtRead) != 0) {
        protection = protection | Protection::read;
    }
    if ((value & kMachVmProtWrite) != 0) {
        protection = protection | Protection::write;
    }
    if ((value & kMachVmProtExecute) != 0) {
        protection = protection | Protection::execute;
    }
    return protection;
}

[[nodiscard]] MachTrapDispatchResult guest_mach_return(
    CpuState& state,
    std::int64_t trap_number,
    std::uint32_t kern_return) noexcept {

    state.x[0] = kern_return;
    return {MachTrapDispatchError::none, trap_number, 0};
}

[[nodiscard]] MachTrapDispatchResult dispatch_vm_allocate(
    CpuState& state,
    GuestAddressSpace& address_space,
    MachContext& context,
    std::int64_t trap_number) {

    if (!valid_task_target(state, context)) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }

    const std::uint64_t address_pointer = state.x[1];
    const auto rounded_size = round_up_guest_page(state.x[2]);
    if (!rounded_size.has_value()) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }

    const std::uint64_t flags = state.x[3];
    if ((flags & ~kMachVmFlagsAnywhere) != 0) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }

    std::uint64_t base = 0;
    if ((flags & kMachVmFlagsAnywhere) != 0) {
        const auto candidate = find_anywhere_range(address_space, *rounded_size);
        if (!candidate.has_value()) {
            return guest_mach_return(state, trap_number, kMachKernNoSpace);
        }
        base = *candidate;
    } else {
        const VmResult read_result = read_guest_u64(address_space, address_pointer, base);
        if (!read_result) {
            return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
        }
        if ((base % GuestAddressSpace::kPageSize) != 0) {
            return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
        }
    }

    const VmResult map_result = address_space.map(
        base,
        *rounded_size,
        Protection::read | Protection::write);
    if (!map_result) {
        const std::uint32_t kern_return =
            map_result.error == VmError::overlap ? kMachKernNoSpace : kMachKernInvalidArgument;
        return guest_mach_return(state, trap_number, kern_return);
    }

    const VmResult copyout_result = write_guest_u64(address_space, address_pointer, base);
    if (!copyout_result) {
        (void)address_space.unmap(base, *rounded_size);
        return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
    }

    return guest_mach_return(state, trap_number, kMachKernSuccess);
}

[[nodiscard]] MachTrapDispatchResult dispatch_vm_deallocate(
    CpuState& state,
    GuestAddressSpace& address_space,
    const MachContext& context,
    std::int64_t trap_number) {

    if (!valid_task_target(state, context)) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }

    const std::uint64_t address = state.x[1];
    const auto rounded_size = round_up_guest_page(state.x[2]);
    if (!rounded_size.has_value() || (address % GuestAddressSpace::kPageSize) != 0) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }

    const VmResult result = address_space.unmap(address, *rounded_size);
    if (!result) {
        return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
    }
    return guest_mach_return(state, trap_number, kMachKernSuccess);
}

[[nodiscard]] MachTrapDispatchResult dispatch_vm_protect(
    CpuState& state,
    GuestAddressSpace& address_space,
    const MachContext& context,
    std::int64_t trap_number) {

    if (!valid_task_target(state, context)) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }

    const std::uint64_t address = state.x[1];
    const auto rounded_size = round_up_guest_page(state.x[2]);
    const std::uint64_t set_maximum = state.x[3];
    const std::uint64_t raw_protection = state.x[4];

    if (!rounded_size.has_value() ||
        (address % GuestAddressSpace::kPageSize) != 0 ||
        set_maximum != 0 ||
        raw_protection > std::numeric_limits<std::uint32_t>::max() ||
        (static_cast<std::uint32_t>(raw_protection) & ~kMachVmProtMask) != 0) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }

    const Protection protection = decode_vm_protection(static_cast<std::uint32_t>(raw_protection));
    const VmResult result = address_space.protect(address, *rounded_size, protection);
    if (!result) {
        return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
    }
    return guest_mach_return(state, trap_number, kMachKernSuccess);
}

} // namespace

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

    switch (trap_number) {
    case kMachTrapVmAllocate:
        return dispatch_vm_allocate(state, address_space, context, trap_number);
    case kMachTrapVmDeallocate:
        return dispatch_vm_deallocate(state, address_space, context, trap_number);
    case kMachTrapVmProtect:
        return dispatch_vm_protect(state, address_space, context, trap_number);
    case kMachTrapReplyPort: {
        const auto allocated = context.allocate_reply_port();
        if (!allocated.has_value()) {
            return {MachTrapDispatchError::port_namespace_exhausted, trap_number, 0};
        }
        state.x[0] = *allocated;
        return {MachTrapDispatchError::none, trap_number, *allocated};
    }
    case kMachTrapThreadSelf:
        state.x[0] = context.thread_self_port();
        return {MachTrapDispatchError::none, trap_number, context.thread_self_port()};
    case kMachTrapTaskSelf:
        state.x[0] = context.task_self_port();
        return {MachTrapDispatchError::none, trap_number, context.task_self_port()};
    case kMachTrapHostSelf:
        state.x[0] = context.host_self_port();
        return {MachTrapDispatchError::none, trap_number, context.host_self_port()};
    default:
        return {MachTrapDispatchError::unsupported_trap, trap_number, 0};
    }
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
