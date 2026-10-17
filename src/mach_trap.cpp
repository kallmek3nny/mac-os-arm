#include "macosarm/mach_trap.hpp"

#include "macosarm/darwin_syscall.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>

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

[[nodiscard]] std::uint32_t read_u32_le(
    std::span<const std::byte> bytes,
    std::size_t offset) noexcept {

    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + i]))
            << (i * 8);
    }
    return value;
}

void write_u32_le(
    std::span<std::byte> bytes,
    std::size_t offset,
    std::uint32_t value) noexcept {

    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

[[nodiscard]] VmResult write_guest_u32(
    GuestAddressSpace& address_space,
    std::uint64_t address,
    std::uint32_t value) {

    std::array<std::byte, 4> bytes{};
    write_u32_le(bytes, 0, value);
    return address_space.write(address, bytes);
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

[[nodiscard]] MachTrapDispatchResult dispatch_port_deallocate(
    CpuState& state,
    MachContext& context,
    std::int64_t trap_number) noexcept {

    if (!valid_task_target(state, context)) {
        return guest_mach_return(state, trap_number, kMachSendInvalidDest);
    }
    if (state.x[1] > std::numeric_limits<std::uint32_t>::max()) {
        return guest_mach_return(state, trap_number, kMachKernInvalidName);
    }

    const std::uint32_t name = static_cast<std::uint32_t>(state.x[1]);
    if (name != context.host_self_port() || !context.release_host_self_send_right()) {
        return guest_mach_return(state, trap_number, kMachKernInvalidName);
    }
    return guest_mach_return(state, trap_number, kMachKernSuccess);
}

[[nodiscard]] MachTrapDispatchResult dispatch_port_construct(
    CpuState& state,
    GuestAddressSpace& address_space,
    MachContext& context,
    std::int64_t trap_number) {

    if (!valid_task_target(state, context)) {
        return guest_mach_return(state, trap_number, kMachSendInvalidDest);
    }

    std::array<std::byte, kMachPortOptionsSize> options{};
    const VmResult copyin = address_space.read(state.x[1], options);
    if (!copyin) {
        return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
    }

    const std::span<const std::byte> option_bytes{options};
    if (read_u32_le(option_bytes, 0) != kMachPortOptionsReplyPort || state.x[2] != 0) {
        return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
    }
    for (std::size_t index = sizeof(std::uint32_t); index < options.size(); ++index) {
        if (options[index] != std::byte{0}) {
            return guest_mach_return(state, trap_number, kMachKernInvalidArgument);
        }
    }

    // Validate copyout before consuming a synthetic namespace entry. The
    // guest VM is single-threaded here, so writing the original bytes back is
    // a side-effect-free writability check before allocation.
    std::array<std::byte, sizeof(std::uint32_t)> original_name{};
    const VmResult name_read = address_space.read(state.x[3], original_name);
    if (!name_read) {
        return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
    }
    const VmResult name_write_preflight = address_space.write(state.x[3], original_name);
    if (!name_write_preflight) {
        return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
    }

    const auto allocated = context.allocate_reply_port();
    if (!allocated.has_value()) {
        return guest_mach_return(state, trap_number, kMachKernResourceShortage);
    }

    const VmResult copyout = write_guest_u32(address_space, state.x[3], *allocated);
    if (!copyout) {
        (void)context.rollback_reply_port_allocation(*allocated);
        return guest_mach_return(state, trap_number, kMachKernInvalidAddress);
    }

    state.x[0] = kMachKernSuccess;
    return {MachTrapDispatchError::none, trap_number, *allocated};
}

void normalize_simple_message_for_receive(std::vector<std::byte>& message) noexcept {
    std::span<std::byte> bytes{message};
    const std::uint32_t sender_bits = read_u32_le(bytes, 0);
    const std::uint32_t sender_remote_bits = sender_bits & kMachMsgBitsRemoteMask;
    const std::uint32_t sender_local_bits = (sender_bits & kMachMsgBitsLocalMask) >> 8;
    const std::uint32_t other_bits =
        sender_bits & ~(kMachMsgBitsRemoteMask | kMachMsgBitsLocalMask);
    const std::uint32_t received_bits =
        other_bits | sender_local_bits | (sender_remote_bits << 8);

    const std::uint32_t destination_port = read_u32_le(bytes, 8);
    const std::uint32_t reply_port = read_u32_le(bytes, 12);

    write_u32_le(bytes, 0, received_bits);
    write_u32_le(bytes, 4, static_cast<std::uint32_t>(message.size()));
    write_u32_le(bytes, 8, reply_port);
    write_u32_le(bytes, 12, destination_port);
}

constexpr std::size_t kHostInfoRequestSize = 40U;
constexpr std::size_t kHostInfoReplySize = 72U;
constexpr std::uint32_t kHostInfoMessageId = 200U;
constexpr std::uint32_t kHostInfoReplyId = 300U;
constexpr std::uint32_t kHostPriorityInfoFlavor = 5U;
constexpr std::uint32_t kHostPriorityInfoCount = 8U;
constexpr std::uint32_t kMachMsgTypeMoveSendOnce = 18U;
constexpr std::array<std::uint32_t, kHostPriorityInfoCount> kHostPriorityInfoValues{
    80U, // MINPRI_KERNEL
    80U, // MINPRI_KERNEL
    64U, // MINPRI_RESERVED
    31U, // BASEPRI_DEFAULT
    0U,  // DEPRESSPRI
    0U,  // IDLEPRI
    0U,  // MINPRI_USER
    79U, // MAXPRI_RESERVED
};

[[nodiscard]] std::uint32_t dispatch_host_priority_info_request(
    const std::vector<std::byte>& request,
    MachContext& context) {

    if (request.size() != kHostInfoRequestSize) {
        return kMachSendInvalidData;
    }

    const std::span<const std::byte> request_bytes{request};
    if (read_u32_le(request_bytes, 4U) != kHostInfoRequestSize ||
        read_u32_le(request_bytes, 20U) != kHostInfoMessageId ||
        read_u32_le(request_bytes, 32U) != kHostPriorityInfoFlavor ||
        read_u32_le(request_bytes, 36U) < kHostPriorityInfoCount) {
        return kMachSendInvalidData;
    }

    const std::uint32_t reply_port = read_u32_le(request_bytes, 12U);
    if (!context.is_receive_port(reply_port)) {
        return kMachSendInvalidReply;
    }

    std::vector<std::byte> reply(kHostInfoReplySize, std::byte{0});
    std::span<std::byte> reply_bytes{reply};
    write_u32_le(reply_bytes, 0U, kMachMsgTypeMoveSendOnce << 8U);
    write_u32_le(reply_bytes, 4U, static_cast<std::uint32_t>(reply.size()));
    write_u32_le(reply_bytes, 8U, 0U);
    write_u32_le(reply_bytes, 12U, reply_port);
    write_u32_le(reply_bytes, 16U, 0U);
    write_u32_le(reply_bytes, 20U, kHostInfoReplyId);
    for (std::size_t index = 0; index < 8U; ++index) {
        reply[24U + index] = request[24U + index];
    }
    write_u32_le(reply_bytes, 32U, kMachKernSuccess);
    write_u32_le(reply_bytes, 36U, kHostPriorityInfoCount);
    for (std::size_t index = 0; index < kHostPriorityInfoValues.size(); ++index) {
        write_u32_le(reply_bytes, 40U + (index * 4U), kHostPriorityInfoValues[index]);
    }

    if (!context.enqueue_message(reply_port, std::move(reply))) {
        return kMachSendNoBuffer;
    }
    return kMachMsgSuccess;
}

[[nodiscard]] MachTrapDispatchResult dispatch_mach_message(
    CpuState& state,
    GuestAddressSpace& address_space,
    MachContext& context,
    std::int64_t trap_number) {

    const std::uint64_t message_address = state.x[0];
    const std::uint64_t raw_options = state.x[1];
    const std::uint64_t send_size = state.x[2];
    const std::uint64_t receive_size = state.x[3];
    const std::uint64_t raw_receive_name = state.x[4];
    const std::uint64_t notify = state.x[6];

    if (raw_options > std::numeric_limits<std::uint32_t>::max()) {
        return guest_mach_return(state, trap_number, kMachSendInvalidHeader);
    }

    const std::uint32_t options = static_cast<std::uint32_t>(raw_options);
    const bool wants_send = (options & kMachSendMsg) != 0;
    const bool wants_receive = (options & kMachRcvMsg) != 0;

    if (!wants_send && !wants_receive) {
        return guest_mach_return(state, trap_number, kMachSendInvalidHeader);
    }
    if ((options & ~kMachMsgSimpleSupportedOptions) != 0) {
        return guest_mach_return(
            state,
            trap_number,
            wants_send ? kMachSendInvalidHeader : kMachRcvInvalidData);
    }
    if (notify != 0) {
        return guest_mach_return(state, trap_number, kMachSendInvalidNotify);
    }

    if (wants_send) {
        if (send_size < kMachMsgHeaderSize || (send_size & 3U) != 0) {
            return guest_mach_return(state, trap_number, kMachSendMsgTooSmall);
        }
        if (send_size > kMachMsgMaxInlineSize) {
            return guest_mach_return(state, trap_number, kMachSendTooLarge);
        }

        std::vector<std::byte> message(static_cast<std::size_t>(send_size));
        const VmResult copyin = address_space.read(message_address, message);
        if (!copyin) {
            return guest_mach_return(state, trap_number, kMachSendInvalidData);
        }

        const std::span<const std::byte> const_message{message};
        const std::uint32_t bits = read_u32_le(const_message, 0);
        if ((bits & kMachMsgBitsComplex) != 0) {
            return guest_mach_return(state, trap_number, kMachSendInvalidType);
        }

        const std::uint32_t destination_port = read_u32_le(const_message, 8);
        if (destination_port == context.host_self_port()) {
            if (!context.has_host_self_send_right()) {
                return guest_mach_return(state, trap_number, kMachSendInvalidDest);
            }
            const std::uint32_t host_result =
                dispatch_host_priority_info_request(message, context);
            if (host_result != kMachMsgSuccess) {
                return guest_mach_return(state, trap_number, host_result);
            }
        } else {
            if (!context.is_receive_port(destination_port)) {
                return guest_mach_return(state, trap_number, kMachSendInvalidDest);
            }

            normalize_simple_message_for_receive(message);
            if (!context.enqueue_message(destination_port, std::move(message))) {
                return guest_mach_return(state, trap_number, kMachSendNoBuffer);
            }
        }
    }

    if (wants_receive) {
        if (raw_receive_name > std::numeric_limits<std::uint32_t>::max()) {
            return guest_mach_return(state, trap_number, kMachRcvInvalidName);
        }
        const std::uint32_t receive_name = static_cast<std::uint32_t>(raw_receive_name);
        if (!context.is_receive_port(receive_name)) {
            return guest_mach_return(state, trap_number, kMachRcvInvalidName);
        }

        const std::vector<std::byte>* message = context.peek_message(receive_name);
        if (message == nullptr) {
            // The phase-11 transport is intentionally schedulerless. An empty
            // queue returns immediately rather than blocking a host thread.
            return guest_mach_return(state, trap_number, kMachRcvTimedOut);
        }
        if (message->size() > receive_size) {
            return guest_mach_return(state, trap_number, kMachRcvTooLarge);
        }

        const VmResult copyout = address_space.write(message_address, *message);
        if (!copyout) {
            return guest_mach_return(state, trap_number, kMachRcvInvalidData);
        }
        (void)context.pop_message(receive_name);
    }

    return guest_mach_return(state, trap_number, kMachMsgSuccess);
}

} // namespace

bool MachContext::acquire_host_self_send_right() noexcept {
    if (host_self_send_refs_ == std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    ++host_self_send_refs_;
    return true;
}

bool MachContext::release_host_self_send_right() noexcept {
    if (host_self_send_refs_ == 0) {
        return false;
    }
    --host_self_send_refs_;
    return true;
}

std::optional<std::uint32_t> MachContext::allocate_reply_port() {
    if (receive_queues_.size() >= kMaxReplyPorts ||
        next_reply_port_ == 0 ||
        next_reply_port_ == std::numeric_limits<std::uint32_t>::max()) {
        return std::nullopt;
    }

    const std::uint32_t port = next_reply_port_;
    ++next_reply_port_;
    receive_queues_.try_emplace(port);
    return port;
}

bool MachContext::rollback_reply_port_allocation(std::uint32_t port) noexcept {
    if (next_reply_port_ != port + 1U) {
        return false;
    }
    const auto it = receive_queues_.find(port);
    if (it == receive_queues_.end() || !it->second.empty()) {
        return false;
    }
    receive_queues_.erase(it);
    next_reply_port_ = port;
    return true;
}

bool MachContext::is_receive_port(std::uint32_t port) const noexcept {
    return receive_queues_.find(port) != receive_queues_.end();
}

bool MachContext::enqueue_message(std::uint32_t port, std::vector<std::byte> message) {
    auto it = receive_queues_.find(port);
    if (it == receive_queues_.end() || it->second.size() >= kMachMsgMaxQueueDepth) {
        return false;
    }
    it->second.push_back(std::move(message));
    return true;
}

const std::vector<std::byte>* MachContext::peek_message(std::uint32_t port) const noexcept {
    const auto it = receive_queues_.find(port);
    if (it == receive_queues_.end() || it->second.empty()) {
        return nullptr;
    }
    return &it->second.front();
}

bool MachContext::pop_message(std::uint32_t port) noexcept {
    auto it = receive_queues_.find(port);
    if (it == receive_queues_.end() || it->second.empty()) {
        return false;
    }
    it->second.pop_front();
    return true;
}

std::size_t MachContext::queued_message_count(std::uint32_t port) const noexcept {
    const auto it = receive_queues_.find(port);
    return it == receive_queues_.end() ? 0 : it->second.size();
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
    case kMachTrapPortDeallocate:
        return dispatch_port_deallocate(state, context, trap_number);
    case kMachTrapPortConstruct:
        return dispatch_port_construct(state, address_space, context, trap_number);
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
        if (!context.acquire_host_self_send_right()) {
            state.x[0] = 0;
            return {MachTrapDispatchError::none, trap_number, 0};
        }
        state.x[0] = context.host_self_port();
        return {MachTrapDispatchError::none, trap_number, context.host_self_port()};
    case kMachTrapMessage:
        return dispatch_mach_message(state, address_space, context, trap_number);
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
