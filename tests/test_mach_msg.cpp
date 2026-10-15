#include "macosarm/mach_trap.hpp"

#include "macosarm/darwin_syscall.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

void put_u32(std::span<std::byte> bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

std::uint32_t get_u32(std::span<const std::byte> bytes, std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + i]))
            << (i * 8);
    }
    return value;
}

macosarm::ExecutionResult svc() {
    return {
        macosarm::StopReason::supervisor_call,
        1,
        macosarm::kDarwinSvcImmediate,
        macosarm::VmError::none,
    };
}

void set_mach_msg_trap(macosarm::CpuState& state) {
    state.x[16] = std::bit_cast<std::uint64_t>(macosarm::kMachTrapMessage);
}

std::array<std::byte, 32> make_message(
    std::uint32_t destination,
    std::uint32_t reply,
    std::uint32_t bits = 19U,
    std::uint32_t id = 0x1234U) {

    std::array<std::byte, 32> message{};
    put_u32(message, 0, bits);
    put_u32(message, 4, static_cast<std::uint32_t>(message.size()));
    put_u32(message, 8, destination);
    put_u32(message, 12, reply);
    put_u32(message, 16, 0);
    put_u32(message, 20, id);
    message[24] = std::byte{'p'};
    message[25] = std::byte{'i'};
    message[26] = std::byte{'n'};
    message[27] = std::byte{'g'};
    return message;
}

void configure_trap(
    macosarm::CpuState& state,
    std::uint64_t message_address,
    std::uint32_t options,
    std::uint64_t send_size,
    std::uint64_t receive_size,
    std::uint32_t receive_name) {

    state.x[0] = message_address;
    state.x[1] = options;
    state.x[2] = send_size;
    state.x[3] = receive_size;
    state.x[4] = receive_name;
    state.x[5] = 0;
    state.x[6] = 0;
    set_mach_msg_trap(state);
}

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;

    constexpr std::uint64_t buffer_base = 0x400000000ULL;
    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(
               buffer_base,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::write)),
           "message buffer maps RW");

    macosarm::MachContext context;
    const auto receive_port = context.allocate_reply_port();
    expect(receive_port.has_value(), "reply port allocation succeeds");
    if (!receive_port.has_value()) {
        return EXIT_FAILURE;
    }
    expect(context.is_receive_port(*receive_port), "reply port owns a receive queue");

    {
        auto message = make_message(*receive_port, 0);
        expect(static_cast<bool>(vm.write(buffer_base, message)), "loopback message loads");

        macosarm::CpuState state{};
        configure_trap(
            state,
            buffer_base,
            macosarm::kMachSendMsg | macosarm::kMachRcvMsg,
            message.size(),
            message.size(),
            *receive_port);

        const auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result), "send+receive trap is handled");
        expect(state.x[0] == macosarm::kMachMsgSuccess, "send+receive returns MACH_MSG_SUCCESS");
        expect(context.queued_message_count(*receive_port) == 0,
               "send+receive consumes the queued message");

        std::array<std::byte, 32> received{};
        expect(static_cast<bool>(vm.read(buffer_base, received)), "loopback result is readable");
        expect(get_u32(received, 4) == received.size(), "received header carries exact message size");
        expect(get_u32(received, 8) == 0, "sender reply port becomes received remote port");
        expect(get_u32(received, 12) == *receive_port,
               "sender destination becomes received local port");
        expect((get_u32(received, 0) & macosarm::kMachMsgBitsLocalMask) == (19U << 8),
               "remote disposition moves to received local bits");
        expect(received[24] == std::byte{'p'} && received[27] == std::byte{'g'},
               "inline payload survives transport");
    }

    {
        auto message = make_message(*receive_port, 0, 19U, 0x2222U);
        expect(static_cast<bool>(vm.write(buffer_base, message)), "queued message loads");

        macosarm::CpuState state{};
        configure_trap(
            state,
            buffer_base,
            macosarm::kMachSendMsg,
            message.size(),
            0,
            0);
        auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachMsgSuccess,
               "send-only trap queues a message");
        expect(context.queued_message_count(*receive_port) == 1,
               "send-only leaves one queued message");

        configure_trap(
            state,
            buffer_base,
            macosarm::kMachRcvMsg,
            0,
            24,
            *receive_port);
        result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachRcvTooLarge,
               "too-small receive reports MACH_RCV_TOO_LARGE");
        expect(context.queued_message_count(*receive_port) == 1,
               "too-small receive does not drop the message");

        configure_trap(
            state,
            buffer_base,
            macosarm::kMachRcvMsg,
            0,
            message.size(),
            *receive_port);
        result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachMsgSuccess,
               "retry with enough room receives queued message");
        expect(context.queued_message_count(*receive_port) == 0,
               "successful retry drains queue");
    }

    {
        auto complex = make_message(
            *receive_port,
            0,
            macosarm::kMachMsgBitsComplex | 19U,
            0x3333U);
        expect(static_cast<bool>(vm.write(buffer_base, complex)), "complex test message loads");

        macosarm::CpuState state{};
        configure_trap(
            state,
            buffer_base,
            macosarm::kMachSendMsg,
            complex.size(),
            0,
            0);
        const auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachSendInvalidType,
               "complex message is rejected until descriptors are implemented");
        expect(context.queued_message_count(*receive_port) == 0,
               "rejected complex message never reaches queue");
    }

    {
        auto invalid_destination = make_message(0xdeadU, 0);
        expect(static_cast<bool>(vm.write(buffer_base, invalid_destination)),
               "invalid-destination message loads");

        macosarm::CpuState state{};
        configure_trap(
            state,
            buffer_base,
            macosarm::kMachSendMsg,
            invalid_destination.size(),
            0,
            0);
        const auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachSendInvalidDest,
               "unknown destination returns MACH_SEND_INVALID_DEST");
    }

    {
        macosarm::CpuState state{};
        configure_trap(state, buffer_base, macosarm::kMachSendMsg, 20, 0, 0);
        auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachSendMsgTooSmall,
               "sub-header send is rejected before guest copyin");

        configure_trap(
            state,
            buffer_base,
            macosarm::kMachSendMsg,
            macosarm::kMachMsgMaxInlineSize + 4,
            0,
            0);
        result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachSendTooLarge,
               "over-cap send is rejected before allocation");

        configure_trap(state, 0xdead00000000ULL, macosarm::kMachSendMsg, 24, 0, 0);
        result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachSendInvalidData,
               "unmapped send buffer reports invalid data");
    }

    {
        macosarm::CpuState state{};
        configure_trap(state, buffer_base, macosarm::kMachRcvMsg, 0, 32, 0xbeefU);
        auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachRcvInvalidName,
               "receive from unknown port reports invalid name");

        configure_trap(state, buffer_base, macosarm::kMachRcvMsg, 0, 32, *receive_port);
        result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachRcvTimedOut,
               "empty schedulerless queue returns immediately as timed out");
    }

    {
        const auto readonly_port = context.allocate_reply_port();
        expect(readonly_port.has_value(), "copyout test reply port allocates");
        if (readonly_port.has_value()) {
            auto message = make_message(*readonly_port, 0);
            std::vector<std::byte> queued(message.begin(), message.end());
            expect(context.enqueue_message(*readonly_port, std::move(queued)),
                   "copyout test queues message directly");

            constexpr std::uint64_t readonly_base = buffer_base + GuestAddressSpace::kPageSize;
            expect(static_cast<bool>(vm.map(
                       readonly_base,
                       GuestAddressSpace::kPageSize,
                       Protection::read)),
                   "read-only receive page maps");

            macosarm::CpuState state{};
            configure_trap(
                state,
                readonly_base,
                macosarm::kMachRcvMsg,
                0,
                message.size(),
                *readonly_port);
            const auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
            expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachRcvInvalidData,
                   "failed receive copyout reports invalid data");
            expect(context.queued_message_count(*readonly_port) == 1,
                   "failed receive copyout keeps message queued");
        }
    }

    {
        const auto capped_port = context.allocate_reply_port();
        expect(capped_port.has_value(), "queue-cap test reply port allocates");
        if (capped_port.has_value()) {
            for (std::size_t i = 0; i < macosarm::kMachMsgMaxQueueDepth; ++i) {
                expect(context.enqueue_message(*capped_port, std::vector<std::byte>(24)),
                       "queue accepts message below hard depth cap");
            }
            expect(!context.enqueue_message(*capped_port, std::vector<std::byte>(24)),
                   "queue rejects message beyond hard depth cap");
        }
    }

    {
        macosarm::MachContext capped_context;
        for (std::size_t i = 0; i < macosarm::MachContext::kMaxReplyPorts; ++i) {
            expect(capped_context.allocate_reply_port().has_value(),
                   "reply-port namespace accepts entry below hard cap");
        }
        expect(!capped_context.allocate_reply_port().has_value(),
               "reply-port namespace refuses allocation beyond hard cap");
    }

    {
        macosarm::CpuState state{};
        configure_trap(state, buffer_base, macosarm::kMachSendMsg | 0x4U, 32, 0, 0);
        auto result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachSendInvalidHeader,
               "unsupported Mach option bits fail explicitly");

        configure_trap(state, buffer_base, macosarm::kMachSendMsg, 32, 0, 0);
        state.x[6] = 7;
        result = macosarm::dispatch_mach_trap(state, vm, svc(), context);
        expect(static_cast<bool>(result) && state.x[0] == macosarm::kMachSendInvalidNotify,
               "unsupported notify port fails explicitly");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "simple Mach message transport tests passed\n";
    return EXIT_SUCCESS;
}
