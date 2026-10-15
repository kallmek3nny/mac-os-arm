#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/mach_trap.hpp"
#include "macosarm/process.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

void put_instruction(
    std::array<std::byte, macosarm::GuestAddressSpace::kPageSize>& page,
    std::size_t offset,
    std::uint32_t instruction) {
    for (std::size_t i = 0; i < 4; ++i) {
        page.at(offset + i) = static_cast<std::byte>((instruction >> (i * 8)) & 0xffU);
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

struct NullHost final : macosarm::DarwinHostServices {
    macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> data) override {
        return {data.size(), 0};
    }
};

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;

    constexpr std::uint64_t code_base = 0x100000000ULL;
    constexpr std::uint64_t message_base = 0x200000000ULL;

    GuestAddressSpace vm;
    expect(static_cast<bool>(vm.map(
               code_base,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::execute)),
           "JIT Mach message code page maps");
    expect(static_cast<bool>(vm.map(
               message_base,
               GuestAddressSpace::kPageSize,
               Protection::read | Protection::write)),
           "JIT Mach message data page maps");

    std::array<std::byte, GuestAddressSpace::kPageSize> code{};
    put_instruction(code, 0, 0x92800330U);  // movn x16, #25 => -26 mach_reply_port
    put_instruction(code, 4, 0xd4001001U);  // svc #0x80
    put_instruction(code, 8, 0xaa0003f4U);  // mov x20, x0 (reply port)
    put_instruction(code, 12, 0xaa1303e0U); // mov x0, x19 (message pointer)
    put_instruction(code, 16, 0x928003d0U); // movn x16, #30 => -31 mach_msg_trap
    put_instruction(code, 20, 0xd4001001U); // svc #0x80
    put_instruction(code, 24, 0xaa0003f5U); // mov x21, x0 (mach_msg return)
    put_instruction(code, 28, 0xd2800000U); // mov x0, #0
    put_instruction(code, 32, 0xd2800030U); // mov x16, #1 (exit)
    put_instruction(code, 36, 0xd4001001U); // svc #0x80
    expect(static_cast<bool>(vm.load_bytes(code_base, code)), "JIT Mach message program loads");

    std::array<std::byte, 32> message{};
    put_u32(message, 0, 19U); // simple remote COPY_SEND disposition
    put_u32(message, 4, static_cast<std::uint32_t>(message.size()));
    put_u32(message, 8, macosarm::MachContext::kFirstReplyPort);
    put_u32(message, 12, 0);
    put_u32(message, 16, 0);
    put_u32(message, 20, 0x4142U);
    message[24] = std::byte{'j'};
    message[25] = std::byte{'i'};
    message[26] = std::byte{'t'};
    message[27] = std::byte{'!'};
    expect(static_cast<bool>(vm.write(message_base, message)), "JIT Mach message payload loads");

    macosarm::CpuState state{};
    state.pc = code_base;
    state.sp = 0x700000000ULL;
    state.x[19] = message_base;
    state.x[1] = macosarm::kMachSendMsg | macosarm::kMachRcvMsg;
    state.x[2] = message.size();
    state.x[3] = message.size();
    state.x[4] = macosarm::MachContext::kFirstReplyPort;
    state.x[5] = 0;
    state.x[6] = 0;

    NullHost host;
    macosarm::DynarmicBackend backend;
    const auto result = macosarm::run_process(state, vm, backend, host, 32);

    expect(result.reason == macosarm::ProcessStopReason::exited,
           "real JIT resumes after mach_msg and exits through BSD");
    expect(result.exit_status == 0, "Mach message JIT program exits cleanly");
    expect(result.instructions_executed == 10,
           "Mach message path accounts for every translated instruction");
    expect(state.x[20] == macosarm::MachContext::kFirstReplyPort,
           "translated guest observes deterministic reply port");
    expect(state.x[21] == macosarm::kMachMsgSuccess,
           "translated guest observes MACH_MSG_SUCCESS");
    expect(state.pc == code_base + 40, "JIT PC advances past final BSD SVC");

    std::array<std::byte, 32> received{};
    expect(static_cast<bool>(vm.read(message_base, received)), "JIT receive buffer is readable");
    expect(get_u32(received, 4) == received.size(), "JIT received header preserves message size");
    expect(get_u32(received, 8) == 0, "JIT receive remote port is original reply port");
    expect(get_u32(received, 12) == macosarm::MachContext::kFirstReplyPort,
           "JIT receive local port is original destination");
    expect((get_u32(received, 0) & macosarm::kMachMsgBitsLocalMask) == (19U << 8),
           "JIT receive swaps disposition bits into local field");
    expect(received[24] == std::byte{'j'} && received[27] == std::byte{'!'},
           "JIT Mach transport preserves inline payload");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Dynarmic Mach message transport test passed\n";
    return EXIT_SUCCESS;
}
