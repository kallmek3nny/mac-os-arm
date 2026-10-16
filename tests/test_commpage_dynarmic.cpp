#include "macosarm/darwin_commpage.hpp"
#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/session.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

void put_u32(std::vector<std::byte>& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

void put_name(std::vector<std::byte>& bytes, std::size_t offset, std::string_view name) {
    for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
}

std::vector<std::byte> executable_with_libsystem_commpage_probe() {
    constexpr std::uint64_t text_vm = 0x100000000ULL;
    constexpr std::uint64_t entry_file_offset = 0x200ULL;
    constexpr std::uint32_t command_bytes = 72U + 72U + 24U;

    std::vector<std::byte> bytes(0x4000, std::byte{0});
    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12, macosarm::macho::kMhExecute);
    put_u32(bytes, 16, 3U);
    put_u32(bytes, 20, command_bytes);
    put_u32(bytes, 24, 0x00200000U);
    put_u32(bytes, 28, 0U);

    std::size_t command = 32U;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4U, 72U);
    put_name(bytes, command + 8U, "__PAGEZERO");
    put_u64(bytes, command + 24U, 0U);
    put_u64(bytes, command + 32U, text_vm);
    put_u64(bytes, command + 40U, 0U);
    put_u64(bytes, command + 48U, 0U);

    command += 72U;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4U, 72U);
    put_name(bytes, command + 8U, "__TEXT");
    put_u64(bytes, command + 24U, text_vm);
    put_u64(bytes, command + 32U, 0x4000ULL);
    put_u64(bytes, command + 40U, 0U);
    put_u64(bytes, command + 48U, 0x4000ULL);
    put_u32(bytes, command + 56U, 5U);
    put_u32(bytes, command + 60U, 5U);

    command += 72U;
    put_u32(bytes, command, macosarm::macho::kLcMain);
    put_u32(bytes, command + 4U, 24U);
    put_u64(bytes, command + 8U, entry_file_offset);

    std::size_t code = static_cast<std::size_t>(entry_file_offset);
    const std::uint32_t instructions[] = {
        0xd298200aU, // movz x10, #0xc100
        0xf2bfffeaU, // movk x10, #0xffff, lsl #16
        0xf2c001eaU, // movk x10, #0xf, lsl #32 -> data commpage + kdebug offset
        0xb9400149U, // ldr w9, [x10]
        0x35000349U, // cbnz w9, failure
        0x92800370U, // mov x16, #-28 (task_self_trap)
        0xd4001001U, // svc #0x80
        0xd280202bU, // mov x11, #0x101
        0xeb0b001fU, // cmp x0, x11
        0x540002a1U, // b.ne failure
        0x92800330U, // mov x16, #-26 (mach_reply_port)
        0xd4001001U, // svc #0x80
        0xd284000bU, // mov x11, #0x2000
        0xeb0b001fU, // cmp x0, x11
        0x54000201U, // b.ne failure
        0xd28806eaU, // movz x10, #0x4037
        0xf2bfffeaU, // movk x10, #0xffff, lsl #16
        0xf2c001eaU, // movk x10, #0xf, lsl #32 -> RO commpage kernel shift
        0x39400149U, // ldrb w9, [x10]
        0x7100393fU, // cmp w9, #14
        0x54000141U, // b.ne failure
        0xd28804aaU, // movz x10, #0x4025
        0xf2bfffeaU, // movk x10, #0xffff, lsl #16
        0xf2c001eaU, // movk x10, #0xf, lsl #32 -> RO commpage user shift
        0x39400149U, // ldrb w9, [x10]
        0x7100393fU, // cmp w9, #14
        0x54000081U, // b.ne failure
        0xd2800540U, // mov x0, #42
        0xd2800030U, // mov x16, #1 (exit)
        0xd4001001U, // svc #0x80
        0xd2800c60U, // failure: mov x0, #99
        0xd2800030U, // mov x16, #1 (exit)
        0xd4001001U, // svc #0x80
    };
    for (const std::uint32_t instruction : instructions) {
        put_u32(bytes, code, instruction);
        code += 4U;
    }
    return bytes;
}

struct NullHost final : macosarm::DarwinHostServices {
    macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte>) override {
        return {0, 5};
    }
};

} // namespace

int main() {
    const auto file = executable_with_libsystem_commpage_probe();
    NullHost host;
    macosarm::DynarmicBackend backend;
    macosarm::MachContext mach_context;
    macosarm::SessionConfig config{};
    config.instruction_budget = 64;
    config.mach_context = &mach_context;

    const auto result = macosarm::run_macho_session(file, backend, host, config);
    expect(static_cast<bool>(result),
           "real Dynarmic session reaches the early libSystem commpage path");
    expect(result.process.reason == macosarm::ProcessStopReason::exited &&
               result.process.exit_status == 42,
           "translated bootstrap observes task/reply ports and Darwin page shifts");
    expect(result.process.instructions_executed == 30,
           "libSystem commpage probe executes the expected bounded ARM64 path");
    expect(result.final_state.pc == 0x100000278ULL,
           "translated process stops immediately after the success exit SVC");
    expect(result.final_state.x[9] == macosarm::kDarwinCommpagePageShift &&
               result.final_state.x[10] == macosarm::kDarwinCommpageUserPageShift64Address,
           "final state retains the last page-shift commpage probe");
    expect(mach_context.is_receive_port(macosarm::MachContext::kFirstReplyPort),
           "mach_reply_port allocates the first reply port during bootstrap");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "real Dynarmic Darwin commpage bootstrap passed\n";
    return EXIT_SUCCESS;
}
