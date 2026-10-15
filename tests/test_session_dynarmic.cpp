#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/session.hpp"

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

void put_name(std::vector<std::byte>& bytes, std::size_t offset, const std::string& name) {
    for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
}

std::vector<std::byte> executable_with_write_and_exit() {
    constexpr std::uint64_t text_vm = 0x100000000ULL;
    constexpr std::uint64_t data_vm = 0x100004000ULL;
    constexpr std::uint64_t data_file_offset = 0x4000;
    constexpr std::uint64_t entry_file_offset = 0x200;
    constexpr std::uint32_t command_bytes = 72 + 72 + 72 + 24;

    const std::string message = "hello";
    std::vector<std::byte> bytes(
        static_cast<std::size_t>(data_file_offset) + message.size(),
        std::byte{0});

    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12, macosarm::macho::kMhExecute);
    put_u32(bytes, 16, 4);
    put_u32(bytes, 20, command_bytes);
    put_u32(bytes, 24, 0x00200000U);
    put_u32(bytes, 28, 0);

    std::size_t command = 32;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72);
    put_name(bytes, command + 8, "__PAGEZERO");
    put_u64(bytes, command + 24, 0);
    put_u64(bytes, command + 32, text_vm);
    put_u64(bytes, command + 40, 0);
    put_u64(bytes, command + 48, 0);

    command += 72;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72);
    put_name(bytes, command + 8, "__TEXT");
    put_u64(bytes, command + 24, text_vm);
    put_u64(bytes, command + 32, 0x4000);
    put_u64(bytes, command + 40, 0);
    put_u64(bytes, command + 48, 0x4000);
    put_u32(bytes, command + 56, 5);
    put_u32(bytes, command + 60, 5);

    command += 72;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72);
    put_name(bytes, command + 8, "__DATA");
    put_u64(bytes, command + 24, data_vm);
    put_u64(bytes, command + 32, 0x4000);
    put_u64(bytes, command + 40, data_file_offset);
    put_u64(bytes, command + 48, message.size());
    put_u32(bytes, command + 56, 3);
    put_u32(bytes, command + 60, 3);

    command += 72;
    put_u32(bytes, command, macosarm::macho::kLcMain);
    put_u32(bytes, command + 4, 24);
    put_u64(bytes, command + 8, entry_file_offset);

    std::size_t code = static_cast<std::size_t>(entry_file_offset);
    const std::uint32_t instructions[] = {
        0xd2800020U, // mov x0, #1
        0xd2880001U, // mov x1, #0x4000
        0xf2c00021U, // movk x1, #1, lsl #32 -> 0x100004000
        0xd28000a2U, // mov x2, #5
        0xd2800090U, // mov x16, #4 (write)
        0xd4001001U, // svc #0x80
        0xd28000e0U, // mov x0, #7
        0xd2800030U, // mov x16, #1 (exit)
        0xd4001001U, // svc #0x80
    };
    for (const std::uint32_t instruction : instructions) {
        put_u32(bytes, code, instruction);
        code += 4;
    }

    for (std::size_t i = 0; i < message.size(); ++i) {
        bytes.at(static_cast<std::size_t>(data_file_offset) + i) =
            static_cast<std::byte>(static_cast<unsigned char>(message[i]));
    }
    return bytes;
}

struct CaptureHost final : macosarm::DarwinHostServices {
    std::vector<std::byte> bytes;
    std::int32_t fd{-1};

    macosarm::HostWriteResult write(
        std::int32_t new_fd,
        std::span<const std::byte> data) override {
        fd = new_fd;
        bytes.insert(bytes.end(), data.begin(), data.end());
        return {data.size(), 0};
    }
};

} // namespace

int main() {
    const auto file = executable_with_write_and_exit();
    CaptureHost host;
    macosarm::DynarmicBackend backend;
    macosarm::SessionConfig config{};
    config.instruction_budget = 64;

    const auto result = macosarm::run_macho_session(file, backend, host, config);
    expect(static_cast<bool>(result), "raw ARM64 Mach-O session initializes");
    expect(result.process.reason == macosarm::ProcessStopReason::exited,
           "raw ARM64 Mach-O executes through process exit");
    expect(result.process.exit_status == 7, "raw Mach-O preserves exit status 7");
    expect(result.process.instructions_executed == 9,
           "raw Mach-O executes nine ARM64 instructions across two syscalls");
    expect(result.image.entry_address == 0x100000200ULL,
           "raw Mach-O LC_MAIN becomes the translated entry PC");
    expect(result.final_state.pc == 0x100000224ULL,
           "final PC is immediately after the exit SVC");
    expect(result.final_state.x[16] == macosarm::kDarwinSysExit,
           "final ARM64 syscall register contains exit");

    const std::vector<std::byte> expected{
        std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
    expect(host.fd == 1, "raw Mach-O writes to stdout fd 1");
    expect(host.bytes == expected,
           "raw Mach-O __DATA bytes survive parse/load/JIT and reach host write");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "raw ARM64 Mach-O Dynarmic session passed\n";
    return EXIT_SUCCESS;
}
