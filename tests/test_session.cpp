#include "macosarm/session.hpp"

#include <array>
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

std::vector<std::byte> synthetic_executable(
    std::uint64_t entry_file_offset = 0x200,
    std::uint64_t text_vm_size = 0x4000) {
    constexpr std::uint32_t command_bytes = 72 + 72 + 24;
    std::vector<std::byte> bytes(0x4000, std::byte{0});

    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12, macosarm::macho::kMhExecute);
    put_u32(bytes, 16, 3);
    put_u32(bytes, 20, command_bytes);
    put_u32(bytes, 24, 0x00200000U);
    put_u32(bytes, 28, 0);

    std::size_t command = 32;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72);
    put_name(bytes, command + 8, "__PAGEZERO");
    put_u64(bytes, command + 24, 0);
    put_u64(bytes, command + 32, 0x100000000ULL);
    put_u64(bytes, command + 40, 0);
    put_u64(bytes, command + 48, 0);

    command += 72;
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72);
    put_name(bytes, command + 8, "__TEXT");
    put_u64(bytes, command + 24, 0x100000000ULL);
    put_u64(bytes, command + 32, text_vm_size);
    put_u64(bytes, command + 40, 0);
    put_u64(bytes, command + 48, 0x4000);
    put_u32(bytes, command + 56, 5);
    put_u32(bytes, command + 60, 5);

    command += 72;
    put_u32(bytes, command, macosarm::macho::kLcMain);
    put_u32(bytes, command + 4, 24);
    put_u64(bytes, command + 8, entry_file_offset);

    put_u32(bytes, 0x200, 0xd4001001U); // svc #0x80
    return bytes;
}

struct NullHost final : macosarm::DarwinHostServices {
    macosarm::HostWriteResult write(std::int32_t, std::span<const std::byte>) override {
        return {0, 5};
    }
};

class InspectingBackend final : public macosarm::ExecutionBackend {
public:
    macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace& address_space,
        std::uint64_t instruction_budget) override {
        ++calls;
        observed_budget = instruction_budget;
        observed_pc = state.pc;
        observed_sp = state.sp;

        std::array<std::byte, 4> instruction{};
        code_fetch = address_space.fetch_code(state.pc, instruction).error;
        saw_svc = instruction == std::array<std::byte, 4>{
            std::byte{0x01}, std::byte{0x10}, std::byte{0x00}, std::byte{0xd4}};

        state.pc += 4;
        state.x[0] = 23;
        state.x[16] = macosarm::kDarwinSysExit;
        return {
            macosarm::StopReason::supervisor_call,
            1,
            macosarm::kDarwinSvcImmediate,
            macosarm::VmError::none,
        };
    }

    std::size_t calls{};
    std::uint64_t observed_budget{};
    std::uint64_t observed_pc{};
    std::uint64_t observed_sp{};
    macosarm::VmError code_fetch{macosarm::VmError::none};
    bool saw_svc{};
};

} // namespace

int main() {
    {
        const auto file = synthetic_executable();
        InspectingBackend backend;
        NullHost host;
        macosarm::SessionConfig config{};
        config.instruction_budget = 123;

        const auto result = macosarm::run_macho_session(file, backend, host, config);
        expect(static_cast<bool>(result), "valid raw Mach-O session initializes");
        expect(result.process.reason == macosarm::ProcessStopReason::exited,
               "session drives process runner to exit");
        expect(result.process.exit_status == 23, "session preserves guest exit status");
        expect(result.process.instructions_executed == 1, "session reports backend instruction count");
        expect(result.image.entry_address == 0x100000200ULL, "session exposes loaded entry address");
        expect(backend.calls == 1 && backend.observed_budget == 123,
               "session forwards total instruction budget");
        expect(backend.observed_pc == 0x100000200ULL, "CPU starts at parsed LC_MAIN entry");
        expect(backend.observed_sp == config.stack_base + config.stack_size,
               "CPU starts at top of configured guest stack");
        expect(backend.code_fetch == macosarm::VmError::none && backend.saw_svc,
               "backend sees executable bytes loaded from raw Mach-O");
        expect(result.final_state.pc == 0x100000204ULL, "session returns final CPU state");
    }

    {
        auto file = synthetic_executable();
        put_u32(file, 0, 0x12345678U);
        InspectingBackend backend;
        NullHost host;

        const auto result = macosarm::run_macho_session(file, backend, host);
        expect(result.error == macosarm::SessionError::parse_failure,
               "bad Mach-O magic is a session parse failure");
        expect(result.parse_error == macosarm::macho::ErrorCode::bad_magic,
               "session preserves parser error");
        expect(backend.calls == 0, "parse failure never enters backend");
    }

    {
        const auto file = synthetic_executable(0x200, 0x3000);
        InspectingBackend backend;
        NullHost host;

        const auto result = macosarm::run_macho_session(file, backend, host);
        expect(result.error == macosarm::SessionError::load_failure,
               "unaligned TEXT is a session load failure");
        expect(result.load_error == macosarm::LoadError::unaligned_segment,
               "session preserves loader error");
        expect(backend.calls == 0, "load failure never enters backend");
    }

    {
        const auto file = synthetic_executable();
        InspectingBackend backend;
        NullHost host;
        macosarm::SessionConfig config{};
        config.stack_base = 0x100000000ULL;
        config.stack_size = macosarm::GuestAddressSpace::kPageSize;

        const auto result = macosarm::run_macho_session(file, backend, host, config);
        expect(result.error == macosarm::SessionError::stack_failure,
               "stack overlap is a session stack failure");
        expect(result.vm_error == macosarm::VmError::overlap,
               "session preserves stack VM failure");
        expect(backend.calls == 0, "stack failure never enters backend");
    }

    {
        const auto file = synthetic_executable(0x202);
        InspectingBackend backend;
        NullHost host;

        const auto result = macosarm::run_macho_session(file, backend, host);
        expect(result.error == macosarm::SessionError::cpu_init_failure,
               "unaligned entry is a CPU init failure");
        expect(result.cpu_error == macosarm::CpuInitError::unaligned_entry,
               "session preserves CPU init error");
        expect(backend.calls == 0, "CPU init failure never enters backend");
    }

    {
        const auto file = synthetic_executable();
        InspectingBackend backend;
        NullHost host;
        macosarm::SessionConfig config{};
        config.instruction_budget = 0;

        const auto result = macosarm::run_macho_session(file, backend, host, config);
        expect(static_cast<bool>(result), "zero-budget session still initializes successfully");
        expect(result.process.reason == macosarm::ProcessStopReason::instruction_budget,
               "zero-budget session stops before execution");
        expect(backend.calls == 0, "zero-budget session never enters backend");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "raw Mach-O session bootstrap tests passed\n";
    return EXIT_SUCCESS;
}
