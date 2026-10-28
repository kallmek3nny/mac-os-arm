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

void put_name(std::vector<std::byte>& bytes, std::size_t offset, const std::string& name) {
    for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
}

bool read_u64(
    const macosarm::GuestAddressSpace& address_space,
    std::uint64_t address,
    std::uint64_t& value) {
    std::array<std::byte, sizeof(std::uint64_t)> bytes{};
    if (!address_space.read(address, bytes)) {
        return false;
    }
    value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return true;
}

std::string read_string(
    const macosarm::GuestAddressSpace& address_space,
    std::uint64_t address,
    std::size_t max_bytes = 256) {
    std::string value;
    for (std::size_t index = 0; index < max_bytes; ++index) {
        std::array<std::byte, 1> byte{};
        if (!address_space.read(address + index, byte)) {
            return {};
        }
        const char character = static_cast<char>(std::to_integer<unsigned char>(byte[0]));
        if (character == '\0') {
            return value;
        }
        value.push_back(character);
    }
    return {};
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
    // A segment cannot carry more file bytes than it maps, so an unaligned TEXT
    // vmsize trims the file-backed range to fit. The parser accepts the image
    // and the loader still reports the alignment fault.
    put_u64(bytes, command + 48, text_vm_size < 0x4000ULL ? text_vm_size : 0x4000ULL);
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
        startup_read_ok = read_u64(address_space, state.sp, observed_argc);
        if (startup_read_ok && observed_argc != 0) {
            startup_read_ok = read_u64(address_space, state.sp + 8, observed_argv0);
            if (startup_read_ok) {
                observed_argv0_string = read_string(address_space, observed_argv0);
            }
        }

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
    std::uint64_t observed_argc{};
    std::uint64_t observed_argv0{};
    std::string observed_argv0_string;
    macosarm::VmError code_fetch{macosarm::VmError::none};
    bool saw_svc{};
    bool startup_read_ok{};
};

} // namespace

int main() {
    {
        macosarm::GuestAddressSpace address_space;
        constexpr std::uint64_t base = 0x600000000ULL;
        constexpr std::uint64_t size = macosarm::GuestAddressSpace::kPageSize;
        expect(static_cast<bool>(address_space.map(
                   base,
                   size,
                   macosarm::Protection::read | macosarm::Protection::write)),
               "startup ABI test maps guest stack");

        const std::array<std::string_view, 2> arguments{"/bin/demo", "alpha"};
        const std::array<std::string_view, 2> environment{"A=1", "B=two"};
        const std::array<std::string_view, 1> apple{"executable_path=/bin/demo"};
        macosarm::ProcessStartupConfig startup_config;
        startup_config.arguments = std::span<const std::string_view>(arguments);
        startup_config.environment = std::span<const std::string_view>(environment);
        startup_config.apple = std::span<const std::string_view>(apple);

        const auto startup = macosarm::build_process_startup(
            address_space,
            base,
            size,
            startup_config);
        expect(static_cast<bool>(startup), "darwin startup ABI materializes");
        expect((startup.layout.stack_pointer & 0xfU) == 0,
               "darwin startup stack pointer is 16-byte aligned");
        expect(startup.layout.argc == arguments.size(),
               "darwin startup layout records argc");

        std::uint64_t argc = 0;
        std::uint64_t argv0 = 0;
        std::uint64_t argv1 = 0;
        std::uint64_t argv_null = 1;
        std::uint64_t env0 = 0;
        std::uint64_t env1 = 0;
        std::uint64_t env_null = 1;
        std::uint64_t apple0 = 0;
        std::uint64_t apple_null = 1;
        expect(read_u64(address_space, startup.layout.stack_pointer, argc) && argc == 2,
               "startup stack stores argc at sp");
        expect(read_u64(address_space, startup.layout.argv, argv0) &&
                   read_u64(address_space, startup.layout.argv + 8, argv1) &&
                   read_u64(address_space, startup.layout.argv + 16, argv_null) &&
                   argv_null == 0,
               "startup stack stores null-terminated argv vector");
        expect(read_string(address_space, argv0) == "/bin/demo" &&
                   read_string(address_space, argv1) == "alpha",
               "startup argv pointers reference guest strings in order");
        expect(read_u64(address_space, startup.layout.envp, env0) &&
                   read_u64(address_space, startup.layout.envp + 8, env1) &&
                   read_u64(address_space, startup.layout.envp + 16, env_null) &&
                   env_null == 0 &&
                   read_string(address_space, env0) == "A=1" &&
                   read_string(address_space, env1) == "B=two",
               "startup stack stores null-terminated environment vector");
        expect(read_u64(address_space, startup.layout.apple, apple0) &&
                   read_u64(address_space, startup.layout.apple + 8, apple_null) &&
                   apple_null == 0 &&
                   read_string(address_space, apple0) == "executable_path=/bin/demo",
               "startup stack stores null-terminated apple vector");
    }

    {
        macosarm::GuestAddressSpace address_space;
        constexpr std::uint64_t base = 0x610000000ULL;
        constexpr std::uint64_t size = macosarm::GuestAddressSpace::kPageSize;
        expect(static_cast<bool>(address_space.map(
                   base,
                   size,
                   macosarm::Protection::read | macosarm::Protection::write)),
               "startup failure tests map guest stack");

        const std::string embedded("bad\0value", 9);
        const std::array<std::string_view, 1> bad_argument{
            std::string_view(embedded.data(), embedded.size())};
        macosarm::ProcessStartupConfig bad_config;
        bad_config.arguments = std::span<const std::string_view>(bad_argument);
        const auto bad = macosarm::build_process_startup(
            address_space, base, size, bad_config);
        expect(bad.error == macosarm::ProcessStartupError::embedded_nul,
               "startup rejects embedded NUL strings explicitly");

        const std::array<std::string_view, 2> too_many{"a", "b"};
        macosarm::ProcessStartupConfig bounded_config;
        bounded_config.arguments = std::span<const std::string_view>(too_many);
        bounded_config.max_entries = 1;
        const auto bounded = macosarm::build_process_startup(
            address_space, base, size, bounded_config);
        expect(bounded.error == macosarm::ProcessStartupError::entry_limit,
               "startup entry count is bounded");

        const std::string huge(static_cast<std::size_t>(size), 'x');
        const std::array<std::string_view, 1> huge_argument{huge};
        macosarm::ProcessStartupConfig huge_config;
        huge_config.arguments = std::span<const std::string_view>(huge_argument);
        const auto insufficient = macosarm::build_process_startup(
            address_space, base, size, huge_config);
        expect(insufficient.error == macosarm::ProcessStartupError::insufficient_stack,
               "startup fails closed when strings and pointer table exceed stack");
    }

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
        expect(static_cast<bool>(result.startup) &&
                   backend.observed_sp == result.startup.layout.stack_pointer &&
                   backend.observed_sp < config.stack_base + config.stack_size &&
                   (backend.observed_sp & 0xfU) == 0,
               "CPU starts at materialized aligned Darwin process stack");
        expect(backend.startup_read_ok && backend.observed_argc == 0,
               "default raw session exposes argc zero at initial sp");
        expect(backend.code_fetch == macosarm::VmError::none && backend.saw_svc,
               "backend sees executable bytes loaded from raw Mach-O");
        expect(result.final_state.pc == 0x100000204ULL, "session returns final CPU state");
    }

    {
        const auto file = synthetic_executable();
        InspectingBackend backend;
        NullHost host;
        const std::array<std::string_view, 2> arguments{"demo", "argument"};
        const std::array<std::string_view, 1> environment{"MODE=test"};
        const std::array<std::string_view, 1> apple{"executable_path=demo"};
        macosarm::SessionConfig config{};
        config.startup.arguments = std::span<const std::string_view>(arguments);
        config.startup.environment = std::span<const std::string_view>(environment);
        config.startup.apple = std::span<const std::string_view>(apple);

        const auto result = macosarm::run_macho_session(file, backend, host, config);
        expect(static_cast<bool>(result) && backend.startup_read_ok,
               "session accepts explicit startup vectors");
        expect(backend.observed_argc == 2 && backend.observed_argv0_string == "demo",
               "translated entry sees configured argc and argv on guest stack");
        expect(result.startup.layout.argc == 2 &&
                   result.startup.layout.argv != 0 &&
                   result.startup.layout.envp != 0 &&
                   result.startup.layout.apple != 0,
               "session exposes startup vector addresses for later libSystem bootstrap");
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
        const auto file = synthetic_executable();
        InspectingBackend backend;
        NullHost host;
        const std::string huge(
            static_cast<std::size_t>(macosarm::GuestAddressSpace::kPageSize), 'x');
        const std::array<std::string_view, 1> arguments{huge};
        macosarm::SessionConfig config{};
        config.stack_size = macosarm::GuestAddressSpace::kPageSize;
        config.startup.arguments = std::span<const std::string_view>(arguments);

        const auto result = macosarm::run_macho_session(file, backend, host, config);
        expect(result.error == macosarm::SessionError::startup_failure,
               "session reports process startup construction failure");
        expect(result.startup.error == macosarm::ProcessStartupError::insufficient_stack,
               "session preserves process startup error");
        expect(backend.calls == 0, "startup failure never enters backend");
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

    expect(macosarm::process_startup_error_name(
               macosarm::ProcessStartupError::embedded_nul) == "embedded_nul",
           "process startup errors have stable names");
    expect(macosarm::session_error_name(macosarm::SessionError::startup_failure) ==
               "startup_failure",
           "session startup failure has stable name");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "raw Mach-O session bootstrap tests passed\n";
    return EXIT_SUCCESS;
}
