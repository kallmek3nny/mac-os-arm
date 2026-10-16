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

void put_name(std::vector<std::byte>& bytes, std::size_t offset, const std::string& name) {
    for (std::size_t i = 0; i < name.size() && i < 16; ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(name[i]));
    }
}

void put_string(std::vector<std::byte>& bytes, std::size_t offset, std::string_view value) {
    for (std::size_t i = 0; i < value.size(); ++i) {
        bytes.at(offset + i) = static_cast<std::byte>(static_cast<unsigned char>(value[i]));
    }
}

[[nodiscard]] std::size_t align8(std::size_t value) noexcept {
    return (value + 7U) & ~std::size_t{7U};
}

void put_segment(
    std::vector<std::byte>& bytes,
    std::size_t command,
    std::string_view name,
    std::uint64_t vm_address,
    std::uint64_t vm_size,
    std::uint64_t file_offset,
    std::uint64_t file_size,
    std::uint32_t max_protection,
    std::uint32_t initial_protection) {
    put_u32(bytes, command, macosarm::macho::kLcSegment64);
    put_u32(bytes, command + 4, 72U);
    put_string(bytes, command + 8, name);
    put_u64(bytes, command + 24, vm_address);
    put_u64(bytes, command + 32, vm_size);
    put_u64(bytes, command + 40, file_offset);
    put_u64(bytes, command + 48, file_size);
    put_u32(bytes, command + 56, max_protection);
    put_u32(bytes, command + 60, initial_protection);
}

[[nodiscard]] std::size_t put_dylib_command(
    std::vector<std::byte>& bytes,
    std::size_t command,
    std::uint32_t kind,
    std::string_view path) {
    constexpr std::size_t kFixedSize = 24U;
    const std::size_t command_size = align8(kFixedSize + path.size() + 1U);
    put_u32(bytes, command, kind);
    put_u32(bytes, command + 4, static_cast<std::uint32_t>(command_size));
    put_u32(bytes, command + 8, static_cast<std::uint32_t>(kFixedSize));
    put_u32(bytes, command + 12, 0U);
    put_u32(bytes, command + 16, 0x00010000U);
    put_u32(bytes, command + 20, 0x00010000U);
    put_string(bytes, command + kFixedSize, path);
    return command_size;
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

constexpr std::uint64_t kBootstrapRootBase = 0x100000000ULL;
constexpr std::uint64_t kBootstrapEntry = kBootstrapRootBase + 0x200ULL;
constexpr std::uint64_t kBootstrapDependencyBase = 0x790000000ULL;
constexpr std::uint64_t kBootstrapInitializer = kBootstrapDependencyBase + 0x200ULL;
constexpr std::string_view kBootstrapExecutable =
    "/Applications/Dynarmic.app/Contents/MacOS/Dynarmic";
constexpr std::string_view kBootstrapDependency = "/usr/lib/libSystem.B.dylib";

std::vector<std::byte> executable_with_dependency_bootstrap() {
    std::vector<std::byte> bytes(0x4000, std::byte{0});
    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12, macosarm::macho::kMhExecute);
    put_u32(bytes, 24, 0x00200000U);

    std::size_t command = 32U;
    put_segment(
        bytes,
        command,
        "__PAGEZERO",
        0,
        kBootstrapRootBase,
        0,
        0,
        0,
        0);
    command += 72U;
    put_segment(
        bytes,
        command,
        "__TEXT",
        kBootstrapRootBase,
        0x4000ULL,
        0,
        0x4000ULL,
        5U,
        5U);
    command += 72U;
    command += put_dylib_command(
        bytes,
        command,
        macosarm::macho::kLcLoadDylib,
        kBootstrapDependency);
    put_u32(bytes, command, macosarm::macho::kLcMain);
    put_u32(bytes, command + 4U, 24U);
    put_u64(bytes, command + 8U, 0x200ULL);
    command += 24U;

    put_u32(bytes, 16, 4U);
    put_u32(bytes, 20, static_cast<std::uint32_t>(command - 32U));

    std::size_t code = 0x200U;
    const std::uint32_t instructions[] = {
        0xb50000a0U, // cbnz x0, failure; proves initialize_cpu reset after initializers
        0xd10043eaU, // sub x10, sp, #16
        0xf9400140U, // ldr x0, [x10] -> durable initializer marker
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

std::vector<std::byte> dependency_with_initializer() {
    std::vector<std::byte> bytes(0x4000, std::byte{0});
    put_u32(bytes, 0, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12, macosarm::macho::kMhDylib);

    std::size_t command = 32U;
    put_segment(
        bytes,
        command,
        "__TEXT",
        kBootstrapDependencyBase,
        0x4000ULL,
        0,
        0x4000ULL,
        5U,
        5U);
    command += 72U;
    command += put_dylib_command(
        bytes,
        command,
        macosarm::macho::kLcIdDylib,
        kBootstrapDependency);
    put_u32(bytes, command, macosarm::macho::kLcRoutines64);
    put_u32(bytes, command + 4U, 72U);
    put_u64(bytes, command + 8U, kBootstrapInitializer);
    put_u64(bytes, command + 16U, 0x44ULL);
    command += 72U;

    put_u32(bytes, 16, 3U);
    put_u32(bytes, 20, static_cast<std::uint32_t>(command - 32U));

    std::size_t code = 0x200U;
    const std::uint32_t instructions[] = {
        0xd2800c60U, // mov x0, #99; must not leak into process entry
        0xd2800549U, // mov x9, #42
        0xd10043eaU, // sub x10, sp, #16
        0xf9000149U, // str x9, [x10]
        0xd65f03c0U, // ret to initializer sentinel
    };
    for (const std::uint32_t instruction : instructions) {
        put_u32(bytes, code, instruction);
        code += 4U;
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
    {
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
    }

    {
        auto file = executable_with_write_and_exit();
        constexpr std::size_t entry = 0x200;
        put_u32(file, entry, 0xf94003e0U);     // ldr x0, [sp] -> argc
        put_u32(file, entry + 4, 0xd2800030U); // mov x16, #1 (exit)
        put_u32(file, entry + 8, 0xd4001001U); // svc #0x80

        const std::array<std::string_view, 3> arguments{"demo", "one", "two"};
        const std::array<std::string_view, 1> environment{"MODE=dynarmic"};
        const std::array<std::string_view, 1> apple{"executable_path=demo"};
        CaptureHost host;
        macosarm::DynarmicBackend backend;
        macosarm::SessionConfig config{};
        config.instruction_budget = 16;
        config.startup.arguments = std::span<const std::string_view>(arguments);
        config.startup.environment = std::span<const std::string_view>(environment);
        config.startup.apple = std::span<const std::string_view>(apple);

        const auto result = macosarm::run_macho_session(file, backend, host, config);
        expect(static_cast<bool>(result),
               "real Dynarmic session accepts materialized Darwin startup stack");
        expect(result.process.reason == macosarm::ProcessStopReason::exited &&
                   result.process.exit_status == 3,
               "real Dynarmic guest loads argc directly from initial sp");
        expect(result.process.instructions_executed == 3,
               "argc startup probe executes exactly three ARM64 instructions");
        expect(result.startup.layout.argc == 3 &&
                   result.final_state.sp == result.startup.layout.stack_pointer,
               "real Dynarmic preserves materialized startup stack pointer");
        expect(result.final_state.pc == 0x10000020cULL,
               "argc startup probe stops immediately after exit SVC");
    }

    {
        const auto root = executable_with_dependency_bootstrap();
        const auto dependency = dependency_with_initializer();
        CaptureHost host;
        macosarm::DynarmicBackend backend;
        macosarm::SessionConfig config{};
        config.instruction_budget = 32;
        config.dyld.emplace();
        config.dyld->root_path = kBootstrapExecutable;
        config.dyld->executable_path = kBootstrapExecutable;
        config.dyld->image_lookup = [&dependency](std::string_view path) {
            if (path == kBootstrapDependency) {
                return macosarm::dyld::ImageLookupResult{
                    macosarm::dyld::ImageLookupStatus::found,
                    dependency};
            }
            return macosarm::dyld::ImageLookupResult{
                macosarm::dyld::ImageLookupStatus::not_found,
                {}};
        };
        config.dyld->bootstrap.execution.instructions_per_initializer = 16;
        config.dyld->bootstrap.execution.total_instruction_budget = 16;

        const auto result = macosarm::run_macho_session(root, backend, host, config);
        expect(static_cast<bool>(result),
               "real Dynarmic session completes dependency bootstrap and process execution");
        expect(static_cast<bool>(result.bootstrap) &&
                   result.bootstrap.loading.graph.images.size() == 2,
               "real Dynarmic session loads root plus libSystem-style dependency");
        expect(result.bootstrap.initialization.planning.plan.calls.size() == 1 &&
                   result.bootstrap.initialization.planning.plan.calls.front().address ==
                       kBootstrapInitializer,
               "real Dynarmic session plans dependency initializer at mapped target");
        expect(result.bootstrap.initialization.execution.instructions_executed == 5,
               "real Dynarmic executes five ARM64 dependency-initializer instructions");
        expect(result.process.reason == macosarm::ProcessStopReason::exited &&
                   result.process.exit_status == 42,
               "restored main observes initializer memory and not dirty initializer x0");
        expect(result.process.instructions_executed == 5,
               "restored main follows clean-entry path for exactly five ARM64 instructions");
        expect(result.final_state.pc == kBootstrapEntry + 20U &&
                   result.final_state.x[0] == 42,
               "real Dynarmic process stops immediately after marker-backed exit SVC");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "raw ARM64 Mach-O Dynarmic session passed\n";
    return EXIT_SUCCESS;
}
