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
    for (std::size_t index = 0; index < 4U; ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_u64(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t index = 0; index < 8U; ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void put_string(std::vector<std::byte>& bytes, std::size_t offset, std::string_view value) {
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>(static_cast<unsigned char>(value[index]));
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
    put_u32(bytes, command + 4U, 72U);
    put_string(bytes, command + 8U, name);
    put_u64(bytes, command + 24U, vm_address);
    put_u64(bytes, command + 32U, vm_size);
    put_u64(bytes, command + 40U, file_offset);
    put_u64(bytes, command + 48U, file_size);
    put_u32(bytes, command + 56U, max_protection);
    put_u32(bytes, command + 60U, initial_protection);
}

[[nodiscard]] std::size_t put_dylib_command(
    std::vector<std::byte>& bytes,
    std::size_t command,
    std::uint32_t kind,
    std::string_view path) {
    constexpr std::size_t kFixedBytes = 24U;
    const std::size_t command_size = align8(kFixedBytes + path.size() + 1U);
    put_u32(bytes, command, kind);
    put_u32(bytes, command + 4U, static_cast<std::uint32_t>(command_size));
    put_u32(bytes, command + 8U, static_cast<std::uint32_t>(kFixedBytes));
    put_u32(bytes, command + 12U, 0U);
    put_u32(bytes, command + 16U, 0x00010000U);
    put_u32(bytes, command + 20U, 0x00010000U);
    put_string(bytes, command + kFixedBytes, path);
    return command_size;
}

constexpr std::uint64_t kRootBase = 0x100000000ULL;
constexpr std::uint64_t kRootEntry = kRootBase + 0x200ULL;
constexpr std::uint64_t kDependencyBase = 0x790000000ULL;
constexpr std::uint64_t kDependencyInitializer = kDependencyBase + 0x200ULL;
constexpr std::string_view kExecutablePath =
    "/Applications/ProgramVarsProbe.app/Contents/MacOS/ProgramVarsProbe";
constexpr std::string_view kDependencyPath = "/usr/lib/libSystem.B.dylib";

std::vector<std::byte> executable_with_program_vars_probe() {
    std::vector<std::byte> bytes(0x4000, std::byte{0});
    put_u32(bytes, 0U, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4U, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8U, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12U, macosarm::macho::kMhExecute);
    put_u32(bytes, 24U, 0x00200000U);

    std::size_t command = 32U;
    put_segment(bytes, command, "__PAGEZERO", 0U, kRootBase, 0U, 0U, 0U, 0U);
    command += 72U;
    put_segment(bytes, command, "__TEXT", kRootBase, 0x4000ULL, 0U, 0x4000ULL, 5U, 5U);
    command += 72U;
    command += put_dylib_command(
        bytes,
        command,
        macosarm::macho::kLcLoadDylib,
        kDependencyPath);
    put_u32(bytes, command, macosarm::macho::kLcMain);
    put_u32(bytes, command + 4U, 24U);
    put_u64(bytes, command + 8U, 0x200ULL);
    command += 24U;

    put_u32(bytes, 16U, 4U);
    put_u32(bytes, 20U, static_cast<std::uint32_t>(command - 32U));

    std::size_t code = 0x200U;
    const std::array<std::uint32_t, 4> instructions{
        0xd10043eaU, // sub x10, sp, #16
        0xf9400140U, // ldr x0, [x10] -> initializer-observed argc
        0xd2800030U, // mov x16, #1 (exit)
        0xd4001001U, // svc #0x80
    };
    for (const std::uint32_t instruction : instructions) {
        put_u32(bytes, code, instruction);
        code += 4U;
    }
    return bytes;
}

std::vector<std::byte> dependency_with_program_vars_initializer() {
    std::vector<std::byte> bytes(0x4000, std::byte{0});
    put_u32(bytes, 0U, macosarm::macho::kMhMagic64);
    put_u32(bytes, 4U, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(bytes, 8U, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(bytes, 12U, macosarm::macho::kMhDylib);

    std::size_t command = 32U;
    put_segment(
        bytes,
        command,
        "__TEXT",
        kDependencyBase,
        0x4000ULL,
        0U,
        0x4000ULL,
        5U,
        5U);
    command += 72U;
    command += put_dylib_command(
        bytes,
        command,
        macosarm::macho::kLcIdDylib,
        kDependencyPath);
    put_u32(bytes, command, macosarm::macho::kLcRoutines64);
    put_u32(bytes, command + 4U, 72U);
    put_u64(bytes, command + 8U, kDependencyInitializer);
    command += 72U;

    put_u32(bytes, 16U, 3U);
    put_u32(bytes, 20U, static_cast<std::uint32_t>(command - 32U));

    std::size_t code = 0x200U;
    const std::array<std::uint32_t, 5> instructions{
        0xf9400489U, // ldr x9, [x4, #8] -> ProgramVars.NXArgcPtr
        0xb940012aU, // ldr w10, [x9] -> argc
        0xd10043ebU, // sub x11, sp, #16
        0xf900016aU, // str x10, [x11]
        0xd65f03c0U, // ret to initializer sentinel
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
        return {0, 0};
    }
};

} // namespace

int main() {
    const auto root = executable_with_program_vars_probe();
    const auto dependency = dependency_with_program_vars_initializer();

    const std::array<std::string_view, 2> arguments{
        kExecutablePath,
        "probe-argument",
    };
    const std::array<std::string_view, 1> environment{"MODE=program-vars"};
    const std::array<std::string_view, 1> apple{
        "executable_path=/Applications/ProgramVarsProbe.app/Contents/MacOS/ProgramVarsProbe"};

    NullHost host;
    macosarm::DynarmicBackend backend;
    macosarm::SessionConfig config{};
    config.instruction_budget = 16U;
    config.startup.arguments = std::span<const std::string_view>(arguments);
    config.startup.environment = std::span<const std::string_view>(environment);
    config.startup.apple = std::span<const std::string_view>(apple);
    config.dyld.emplace();
    config.dyld->root_path = kExecutablePath;
    config.dyld->executable_path = kExecutablePath;
    config.dyld->image_lookup = [&dependency](std::string_view path) {
        if (path == kDependencyPath) {
            return macosarm::dyld::ImageLookupResult{
                macosarm::dyld::ImageLookupStatus::found,
                dependency};
        }
        return macosarm::dyld::ImageLookupResult{
            macosarm::dyld::ImageLookupStatus::not_found,
            {}};
    };
    config.dyld->bootstrap.execution.instructions_per_initializer = 16U;
    config.dyld->bootstrap.execution.total_instruction_budget = 16U;

    const auto result = macosarm::run_macho_session(root, backend, host, config);
    expect(static_cast<bool>(result),
           "real Dynarmic session materializes the libSystem ProgramVars startup contract");
    expect(result.program_vars_address == config.stack_base,
           "session exposes the generated ProgramVars record at deterministic guest memory");
    expect(result.bootstrap.initialization.execution.instructions_executed == 5U,
           "translated initializer dereferences ProgramVars and returns through the sentinel");
    expect(result.process.reason == macosarm::ProcessStopReason::exited &&
               result.process.exit_status == 2,
           "translated main observes argc loaded through ProgramVars.NXArgcPtr");
    expect(result.process.instructions_executed == 4U,
           "ProgramVars proof executes the four-instruction main path");
    expect(result.final_state.pc == kRootEntry + 16U,
           "ProgramVars proof stops immediately after the exit SVC");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "libSystem ProgramVars Dynarmic bootstrap passed\n";
    return EXIT_SUCCESS;
}
