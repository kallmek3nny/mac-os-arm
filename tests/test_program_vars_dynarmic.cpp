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
constexpr std::uint64_t kHostInfoMessageAddress = kDependencyBase + 0x4000ULL;
constexpr std::size_t kHostInfoMessageFileOffset = 0x4000U;
constexpr std::uint64_t kExpectedMainThreadPthreadOffset = 80ULL;
constexpr std::uint64_t kArm64PthreadTsdOffset = 224ULL;
constexpr std::uint64_t kExpectedMainThreadTsdOffset =
    kExpectedMainThreadPthreadOffset + kArm64PthreadTsdOffset;
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
    const std::array<std::uint32_t, 16> instructions{
        0xd53bd069U, // mrs x9, TPIDRRO_EL0
        0xb4000189U, // cbz x9, failure
        0xd103812aU, // sub x10, x9, #224 -> arm64 pthread_self
        0xf940012bU, // ldr x11, [x9] -> direct TSD PTHREAD_SELF slot
        0xeb0a017fU, // cmp x11, x10
        0x54000101U, // b.ne failure
        0xf940014cU, // ldr x12, [x10] -> signature initialized by dependency
        0xeb0a019fU, // cmp x12, x10
        0x540000a1U, // b.ne failure
        0xd10043edU, // sub x13, sp, #16
        0xf94001a0U, // ldr x0, [x13] -> initializer-observed argc
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

std::vector<std::byte> dependency_with_libsystem_startup_probe() {
    std::vector<std::byte> bytes(0x8000, std::byte{0});
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
    put_segment(
        bytes,
        command,
        "__DATA",
        kHostInfoMessageAddress,
        0x4000ULL,
        kHostInfoMessageFileOffset,
        0x4000ULL,
        3U,
        3U);
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

    put_u32(bytes, 16U, 4U);
    put_u32(bytes, 20U, static_cast<std::uint32_t>(command - 32U));

    // Minimal MIG host_info request. Translated code fills in the synthetic
    // host and reply ports before invoking mach_msg. NDR is the arm64 little-
    // endian record: {0, 0, 0, protocol-2.0, little-endian, ASCII, IEEE, 0}.
    constexpr std::uint32_t kCopySend = 19U;
    constexpr std::uint32_t kMakeSendOnce = 21U;
    put_u32(bytes, kHostInfoMessageFileOffset, kCopySend | (kMakeSendOnce << 8U));
    put_u32(bytes, kHostInfoMessageFileOffset + 4U, 40U);
    put_u32(bytes, kHostInfoMessageFileOffset + 20U, 200U);
    put_u32(bytes, kHostInfoMessageFileOffset + 24U, 0U);
    put_u32(bytes, kHostInfoMessageFileOffset + 28U, 1U);
    put_u32(bytes, kHostInfoMessageFileOffset + 32U, 5U); // HOST_PRIORITY_INFO
    put_u32(bytes, kHostInfoMessageFileOffset + 36U, 8U); // HOST_PRIORITY_INFO_COUNT

    std::size_t code = 0x200U;
    const std::array<std::uint32_t, 61> instructions{
        0xf9400489U, // ldr x9, [x4, #8] -> ProgramVars.NXArgcPtr
        0xb940012aU, // ldr w10, [x9] -> argc
        0xf940046cU, // ldr x12, [x3, #8] -> generated main_stack apple entry
        0x52800000U, // mov w0, #0 (failure value)
        0x3940018dU, // ldrb w13, [x12]
        0x7101b5bfU, // cmp w13, #'m'
        0x54000681U, // b.ne failure
        0x39402d8dU, // ldrb w13, [x12, #11]
        0x7100c1bfU, // cmp w13, #'0'
        0x54000621U, // b.ne failure
        0x3940318dU, // ldrb w13, [x12, #12]
        0x7101e1bfU, // cmp w13, #'x'
        0x540005c1U, // b.ne failure
        0xd53bd06eU, // mrs x14, TPIDRRO_EL0
        0xb400058eU, // cbz x14, failure
        0xd10381cfU, // sub x15, x14, #224 -> arm64 _pthread_self_direct()
        0xf94001d0U, // ldr x16, [x14] -> direct TSD PTHREAD_SELF slot
        0xeb0f021fU, // cmp x16, x15
        0x54000501U, // b.ne failure
        0xf90001efU, // str x15, [x15] -> _pthread_init_signature with zero token
        0xf94001f1U, // ldr x17, [x15]
        0xeb0f023fU, // cmp x17, x15
        0x54000481U, // b.ne failure
        0x92800390U, // mov x16, #-29 -> mach_host_self trap
        0xd4001001U, // svc #0x80
        0xb4000420U, // cbz x0, failure
        0xaa0003f2U, // mov x18, x0 -> synthetic host port
        0x92800330U, // mov x16, #-26 -> mach_reply_port trap
        0xd4001001U, // svc #0x80
        0xb40003a0U, // cbz x0, failure
        0xaa0003f3U, // mov x19, x0 -> reply port
        0xd2880014U, // movz x20, #0x4000
        0xf2b20014U, // movk x20, #0x9000, lsl #16
        0xf2c000f4U, // movk x20, #0x7, lsl #32 -> 0x790004000
        0xb9000a92U, // str w18, [x20, #8] -> msgh_remote_port
        0xb9000e93U, // str w19, [x20, #12] -> msgh_local_port
        0xaa1403e0U, // mov x0, x20 -> message address
        0xd2800061U, // mov x1, #3 -> MACH_SEND_MSG | MACH_RCV_MSG
        0xd2800502U, // mov x2, #40 -> request size
        0xd2800903U, // mov x3, #72 -> reply size
        0xaa1303e4U, // mov x4, x19 -> receive name
        0xd2800005U, // mov x5, #0 -> timeout
        0xd2800006U, // mov x6, #0 -> notify
        0x928003d0U, // mov x16, #-31 -> mach_msg trap
        0xd4001001U, // svc #0x80
        0xb50001a0U, // cbnz x0, failure
        0xb9401695U, // ldr w21, [x20, #20] -> reply id
        0x7104b2bfU, // cmp w21, #300
        0x54000141U, // b.ne failure
        0xb9402295U, // ldr w21, [x20, #32] -> MIG RetCode
        0x35000115U, // cbnz w21, failure
        0xb9402695U, // ldr w21, [x20, #36] -> host_info_outCnt
        0x710022bfU, // cmp w21, #8
        0x540000a1U, // b.ne failure
        0xb9403695U, // ldr w21, [x20, #52] -> user_priority
        0x71007ebfU, // cmp w21, #31 (BASEPRI_DEFAULT)
        0x54000041U, // b.ne failure
        0xaa0a03e0U, // mov x0, x10
        0xd10043ebU, // failure: sub x11, sp, #16
        0xf9000160U, // str x0, [x11]
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
    const auto dependency = dependency_with_libsystem_startup_probe();

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
    config.instruction_budget = 20U;
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
    config.dyld->bootstrap.execution.instructions_per_initializer = 80U;
    config.dyld->bootstrap.execution.total_instruction_budget = 80U;

    const auto result = macosarm::run_macho_session(root, backend, host, config);
    expect(static_cast<bool>(result),
           "real Dynarmic session reaches libpthread HOST_PRIORITY_INFO bootstrap");
    expect(result.program_vars_address == config.stack_base,
           "session exposes the generated ProgramVars record at deterministic guest memory");
    expect(result.bootstrap.initialization.execution.instructions_executed == 61U,
           "translated initializer crosses pthread signature and host_info startup contracts");
    expect(result.final_state.tpidrro_el0 ==
               config.stack_base + kExpectedMainThreadTsdOffset,
           "TPIDRRO points at pthread_s::tsd and survives initializer-to-main CPU restoration");
    expect(result.process.reason == macosarm::ProcessStopReason::exited &&
               result.process.exit_status == 2,
           "translated main still observes pthread signature after host_info bootstrap");
    expect(result.process.instructions_executed == 13U,
           "libSystem startup proof preserves the successful arm64 pthread layout path");
    expect(result.final_state.pc == kRootEntry + 52U,
           "libSystem startup proof stops immediately after the successful exit SVC");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "libSystem arm64 HOST_PRIORITY_INFO Dynarmic bootstrap passed\n";
    return EXIT_SUCCESS;
}
