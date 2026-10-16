#include "macosarm/session.hpp"

#include "macosarm/darwin_commpage.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace macosarm {
namespace {

constexpr std::size_t kProgramVarsStructBytes = 5U * sizeof(std::uint64_t);
constexpr std::size_t kProgramVarsArgcOffset = kProgramVarsStructBytes;
constexpr std::size_t kProgramVarsArgvOffset = 48U;
constexpr std::size_t kProgramVarsEnvpOffset = 56U;
constexpr std::size_t kProgramVarsPrognameOffset = 64U;
constexpr std::size_t kProgramVarsStorageBytes = 80U;
constexpr std::size_t kMainThreadTsdSlots = 10U;
constexpr std::size_t kMainThreadTsdBytes = kMainThreadTsdSlots * sizeof(std::uint64_t);
constexpr std::size_t kMainThreadSelfStorageBytes = 16U;
constexpr std::size_t kMainThreadBootstrapBytes =
    kMainThreadTsdBytes + kMainThreadSelfStorageBytes;
constexpr std::string_view kMainStackAppleKey = "main_stack=";

struct ProgramVarsMaterializationResult {
    bool success{};
    std::uint64_t address{};
    VmError vm_error{VmError::none};
};

struct MainThreadBootstrapMaterializationResult {
    bool success{};
    std::uint64_t tsd_base{};
    std::uint64_t self_address{};
    ProcessStartupError startup_error{ProcessStartupError::none};
    VmError vm_error{VmError::none};
};

void encode_u32(
    std::array<std::byte, kProgramVarsStorageBytes>& bytes,
    std::size_t offset,
    std::uint32_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

void encode_u64(
    std::array<std::byte, kProgramVarsStorageBytes>& bytes,
    std::size_t offset,
    std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

[[nodiscard]] bool has_apple_key(
    std::span<const std::string_view> apple,
    std::string_view key) noexcept {
    for (const std::string_view entry : apple) {
        if (entry.starts_with(key)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool append_hex_u64(std::string& output, std::uint64_t value) {
    std::array<char, 16U> digits{};
    const auto converted = std::to_chars(digits.data(), digits.data() + digits.size(), value, 16);
    if (converted.ec != std::errc{}) {
        return false;
    }
    output.append("0x");
    output.append(digits.data(), converted.ptr);
    return true;
}

[[nodiscard]] std::optional<std::string> make_main_stack_apple_entry(
    std::uint64_t stack_base,
    std::uint64_t stack_size) {
    if (stack_size > std::numeric_limits<std::uint64_t>::max() - stack_base) {
        return std::nullopt;
    }

    const std::uint64_t stack_top = stack_base + stack_size;
    std::string entry{kMainStackAppleKey};
    entry.reserve(96U);
    if (!append_hex_u64(entry, stack_top)) {
        return std::nullopt;
    }
    entry.push_back(',');
    if (!append_hex_u64(entry, stack_size)) {
        return std::nullopt;
    }
    entry.push_back(',');
    if (!append_hex_u64(entry, stack_base)) {
        return std::nullopt;
    }
    entry.push_back(',');
    if (!append_hex_u64(entry, stack_size)) {
        return std::nullopt;
    }
    return entry;
}

[[nodiscard]] ProgramVarsMaterializationResult materialize_program_vars(
    GuestAddressSpace& address_space,
    const ProcessStartupLayout& startup,
    const ProcessStartupConfig& startup_config,
    const LoadedImage& image,
    std::uint64_t stack_base) {
    ProgramVarsMaterializationResult result;

    if (stack_base > std::numeric_limits<std::uint64_t>::max() - kProgramVarsStorageBytes ||
        startup.stack_pointer < stack_base + kProgramVarsStorageBytes ||
        startup.argc > std::numeric_limits<std::uint32_t>::max()) {
        return result;
    }

    std::uint64_t progname = 0;
    if (!startup_config.arguments.empty()) {
        std::array<std::byte, sizeof(std::uint64_t)> argv0_bytes{};
        const VmResult argv0_read = address_space.read(startup.argv, argv0_bytes);
        if (!argv0_read) {
            result.vm_error = argv0_read.error;
            return result;
        }

        std::uint64_t argv0 = 0;
        for (std::size_t index = 0; index < argv0_bytes.size(); ++index) {
            argv0 |= static_cast<std::uint64_t>(
                         std::to_integer<unsigned char>(argv0_bytes[index]))
                     << (index * 8U);
        }

        const std::string_view argument0 = startup_config.arguments.front();
        const std::size_t separator = argument0.find_last_of('/');
        const std::size_t basename_offset =
            separator == std::string_view::npos ? 0U : separator + 1U;
        if (basename_offset > std::numeric_limits<std::uint64_t>::max() - argv0) {
            return result;
        }
        progname = argv0 + static_cast<std::uint64_t>(basename_offset);
    }

    const std::uint64_t argc_slot = stack_base + kProgramVarsArgcOffset;
    const std::uint64_t argv_slot = stack_base + kProgramVarsArgvOffset;
    const std::uint64_t envp_slot = stack_base + kProgramVarsEnvpOffset;
    const std::uint64_t progname_slot = stack_base + kProgramVarsPrognameOffset;

    std::array<std::byte, kProgramVarsStorageBytes> bytes{};
    encode_u64(bytes, 0U, image.preferred_load_address);
    encode_u64(bytes, 8U, argc_slot);
    encode_u64(bytes, 16U, argv_slot);
    encode_u64(bytes, 24U, envp_slot);
    encode_u64(bytes, 32U, progname_slot);
    encode_u32(bytes, kProgramVarsArgcOffset, static_cast<std::uint32_t>(startup.argc));
    encode_u64(bytes, kProgramVarsArgvOffset, startup.argv);
    encode_u64(bytes, kProgramVarsEnvpOffset, startup.envp);
    encode_u64(bytes, kProgramVarsPrognameOffset, progname);

    const VmResult written = address_space.write(stack_base, bytes);
    if (!written) {
        result.vm_error = written.error;
        return result;
    }

    result.success = true;
    result.address = stack_base;
    return result;
}

[[nodiscard]] MainThreadBootstrapMaterializationResult materialize_main_thread_bootstrap(
    GuestAddressSpace& address_space,
    const ProcessStartupLayout& startup,
    std::uint64_t stack_base) {
    MainThreadBootstrapMaterializationResult result;
    constexpr std::uint64_t kProgramVarsBytes =
        static_cast<std::uint64_t>(kProgramVarsStorageBytes);
    constexpr std::uint64_t kBootstrapBytes =
        static_cast<std::uint64_t>(kMainThreadBootstrapBytes);
    constexpr std::uint64_t kTsdBytes = static_cast<std::uint64_t>(kMainThreadTsdBytes);

    if (stack_base > std::numeric_limits<std::uint64_t>::max() - kProgramVarsBytes) {
        result.startup_error = ProcessStartupError::address_overflow;
        return result;
    }
    const std::uint64_t tsd_base = stack_base + kProgramVarsBytes;
    if (tsd_base > std::numeric_limits<std::uint64_t>::max() - kBootstrapBytes) {
        result.startup_error = ProcessStartupError::address_overflow;
        return result;
    }
    const std::uint64_t bootstrap_end = tsd_base + kBootstrapBytes;
    if (startup.stack_pointer < bootstrap_end) {
        result.startup_error = ProcessStartupError::insufficient_stack;
        return result;
    }

    const std::uint64_t self_address = tsd_base + kTsdBytes;
    std::array<std::byte, kMainThreadBootstrapBytes> bytes{};
    for (std::size_t index = 0; index < sizeof(self_address); ++index) {
        bytes[index] = static_cast<std::byte>((self_address >> (index * 8U)) & 0xffU);
    }

    const VmResult written = address_space.write(tsd_base, bytes);
    if (!written) {
        result.startup_error = ProcessStartupError::memory_failure;
        result.vm_error = written.error;
        return result;
    }

    result.success = true;
    result.tsd_base = tsd_base;
    result.self_address = self_address;
    return result;
}

} // namespace

SessionResult run_macho_session(
    std::span<const std::byte> file_bytes,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    const SessionConfig& config) {

    SessionResult result{};
    const macho::ParseResult parsed = macho::parse(file_bytes);
    if (!parsed) {
        result.error = SessionError::parse_failure;
        result.parse_error = parsed.error;
        return result;
    }

    GuestAddressSpace address_space;
    const LoadResult loaded = load_executable(parsed.image, file_bytes, address_space);
    if (!loaded) {
        result.error = SessionError::load_failure;
        result.load_error = loaded.error;
        result.vm_error = loaded.vm_error;
        return result;
    }
    result.image = loaded.image;

    const DarwinCommpageResult commpage = materialize_darwin_commpage(address_space);
    if (!commpage) {
        result.error = SessionError::commpage_failure;
        result.vm_error = commpage.vm_error;
        return result;
    }

    const VmResult stack = address_space.map(
        config.stack_base,
        config.stack_size,
        Protection::read | Protection::write);
    if (!stack) {
        result.error = SessionError::stack_failure;
        result.vm_error = stack.error;
        return result;
    }

    ProcessStartupConfig startup_config = config.startup;
    std::string generated_main_stack;
    std::vector<std::string_view> augmented_apple;
    if (config.dyld.has_value() &&
        !has_apple_key(config.startup.apple, kMainStackAppleKey)) {
        const std::optional<std::string> main_stack = make_main_stack_apple_entry(
            config.stack_base,
            config.stack_size);
        if (!main_stack.has_value()) {
            result.error = SessionError::startup_failure;
            result.startup.error = ProcessStartupError::address_overflow;
            return result;
        }
        generated_main_stack = *main_stack;
        augmented_apple.assign(config.startup.apple.begin(), config.startup.apple.end());
        augmented_apple.emplace_back(generated_main_stack);
        startup_config.apple = augmented_apple;
    }

    result.startup = build_process_startup(
        address_space,
        config.stack_base,
        config.stack_size,
        startup_config);
    if (!result.startup) {
        result.error = SessionError::startup_failure;
        result.vm_error = result.startup.vm_error;
        return result;
    }

    CpuState state{};
    const CpuInitResult initialized = initialize_cpu(
        state,
        loaded.image,
        result.startup.layout.stack_pointer);
    if (!initialized) {
        result.error = SessionError::cpu_init_failure;
        result.cpu_error = initialized.error;
        return result;
    }

    MachContext owned_mach_context;
    MachContext& mach_context =
        config.mach_context != nullptr ? *config.mach_context : owned_mach_context;

    if (config.dyld.has_value()) {
        const SessionDyldBootstrapConfig& dyld_config = *config.dyld;
        if (dyld_config.root_path.empty() ||
            dyld_config.executable_path.empty() ||
            !dyld_config.image_lookup) {
            result.error = SessionError::bootstrap_config_failure;
            return result;
        }

        dyld::ImageGraphBootstrapConfig bootstrap_config = dyld_config.bootstrap;
        if (bootstrap_config.program_vars == 0) {
            const ProgramVarsMaterializationResult program_vars = materialize_program_vars(
                address_space,
                result.startup.layout,
                startup_config,
                loaded.image,
                config.stack_base);
            if (!program_vars.success) {
                result.error = SessionError::program_vars_failure;
                result.vm_error = program_vars.vm_error;
                return result;
            }
            result.program_vars_address = program_vars.address;
            bootstrap_config.program_vars = program_vars.address;
        } else {
            result.program_vars_address = bootstrap_config.program_vars;
        }

        // arm64 libsyscall obtains the TSD base from TPIDRRO_EL0 and libpthread
        // immediately expects slot zero to contain a non-null pthread-self value.
        // Materialize only that stable early-bootstrap contract here. The opaque
        // self storage deliberately does not claim any private pthread_s layout.
        const MainThreadBootstrapMaterializationResult main_thread =
            materialize_main_thread_bootstrap(
                address_space,
                result.startup.layout,
                config.stack_base);
        if (!main_thread.success) {
            result.error = SessionError::startup_failure;
            result.startup.error = main_thread.startup_error;
            result.startup.vm_error = main_thread.vm_error;
            result.vm_error = main_thread.vm_error;
            return result;
        }
        state.tpidrro_el0 = main_thread.tsd_base;

        // The complete session must share one Mach namespace. A nested
        // initializer-only context would reset reply ports before main.
        bootstrap_config.execution.mach_context = &mach_context;
        result.bootstrap = dyld::bootstrap_image_graph(
            parsed.image,
            file_bytes,
            loaded.image,
            dyld_config.root_path,
            dyld_config.executable_path,
            address_space,
            dyld_config.image_lookup,
            result.startup.layout,
            state,
            backend,
            host,
            bootstrap_config);
        if (!result.bootstrap) {
            result.error = SessionError::bootstrap_failure;
            return result;
        }

        // Initializers intentionally leave the CPU at their return sentinel and
        // may mutate every general-purpose register. Restore the executable
        // entry ABI from durable startup state before translated main begins,
        // while preserving the kernel-owned read-only thread pointer register.
        const std::uint64_t tpidrro_el0 = state.tpidrro_el0;
        const CpuInitResult restored = initialize_cpu(
            state,
            loaded.image,
            result.startup.layout.stack_pointer);
        if (!restored) {
            result.error = SessionError::cpu_init_failure;
            result.cpu_error = restored.error;
            return result;
        }
        state.tpidrro_el0 = tpidrro_el0;
    }

    result.process = run_process(
        state,
        address_space,
        backend,
        host,
        mach_context,
        config.instruction_budget);
    result.final_state = state;
    return result;
}

std::string_view session_error_name(SessionError error) noexcept {
    switch (error) {
    case SessionError::none: return "none";
    case SessionError::parse_failure: return "parse_failure";
    case SessionError::load_failure: return "load_failure";
    case SessionError::commpage_failure: return "commpage_failure";
    case SessionError::stack_failure: return "stack_failure";
    case SessionError::startup_failure: return "startup_failure";
    case SessionError::program_vars_failure: return "program_vars_failure";
    case SessionError::cpu_init_failure: return "cpu_init_failure";
    case SessionError::bootstrap_config_failure: return "bootstrap_config_failure";
    case SessionError::bootstrap_failure: return "bootstrap_failure";
    }
    return "unknown";
}

} // namespace macosarm
