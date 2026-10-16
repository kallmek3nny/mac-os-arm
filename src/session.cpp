#include "macosarm/session.hpp"

#include "macosarm/darwin_commpage.hpp"

namespace macosarm {

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

    result.startup = build_process_startup(
        address_space,
        config.stack_base,
        config.stack_size,
        config.startup);
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
        // entry ABI from durable startup state before translated main begins.
        const CpuInitResult restored = initialize_cpu(
            state,
            loaded.image,
            result.startup.layout.stack_pointer);
        if (!restored) {
            result.error = SessionError::cpu_init_failure;
            result.cpu_error = restored.error;
            return result;
        }
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
    case SessionError::cpu_init_failure: return "cpu_init_failure";
    case SessionError::bootstrap_config_failure: return "bootstrap_config_failure";
    case SessionError::bootstrap_failure: return "bootstrap_failure";
    }
    return "unknown";
}

} // namespace macosarm
