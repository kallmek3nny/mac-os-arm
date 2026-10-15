#include "macosarm/session.hpp"

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

    const VmResult stack = address_space.map(
        config.stack_base,
        config.stack_size,
        Protection::read | Protection::write);
    if (!stack) {
        result.error = SessionError::stack_failure;
        result.vm_error = stack.error;
        return result;
    }

    CpuState state{};
    const CpuInitResult initialized = initialize_cpu(
        state,
        loaded.image,
        config.stack_base + config.stack_size);
    if (!initialized) {
        result.error = SessionError::cpu_init_failure;
        result.cpu_error = initialized.error;
        return result;
    }

    result.process = run_process(
        state,
        address_space,
        backend,
        host,
        config.instruction_budget);
    result.final_state = state;
    return result;
}

std::string_view session_error_name(SessionError error) noexcept {
    switch (error) {
    case SessionError::none: return "none";
    case SessionError::parse_failure: return "parse_failure";
    case SessionError::load_failure: return "load_failure";
    case SessionError::stack_failure: return "stack_failure";
    case SessionError::cpu_init_failure: return "cpu_init_failure";
    }
    return "unknown";
}

} // namespace macosarm
