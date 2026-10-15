#pragma once

#include "macosarm/execution.hpp"
#include "macosarm/image_loader.hpp"
#include "macosarm/macho.hpp"
#include "macosarm/process.hpp"
#include "macosarm/process_startup.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace macosarm {

struct SessionConfig {
    std::uint64_t stack_base{0x700000000ULL};
    std::uint64_t stack_size{8ULL * 1024ULL * 1024ULL};
    std::uint64_t instruction_budget{1'000'000ULL};
    ProcessStartupConfig startup{};
};

enum class SessionError {
    none,
    parse_failure,
    load_failure,
    stack_failure,
    startup_failure,
    cpu_init_failure,
};

struct SessionResult {
    SessionError error{SessionError::none};
    macho::ErrorCode parse_error{macho::ErrorCode::none};
    LoadError load_error{LoadError::none};
    VmError vm_error{VmError::none};
    CpuInitError cpu_error{CpuInitError::none};
    ProcessStartupResult startup{};
    LoadedImage image{};
    CpuState final_state{};
    ProcessResult process{};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == SessionError::none;
    }
};

[[nodiscard]] SessionResult run_macho_session(
    std::span<const std::byte> file_bytes,
    ExecutionBackend& backend,
    DarwinHostServices& host,
    const SessionConfig& config = {});

[[nodiscard]] std::string_view session_error_name(SessionError error) noexcept;

} // namespace macosarm
