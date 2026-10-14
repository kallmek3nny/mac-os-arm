#pragma once

#include "macosarm/address_space.hpp"
#include "macosarm/image_loader.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace macosarm {

struct Vector128 {
    std::uint64_t low{};
    std::uint64_t high{};

    [[nodiscard]] friend constexpr bool operator==(const Vector128&, const Vector128&) = default;
};

struct CpuState {
    std::array<std::uint64_t, 31> x{};
    std::array<Vector128, 32> vectors{};
    std::uint64_t sp{};
    std::uint64_t pc{};
    std::uint32_t pstate{};
    std::uint32_t fpcr{};
    std::uint32_t fpsr{};
};

enum class CpuInitError {
    none,
    unaligned_entry,
    unaligned_stack,
};

struct CpuInitResult {
    CpuInitError error{CpuInitError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == CpuInitError::none;
    }
};

[[nodiscard]] CpuInitResult initialize_cpu(
    CpuState& state,
    const LoadedImage& image,
    std::uint64_t stack_top) noexcept;

[[nodiscard]] VmResult fetch_instruction(
    const GuestAddressSpace& address_space,
    std::uint64_t pc,
    std::uint32_t& instruction) noexcept;

enum class StopReason {
    instruction_budget,
    supervisor_call,
    exception,
    memory_fault,
    backend_error,
};

struct ExecutionResult {
    StopReason reason{StopReason::backend_error};
    std::uint64_t instructions_executed{};
    std::uint32_t supervisor_call{};
    VmError vm_error{VmError::none};
};

class ExecutionBackend {
public:
    virtual ~ExecutionBackend() = default;

    [[nodiscard]] virtual ExecutionResult run(
        CpuState& state,
        GuestAddressSpace& address_space,
        std::uint64_t instruction_budget) = 0;
};

[[nodiscard]] std::string_view cpu_init_error_name(CpuInitError error) noexcept;
[[nodiscard]] std::string_view stop_reason_name(StopReason reason) noexcept;

} // namespace macosarm
