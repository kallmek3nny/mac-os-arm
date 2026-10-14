#pragma once

#include "macosarm/execution.hpp"

#include <array>
#include <cstdint>
#include <string_view>

namespace macosarm {

constexpr std::uint32_t kDarwinPstateCarry = 0x20000000U;
constexpr std::uint32_t kDarwinPlatformTrap = 0x80000000U;

enum class DarwinCallClass {
    unix_syscall,
    mach_trap,
    platform_syscall,
};

struct DarwinCall {
    DarwinCallClass call_class{DarwinCallClass::unix_syscall};
    std::uint32_t number{};
    std::uint32_t svc_immediate{};
    bool indirect{};
    std::array<std::uint64_t, 8> arguments{};
};

[[nodiscard]] DarwinCall decode_darwin_svc(
    const CpuState& state,
    std::uint32_t svc_immediate) noexcept;

enum class UnixReturnDisposition {
    success,
    error,
    restart,
    just_return,
};

struct UnixReturn {
    UnixReturnDisposition disposition{UnixReturnDisposition::success};
    std::uint64_t value0{};
    std::uint64_t value1{};
    std::uint32_t error_number{};
};

void apply_unix_return(CpuState& state, const UnixReturn& result) noexcept;
void apply_mach_return(CpuState& state, std::uint64_t kern_return_value) noexcept;

[[nodiscard]] std::string_view darwin_call_class_name(DarwinCallClass value) noexcept;
[[nodiscard]] std::string_view unix_return_disposition_name(UnixReturnDisposition value) noexcept;

} // namespace macosarm
