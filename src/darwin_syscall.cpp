#include "macosarm/darwin_syscall.hpp"

#include <cstddef>
#include <cstdint>

namespace macosarm {

DarwinCall decode_darwin_svc(const CpuState& state, std::uint32_t svc_immediate) noexcept {
    DarwinCall result;
    result.svc_immediate = svc_immediate;

    const std::uint32_t raw_selector = static_cast<std::uint32_t>(state.x[16]);
    const std::int32_t selector = static_cast<std::int32_t>(raw_selector);

    if (raw_selector == kDarwinPlatformTrap) {
        result.call_class = DarwinCallClass::platform_syscall;
        result.number = raw_selector;
        for (std::size_t i = 0; i < result.arguments.size(); ++i) {
            result.arguments[i] = state.x[i];
        }
        return result;
    }

    if (selector < 0) {
        result.call_class = DarwinCallClass::mach_trap;
        result.number = static_cast<std::uint32_t>(-static_cast<std::int64_t>(selector));
        for (std::size_t i = 0; i < result.arguments.size(); ++i) {
            result.arguments[i] = state.x[i];
        }
        return result;
    }

    result.call_class = DarwinCallClass::unix_syscall;
    result.indirect = raw_selector == 0;

    // XNU narrows the unix syscall number to the unsigned-short sysent index.
    // With x16 == 0, x0 contains the real number and arguments shift by one.
    const std::uint64_t syscall_source = result.indirect ? state.x[0] : state.x[16];
    result.number = static_cast<std::uint16_t>(syscall_source);

    const std::size_t argument_offset = result.indirect ? 1 : 0;
    for (std::size_t i = 0; i < result.arguments.size(); ++i) {
        result.arguments[i] = state.x[i + argument_offset];
    }
    return result;
}

void apply_unix_return(CpuState& state, const UnixReturn& result) noexcept {
    switch (result.disposition) {
    case UnixReturnDisposition::success:
        state.x[0] = result.value0;
        state.x[1] = result.value1;
        state.pstate &= ~kDarwinPstateCarry;
        break;
    case UnixReturnDisposition::error:
        state.x[0] = result.error_number;
        state.x[1] = 0;
        state.pstate |= kDarwinPstateCarry;
        break;
    case UnixReturnDisposition::restart:
        state.pc -= 4;
        break;
    case UnixReturnDisposition::just_return:
        break;
    }
}

void apply_mach_return(CpuState& state, std::uint64_t kern_return_value) noexcept {
    state.x[0] = kern_return_value;
}

std::string_view darwin_call_class_name(DarwinCallClass value) noexcept {
    switch (value) {
    case DarwinCallClass::unix_syscall: return "unix_syscall";
    case DarwinCallClass::mach_trap: return "mach_trap";
    case DarwinCallClass::platform_syscall: return "platform_syscall";
    }
    return "unknown";
}

std::string_view unix_return_disposition_name(UnixReturnDisposition value) noexcept {
    switch (value) {
    case UnixReturnDisposition::success: return "success";
    case UnixReturnDisposition::error: return "error";
    case UnixReturnDisposition::restart: return "restart";
    case UnixReturnDisposition::just_return: return "just_return";
    }
    return "unknown";
}

} // namespace macosarm
