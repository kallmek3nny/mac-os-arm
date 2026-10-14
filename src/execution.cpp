#include "macosarm/execution.hpp"

#include <array>
#include <cstddef>

namespace macosarm {

CpuInitResult initialize_cpu(
    CpuState& state,
    const LoadedImage& image,
    std::uint64_t stack_top) noexcept {

    if ((image.entry_address & 0x3U) != 0) {
        return {CpuInitError::unaligned_entry};
    }
    if ((stack_top & 0xfU) != 0) {
        return {CpuInitError::unaligned_stack};
    }

    state = {};
    state.pc = image.entry_address;
    state.sp = stack_top;
    return {};
}

VmResult fetch_instruction(
    const GuestAddressSpace& address_space,
    std::uint64_t pc,
    std::uint32_t& instruction) noexcept {

    if ((pc & 0x3U) != 0) {
        return {VmError::unaligned};
    }

    std::array<std::byte, 4> bytes{};
    const VmResult fetched = address_space.fetch_code(pc, bytes);
    if (!fetched) {
        return fetched;
    }

    instruction = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        instruction |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    }
    return {};
}

std::string_view cpu_init_error_name(CpuInitError error) noexcept {
    switch (error) {
    case CpuInitError::none: return "none";
    case CpuInitError::unaligned_entry: return "unaligned_entry";
    case CpuInitError::unaligned_stack: return "unaligned_stack";
    }
    return "unknown";
}

std::string_view stop_reason_name(StopReason reason) noexcept {
    switch (reason) {
    case StopReason::instruction_budget: return "instruction_budget";
    case StopReason::supervisor_call: return "supervisor_call";
    case StopReason::exception: return "exception";
    case StopReason::memory_fault: return "memory_fault";
    case StopReason::backend_error: return "backend_error";
    }
    return "unknown";
}

} // namespace macosarm
