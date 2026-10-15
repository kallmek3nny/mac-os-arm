#pragma once

#include "macosarm/dyld_initializer_execution.hpp"
#include "macosarm/process_startup.hpp"

#include <cstdint>

namespace macosarm::dyld {

[[nodiscard]] constexpr InitializerCallContext initializer_context_from_process_startup(
    const ProcessStartupLayout& layout,
    std::uint64_t program_vars = 0) noexcept {
    return {
        layout.argc,
        layout.argv,
        layout.envp,
        layout.apple,
        program_vars,
    };
}

} // namespace macosarm::dyld
