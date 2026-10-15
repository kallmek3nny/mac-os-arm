#pragma once

#include "macosarm/execution.hpp"
#include "macosarm/pointer_auth.hpp"

#include <memory>

namespace macosarm {

// ARM64 execution through Dynarmic. The implementation is kept behind a PIMPL
// so the rest of the runtime does not depend on Dynarmic headers or ABI.
class DynarmicBackend final : public ExecutionBackend {
public:
    // Without an explicit key set, PAUTH instructions are rejected instead of
    // being allowed to degrade into Dynarmic hint/NOP behavior.
    DynarmicBackend();
    explicit DynarmicBackend(PointerAuthKeySet pointer_auth_keys);
    ~DynarmicBackend() override;

    DynarmicBackend(const DynarmicBackend&) = delete;
    DynarmicBackend& operator=(const DynarmicBackend&) = delete;
    DynarmicBackend(DynarmicBackend&&) noexcept;
    DynarmicBackend& operator=(DynarmicBackend&&) noexcept;

    [[nodiscard]] ExecutionResult run(
        CpuState& state,
        GuestAddressSpace& address_space,
        std::uint64_t instruction_budget) override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace macosarm
