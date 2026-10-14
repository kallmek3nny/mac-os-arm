#include "macosarm/dynarmic_backend.hpp"

#include <dynarmic/interface/A64/a64.h>
#include <dynarmic/interface/A64/config.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace macosarm {
namespace {

template <typename T>
[[nodiscard]] T decode_little_endian(const std::array<std::byte, sizeof(T)>& bytes) noexcept {
    T value{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        value |= static_cast<T>(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    }
    return value;
}

template <typename T>
[[nodiscard]] std::array<std::byte, sizeof(T)> encode_little_endian(T value) noexcept {
    std::array<std::byte, sizeof(T)> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>((value >> (i * 8)) & static_cast<T>(0xff));
    }
    return bytes;
}

} // namespace

struct DynarmicBackend::Impl final : Dynarmic::A64::UserCallbacks {
    Impl() {
        Dynarmic::A64::UserConfig config{};
        config.callbacks = this;
        config.enable_cycle_counting = false;
        config.check_halt_on_memory_access = true;
        config.code_cache_size = 16 * 1024 * 1024;
        jit = std::make_unique<Dynarmic::A64::Jit>(config);
    }

    [[nodiscard]] ExecutionResult run(
        CpuState& state,
        GuestAddressSpace& new_address_space,
        std::uint64_t instruction_budget) {

        if (instruction_budget == 0) {
            return {StopReason::instruction_budget, 0, 0, VmError::none};
        }

        if (address_space != &new_address_space) {
            address_space = &new_address_space;
            jit->ClearCache();
        }

        pending_result.reset();
        jit->ClearHalt(Dynarmic::HaltReason::UserDefined1);
        copy_state_to_jit(state);

        std::uint64_t executed = 0;
        while (executed < instruction_budget) {
            pending_result.reset();
            jit->ClearHalt(Dynarmic::HaltReason::UserDefined1);
            (void)jit->Step();
            ++executed;

            if (pending_result.has_value()) {
                ExecutionResult result = *pending_result;
                result.instructions_executed = executed;
                copy_state_from_jit(state);
                return result;
            }
        }

        copy_state_from_jit(state);
        return {StopReason::instruction_budget, executed, 0, VmError::none};
    }

    std::optional<std::uint32_t> MemoryReadCode(Dynarmic::A64::VAddr vaddr) override {
        std::array<std::byte, 4> bytes{};
        const VmResult result = active_memory().fetch_code(vaddr, bytes);
        if (!result) {
            record_memory_fault(result.error);
            return std::nullopt;
        }
        return decode_little_endian<std::uint32_t>(bytes);
    }

    std::uint8_t MemoryRead8(Dynarmic::A64::VAddr vaddr) override {
        return read_scalar<std::uint8_t>(vaddr);
    }

    std::uint16_t MemoryRead16(Dynarmic::A64::VAddr vaddr) override {
        return read_scalar<std::uint16_t>(vaddr);
    }

    std::uint32_t MemoryRead32(Dynarmic::A64::VAddr vaddr) override {
        return read_scalar<std::uint32_t>(vaddr);
    }

    std::uint64_t MemoryRead64(Dynarmic::A64::VAddr vaddr) override {
        return read_scalar<std::uint64_t>(vaddr);
    }

    Dynarmic::A64::Vector MemoryRead128(Dynarmic::A64::VAddr vaddr) override {
        std::array<std::byte, 16> bytes{};
        const VmResult result = active_memory().read(vaddr, bytes);
        if (!result) {
            record_memory_fault(result.error);
            return {};
        }

        std::array<std::byte, 8> low_bytes{};
        std::array<std::byte, 8> high_bytes{};
        for (std::size_t i = 0; i < 8; ++i) {
            low_bytes[i] = bytes[i];
            high_bytes[i] = bytes[i + 8];
        }
        return {
            decode_little_endian<std::uint64_t>(low_bytes),
            decode_little_endian<std::uint64_t>(high_bytes),
        };
    }

    void MemoryWrite8(Dynarmic::A64::VAddr vaddr, std::uint8_t value) override {
        write_scalar(vaddr, value);
    }

    void MemoryWrite16(Dynarmic::A64::VAddr vaddr, std::uint16_t value) override {
        write_scalar(vaddr, value);
    }

    void MemoryWrite32(Dynarmic::A64::VAddr vaddr, std::uint32_t value) override {
        write_scalar(vaddr, value);
    }

    void MemoryWrite64(Dynarmic::A64::VAddr vaddr, std::uint64_t value) override {
        write_scalar(vaddr, value);
    }

    void MemoryWrite128(Dynarmic::A64::VAddr vaddr, Dynarmic::A64::Vector value) override {
        const auto low = encode_little_endian<std::uint64_t>(value[0]);
        const auto high = encode_little_endian<std::uint64_t>(value[1]);
        std::array<std::byte, 16> bytes{};
        for (std::size_t i = 0; i < 8; ++i) {
            bytes[i] = low[i];
            bytes[i + 8] = high[i];
        }
        write_bytes(vaddr, bytes);
    }

    void InterpreterFallback(Dynarmic::A64::VAddr, std::size_t) override {
        record_stop({StopReason::backend_error, 0, 0, VmError::none});
    }

    void CallSVC(std::uint32_t swi) override {
        record_stop({StopReason::supervisor_call, 0, swi, VmError::none});
    }

    void ExceptionRaised(Dynarmic::A64::VAddr, Dynarmic::A64::Exception) override {
        if (!pending_result.has_value()) {
            record_stop({StopReason::exception, 0, 0, VmError::none});
        }
    }

    void AddTicks(std::uint64_t) override {}
    std::uint64_t GetTicksRemaining() override { return 0; }
    std::uint64_t GetCNTPCT() override { return 0; }

private:
    template <typename T>
    [[nodiscard]] T read_scalar(Dynarmic::A64::VAddr vaddr) {
        std::array<std::byte, sizeof(T)> bytes{};
        const VmResult result = active_memory().read(vaddr, bytes);
        if (!result) {
            record_memory_fault(result.error);
            return {};
        }
        return decode_little_endian<T>(bytes);
    }

    template <typename T>
    void write_scalar(Dynarmic::A64::VAddr vaddr, T value) {
        const auto bytes = encode_little_endian<T>(value);
        write_bytes(vaddr, bytes);
    }

    template <std::size_t N>
    void write_bytes(Dynarmic::A64::VAddr vaddr, const std::array<std::byte, N>& bytes) {
        const VmResult result = active_memory().write(vaddr, bytes);
        if (!result) {
            record_memory_fault(result.error);
        }
    }

    [[nodiscard]] GuestAddressSpace& active_memory() {
        return *address_space;
    }

    void record_memory_fault(VmError error) {
        record_stop({StopReason::memory_fault, 0, 0, error});
    }

    void record_stop(ExecutionResult result) {
        if (!pending_result.has_value()) {
            pending_result = result;
        }
        if (jit && jit->IsExecuting()) {
            jit->HaltExecution(Dynarmic::HaltReason::UserDefined1);
        }
    }

    void copy_state_to_jit(const CpuState& state) {
        jit->SetRegisters(state.x);
        jit->SetSP(state.sp);
        jit->SetPC(state.pc);
        jit->SetPstate(state.pstate);
        jit->SetFpcr(state.fpcr);
        jit->SetFpsr(state.fpsr);

        std::array<Dynarmic::A64::Vector, 32> vectors{};
        for (std::size_t i = 0; i < vectors.size(); ++i) {
            vectors[i] = {state.vectors[i].low, state.vectors[i].high};
        }
        jit->SetVectors(vectors);
    }

    void copy_state_from_jit(CpuState& state) const {
        state.x = jit->GetRegisters();
        state.sp = jit->GetSP();
        state.pc = jit->GetPC();
        state.pstate = jit->GetPstate();
        state.fpcr = jit->GetFpcr();
        state.fpsr = jit->GetFpsr();

        const auto vectors = jit->GetVectors();
        for (std::size_t i = 0; i < vectors.size(); ++i) {
            state.vectors[i] = {vectors[i][0], vectors[i][1]};
        }
    }

    GuestAddressSpace* address_space{};
    std::optional<ExecutionResult> pending_result;
    std::unique_ptr<Dynarmic::A64::Jit> jit;
};

DynarmicBackend::DynarmicBackend() : impl_(std::make_unique<Impl>()) {}
DynarmicBackend::~DynarmicBackend() = default;
DynarmicBackend::DynarmicBackend(DynarmicBackend&&) noexcept = default;
DynarmicBackend& DynarmicBackend::operator=(DynarmicBackend&&) noexcept = default;

ExecutionResult DynarmicBackend::run(
    CpuState& state,
    GuestAddressSpace& address_space,
    std::uint64_t instruction_budget) {
    return impl_->run(state, address_space, instruction_budget);
}

} // namespace macosarm
