#pragma once

#include "macosarm/process.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace macosarm {

// Cooperative guest A64 execution contexts, not Darwin pthreads.
// The caller owns all mapped stacks and TLS allocations. The guest
// CPU state includes general, SIMD/FP, PSTATE and TPIDRRO_EL0 registers.
enum class GuestThreadStatus { runnable, stopped };
enum class GuestThreadAddError {
    none, missing_main, duplicate_main, invalid_cpu, process_stopped, capacity,
};
struct GuestThreadAddResult {
    GuestThreadAddError error{GuestThreadAddError::none};
    std::uint64_t thread_id{};
    [[nodiscard]] explicit operator bool() const noexcept {
        return error == GuestThreadAddError::none;
    }
};
enum class GuestThreadRunError {
    none, unknown_thread, invalid_quantum, stopped, budget_exhausted,
};
struct GuestThreadRunResult {
    GuestThreadRunError error{GuestThreadRunError::none};
    ProcessResult process{};
    [[nodiscard]] explicit operator bool() const noexcept {
        return error == GuestThreadRunError::none;
    }
};
struct GuestThread {
    MachThreadIdentity identity{};
    CpuState cpu{};
    GuestThreadStatus status{GuestThreadStatus::runnable};
    std::uint64_t instructions_executed{};
};

// A process-scoped CPU context table with bounded serialized execution.
// This foundation deliberately does not change bsdthread_register/create
// until pthread structures, stacks and kernel thread lifecycle are supported.
class GuestThreadGroup {
public:
    GuestThreadGroup(GuestAddressSpace& vm, MachContext& mach,
                     std::uint64_t total_budget) noexcept
        : vm_(vm), mach_(mach), remaining_(total_budget) {}

    [[nodiscard]] GuestThreadAddResult add_main(CpuState initial) {
        if (stopped_) return {GuestThreadAddError::process_stopped, 0};
        if (!threads_.empty()) return {GuestThreadAddError::duplicate_main, 0};
        if (!valid_initial_state(initial)) return {GuestThreadAddError::invalid_cpu, 0};
        const auto identity = mach_.main_thread_identity();
        threads_.push_back({identity, initial});
        return {GuestThreadAddError::none, identity.thread_id};
    }

    [[nodiscard]] GuestThreadAddResult add_worker(CpuState initial) {
        if (stopped_) return {GuestThreadAddError::process_stopped, 0};
        if (threads_.empty()) return {GuestThreadAddError::missing_main, 0};
        if (threads_.size() >= MachContext::kMaxGuestThreads) {
            return {GuestThreadAddError::capacity, 0};
        }
        if (!valid_initial_state(initial)) return {GuestThreadAddError::invalid_cpu, 0};
        const auto identity = mach_.allocate_worker_thread_identity();
        if (!identity) return {GuestThreadAddError::capacity, 0};
        threads_.push_back({*identity, initial});
        return {GuestThreadAddError::none, identity->thread_id};
    }

    [[nodiscard]] GuestThreadRunResult run_slice(
        std::uint64_t thread_id, ExecutionBackend& backend,
        DarwinHostServices& host, std::uint64_t quantum) {
        if (quantum == 0) return {GuestThreadRunError::invalid_quantum, {}};
        auto it = std::find_if(threads_.begin(), threads_.end(),
                               [thread_id](const GuestThread& t) {
                                   return t.identity.thread_id == thread_id;
                               });
        if (it == threads_.end()) return {GuestThreadRunError::unknown_thread, {}};
        if (stopped_ || it->status != GuestThreadStatus::runnable) {
            return {GuestThreadRunError::stopped, {}};
        }
        if (remaining_ == 0) return {GuestThreadRunError::budget_exhausted, {}};
        const ProcessResult process = run_process(
            it->cpu, vm_, backend, host, mach_,
            std::min(remaining_, quantum), &it->identity);
        remaining_ -= process.instructions_executed;
        it->instructions_executed += process.instructions_executed;
        if (process.reason != ProcessStopReason::instruction_budget) {
            it->status = GuestThreadStatus::stopped;
            stopped_ = true; // BSD exit and fatal faults end the process.
        }
        return {GuestThreadRunError::none, process};
    }

    [[nodiscard]] const GuestThread* find(std::uint64_t thread_id) const noexcept {
        for (const GuestThread& t : threads_) {
            if (t.identity.thread_id == thread_id) return &t;
        }
        return nullptr;
    }
    [[nodiscard]] std::size_t size() const noexcept { return threads_.size(); }
    [[nodiscard]] std::uint64_t remaining_budget() const noexcept { return remaining_; }
    [[nodiscard]] bool stopped() const noexcept { return stopped_; }

private:
    [[nodiscard]] bool valid_initial_state(const CpuState& state) const noexcept {
        if ((state.pc & 3U) != 0U || (state.sp & 15U) != 0U || state.sp < 16U) {
            return false;
        }
        std::uint32_t instruction = 0;
        return static_cast<bool>(fetch_instruction(vm_, state.pc, instruction)) &&
               static_cast<bool>(vm_.probe_write(state.sp - 16U, 16U));
    }

    GuestAddressSpace& vm_;
    MachContext& mach_;
    std::vector<GuestThread> threads_;
    std::uint64_t remaining_{};
    bool stopped_{};
};

} // namespace macosarm
