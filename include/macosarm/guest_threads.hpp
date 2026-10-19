#pragma once

#include "macosarm/process.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace macosarm {

// Cooperative guest A64 execution contexts, not Darwin pthreads.
// The caller owns all mapped stacks and TLS allocations. The guest
// CPU state includes general, SIMD/FP, PSTATE and TPIDRRO_EL0 registers.
enum class GuestThreadStatus { runnable, stopped };
enum class GuestThreadAddError {
    none, missing_main, duplicate_main, invalid_cpu, process_stopped, capacity,
    invalid_stack_size, allocation_failed,
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
enum class GuestThreadReapError {
    none, unknown_thread, main_thread, still_running, allocation_changed,
};
struct GuestThreadReapResult {
    GuestThreadReapError error{GuestThreadReapError::none};
    [[nodiscard]] explicit operator bool() const noexcept {
        return error == GuestThreadReapError::none;
    }
};

struct GuestOwnedStack {
    std::uint64_t base{}; // Includes the inaccessible guard page.
    std::uint64_t size{};
    std::uint64_t allocation_id{};
    std::size_t slot{};
};

struct GuestThread {
    MachThreadIdentity identity{};
    CpuState cpu{};
    GuestThreadStatus status{GuestThreadStatus::runnable};
    std::uint64_t instructions_executed{};
    std::optional<GuestOwnedStack> owned_stack{};
};

// A process-scoped CPU context table with bounded serialized execution.
// This foundation deliberately does not change bsdthread_register/create
// until pthread structures, stacks and kernel thread lifecycle are supported.
class GuestThreadGroup {
public:
    static constexpr std::uint64_t kStackArenaBase = 0x40000000000ULL;
    static constexpr std::uint64_t kStackSlotSize = 0x200000ULL;
    static constexpr std::uint64_t kMaxOwnedStackPages = 64U;

    GuestThreadGroup(GuestAddressSpace& vm, MachContext& mach,
                     std::uint64_t total_budget) noexcept
        : vm_(vm), mach_(mach), remaining_(total_budget) {}

    // Stack reservations belong to this group. Never double-reclaim them by
    // accidentally copying or moving the group that owns the leases.
    GuestThreadGroup(const GuestThreadGroup&) = delete;
    GuestThreadGroup& operator=(const GuestThreadGroup&) = delete;
    GuestThreadGroup(GuestThreadGroup&&) = delete;
    GuestThreadGroup& operator=(GuestThreadGroup&&) = delete;

    ~GuestThreadGroup() noexcept {
        for (const GuestThread& thread : threads_) {
            if (thread.owned_stack) {
                const GuestOwnedStack& stack = *thread.owned_stack;
                // A guest may have unmapped and replaced these pages. The VM
                // allocation token prevents deleting unrelated guest memory.
                (void)vm_.unmap_allocation(stack.base, stack.size,
                                           stack.allocation_id);
            }
        }
    }

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

    // Allocate a worker's stack in a bounded synthetic guest VA arena.
    // A permanently non-accessible page guards the lower bound, with stack growing down
    // from the top of the contiguous writable pages. This does not create
    // a real Darwin pthread or initialize Apple libpthread TLS.
    [[nodiscard]] GuestThreadAddResult add_owned_worker(
        CpuState initial, std::uint64_t stack_size) {
        if (stopped_) return {GuestThreadAddError::process_stopped, 0};
        if (threads_.empty()) return {GuestThreadAddError::missing_main, 0};
        if (threads_.size() >= MachContext::kMaxGuestThreads) {
            return {GuestThreadAddError::capacity, 0};
        }
        constexpr std::uint64_t page = GuestAddressSpace::kPageSize;
        if (stack_size == 0 || stack_size > kMaxOwnedStackPages * page ||
            (stack_size % page) != 0U) {
            return {GuestThreadAddError::invalid_stack_size, 0};
        }
        if ((initial.pc & 3U) != 0U) {
            return {GuestThreadAddError::invalid_cpu, 0};
        }
        std::uint32_t instruction = 0;
        if (!fetch_instruction(vm_, initial.pc, instruction)) {
            return {GuestThreadAddError::invalid_cpu, 0};
        }

        const std::uint64_t reservation = stack_size + page;
        const auto rw = Protection::read | Protection::write;
        for (std::size_t slot = 0; slot < stack_slots_.size(); ++slot) {
            if (stack_slots_[slot]) continue;
            const std::uint64_t base = kStackArenaBase + slot * kStackSlotSize;
            const VmResult mapped = vm_.map(base, reservation, rw);
            if (!mapped) {
                if (mapped.error == VmError::overlap) continue;
                return {GuestThreadAddError::allocation_failed, 0};
            }
            const auto allocation_id = vm_.allocation_id_at(base);
            if (!allocation_id ||
                !vm_.protect_range(base, page, Protection::none) ||
                !vm_.restrict_maximum_protection_range(
                    base, page, Protection::none)) {
                (void)vm_.unmap_range(base, reservation);
                return {GuestThreadAddError::allocation_failed, 0};
            }
            initial.sp = base + reservation;
            const GuestThreadAddResult added = add_worker(initial);
            if (!added) {
                (void)vm_.unmap_allocation(base, reservation, *allocation_id);
                return added;
            }
            threads_.back().owned_stack = GuestOwnedStack{
                base, reservation, *allocation_id, slot};
            stack_slots_[slot] = true;
            return added;
        }
        return {GuestThreadAddError::allocation_failed, 0};
    }

    // Explicit host-managed reaping, *not* pthread_join: it does not block
    // and cannot release a running worker. All owned stack pages must still
    // belong to the allocation that created them, even after mprotect splits.
    [[nodiscard]] GuestThreadReapResult reap_stopped_worker(
        std::uint64_t thread_id) {
        const auto it = std::find_if(threads_.begin(), threads_.end(),
                                     [thread_id](const GuestThread& t) {
                                         return t.identity.thread_id == thread_id;
                                     });
        if (it == threads_.end()) return {GuestThreadReapError::unknown_thread};
        if (it == threads_.begin()) return {GuestThreadReapError::main_thread};
        if (it->status != GuestThreadStatus::stopped) {
            return {GuestThreadReapError::still_running};
        }
        if (it->owned_stack) {
            const GuestOwnedStack stack = *it->owned_stack;
            if (!vm_.unmap_allocation(stack.base, stack.size, stack.allocation_id)) {
                return {GuestThreadReapError::allocation_changed};
            }
            stack_slots_[stack.slot] = false;
        }
        threads_.erase(it);
        return {};
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
        if (process.reason == ProcessStopReason::thread_exited) {
            // bsdthread_terminate ends this context. Other contexts remain
            // runnable, including a worker outliving the original main.
            it->status = GuestThreadStatus::stopped;
        } else if (process.reason != ProcessStopReason::instruction_budget) {
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
    std::array<bool, MachContext::kMaxGuestThreads - 1U> stack_slots_{};
    std::uint64_t remaining_{};
    bool stopped_{};
};

} // namespace macosarm
