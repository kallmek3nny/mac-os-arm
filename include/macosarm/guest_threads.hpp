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
    identity_changed,
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
    // Optional pthread-shaped storage backed by this same owned allocation.
    std::uint64_t pthread_base{};
    std::uint64_t tsd_base{};
    std::uint32_t pthread_size{};
    // Source-derived guest errno_t field, owned by the same VM lease.
    std::uint64_t errno_address{};
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
        for (std::size_t i = 0; i < threads_.size(); ++i) {
            const GuestThread& thread = threads_[i];
            if (thread.owned_stack) {
                const GuestOwnedStack& stack = *thread.owned_stack;
                // A guest may have unmapped and replaced these pages. The VM
                // allocation token prevents deleting unrelated guest memory.
                (void)vm_.unmap_allocation(stack.base, stack.size,
                                           stack.allocation_id);
            }
            // The host is destroying these manually managed contexts, not
            // implementing pthread_detach or a kernel thread-port send right.
            if (i != 0U) {
                (void)mach_.retire_worker_thread_identity(thread.identity);
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

    // Existing guarded worker path, with no implied pthread registration.
    [[nodiscard]] GuestThreadAddResult add_owned_worker(
        CpuState initial, std::uint64_t stack_size) {
        return add_owned_worker_impl(initial, stack_size, std::nullopt);
    }

    // Source-observed ARM64 TSD layout: TPIDRRO_EL0 points to slot 0
    // (pthread_self) and slot 3 stores the Mach thread-self port. This
    // optional manually managed worker does not implement syscall #360.
    [[nodiscard]] GuestThreadAddResult add_owned_worker_with_tsd(
        CpuState initial, std::uint64_t stack_size,
        std::uint32_t pthread_size, std::uint32_t tsd_offset) {
        return add_owned_worker_impl(
            initial, stack_size, PthreadTlsShape{pthread_size, tsd_offset});
    }

    // opt-in libpthread errno slot 1. Apple _pthread_struct_init stores
    // &pthread->err_no there; the offset comes from the caller's ABI
    // layout, not a host C++ struct. No syscall or feature bits change.
    [[nodiscard]] GuestThreadAddResult add_owned_worker_with_errno_tsd(
        CpuState initial, std::uint64_t stack_size,
        std::uint32_t pthread_size, std::uint32_t tsd_offset,
        std::uint32_t errno_offset) {
        return add_owned_worker_impl(
            initial, stack_size,
            PthreadTlsShape{pthread_size, tsd_offset, errno_offset});
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
        if (!mach_.is_active_worker_thread_identity(it->identity)) {
            return {GuestThreadReapError::identity_changed};
        }
        if (it->owned_stack) {
            const GuestOwnedStack stack = *it->owned_stack;
            if (!vm_.unmap_allocation(stack.base, stack.size, stack.allocation_id)) {
                return {GuestThreadReapError::allocation_changed};
            }
            stack_slots_[stack.slot] = false;
        }
        if (!mach_.retire_worker_thread_identity(it->identity)) {
            return {GuestThreadReapError::identity_changed};
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
    struct PthreadTlsShape {
        std::uint32_t pthread_size{};
        std::uint32_t tsd_offset{};
        std::optional<std::uint32_t> errno_offset{};
    };

    [[nodiscard]] GuestThreadAddResult add_owned_worker_impl(
        CpuState initial, std::uint64_t stack_size,
        std::optional<PthreadTlsShape> tls) {
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
        // Four 64-bit slots are needed for source-defined PTHREAD_SELF and
        // MACH_THREAD_SELF, without claiming other libpthread TLS fields.
        constexpr std::size_t prefix_size = 4U * sizeof(std::uint64_t);
        if (tls && (tls->pthread_size < prefix_size ||
                    tls->pthread_size > 64U * 1024U ||
                    (tls->pthread_size % 8U) != 0U ||
                    (tls->tsd_offset % 8U) != 0U ||
                    tls->tsd_offset > tls->pthread_size - prefix_size ||
                    (tls->errno_offset &&
                     (tls->tsd_offset < sizeof(std::uint32_t) ||
                      (*tls->errno_offset % alignof(std::uint32_t)) != 0U ||
                      *tls->errno_offset >
                          tls->tsd_offset - sizeof(std::uint32_t))))) {
            return {GuestThreadAddError::invalid_stack_size, 0};
        }
        if ((initial.pc & 3U) != 0U) {
            return {GuestThreadAddError::invalid_cpu, 0};
        }
        std::uint32_t instruction = 0;
        if (!fetch_instruction(vm_, initial.pc, instruction)) {
            return {GuestThreadAddError::invalid_cpu, 0};
        }
        const std::uint64_t pthread_pages = tls
            ? (static_cast<std::uint64_t>(tls->pthread_size) + page - 1U) / page
            : 0U;
        const std::uint64_t reservation = page + stack_size + pthread_pages * page;
        if (reservation > kStackSlotSize) {
            return {GuestThreadAddError::invalid_stack_size, 0};
        }
        const auto rw = Protection::read | Protection::write;
        for (std::size_t slot = 0; slot < stack_slots_.size(); ++slot) {
            if (stack_slots_[slot]) continue;
            const std::uint64_t base = kStackArenaBase + slot * kStackSlotSize;
            const VmResult mapped = vm_.map(base, reservation, rw);
            if (!mapped) {
                if (mapped.error == VmError::overlap) continue;
                return {GuestThreadAddError::allocation_failed, 0};
            }
            const auto id = vm_.allocation_id_at(base);
            if (!id || !vm_.protect_range(base, page, Protection::none) ||
                !vm_.restrict_maximum_protection_range(
                    base, page, Protection::none)) {
                (void)vm_.unmap_range(base, reservation);
                return {GuestThreadAddError::allocation_failed, 0};
            }
            const std::uint64_t pthread_base = base + page + stack_size;
            const std::uint64_t tsd_base = tls ? pthread_base + tls->tsd_offset : 0U;
            const std::uint64_t errno_address = tls && tls->errno_offset
                ? pthread_base + *tls->errno_offset : 0U;
            initial.sp = pthread_base;
            if (tls) initial.tpidrro_el0 = tsd_base;
            const GuestThreadAddResult added = add_worker(initial);
            if (!added) {
                (void)vm_.unmap_allocation(base, reservation, *id);
                return added;
            }
            if (tls) {
                std::array<std::byte, prefix_size> prefix{};
                const auto encode = [&](std::size_t offset, std::uint64_t value) {
                    for (std::size_t i = 0; i < 8U; ++i) {
                        prefix[offset + i] = static_cast<std::byte>(
                            (value >> (i * 8U)) & 0xffU);
                    }
                };
                encode(0U, pthread_base);
                if (errno_address != 0U) encode(8U, errno_address);
                encode(24U, threads_.back().identity.thread_self_port);
                const std::array<std::byte, 4> initial_errno{};
                if (!vm_.write(tsd_base, prefix) ||
                    (errno_address != 0U &&
                     !vm_.write(errno_address, initial_errno))) {
                    // Atomic construction: on copyout failure undo both VM
                    // ownership and thread-table identity publication.
                    const MachThreadIdentity failed = threads_.back().identity;
                    threads_.pop_back();
                    (void)mach_.retire_worker_thread_identity(failed);
                    (void)vm_.unmap_allocation(base, reservation, *id);
                    return {GuestThreadAddError::allocation_failed, 0};
                }
            }
            threads_.back().owned_stack = GuestOwnedStack{
                base, reservation, *id, slot,
                tls ? pthread_base : 0U, tsd_base,
                tls ? tls->pthread_size : 0U, errno_address};
            stack_slots_[slot] = true;
            return added;
        }
        return {GuestThreadAddError::allocation_failed, 0};
    }

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
