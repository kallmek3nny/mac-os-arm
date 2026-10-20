// Phase49: process-managed guarded stacks with exact allocation provenance.
// These are manually scheduled guest contexts, not Darwin pthreads.
void test_owned_guest_stacks() {
    using namespace macosarm;
    constexpr std::uint64_t code = 0x2b0000000ULL;
    constexpr std::uint64_t main_stack = 0x2c0000000ULL;
    constexpr auto page = GuestAddressSpace::kPageSize;
    const auto rw = Protection::read | Protection::write;
    GuestAddressSpace vm;
    const std::array<std::byte, 4> nop{
        std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5}};
    expect(static_cast<bool>(vm.map(code, page,
                        Protection::read | Protection::execute)) &&
               static_cast<bool>(vm.load_bytes(code, nop)) &&
               static_cast<bool>(vm.map(main_stack, page, rw)),
           "owned stack test guest code and external main stack map");

    CpuState main{};
    main.pc = code;
    main.sp = main_stack + page;
    CpuState worker = main;
    worker.x[16] = kDarwinSysBsdthreadTerminate;

    MachContext mach;
    {
        GuestThreadGroup group(vm, mach, 8U);
        const auto main_id = group.add_main(main);
        const auto missing_size = group.add_owned_worker(worker, 0);
        const auto bad_alignment = group.add_owned_worker(worker, page + 1U);
        const auto excessive_size = group.add_owned_worker(
            worker, (GuestThreadGroup::kMaxOwnedStackPages + 1U) * page);
        const auto created = group.add_owned_worker(worker, 2U * page);
        const GuestThread* t = group.find(created.thread_id);
        const std::uint64_t expected_top =
            GuestThreadGroup::kStackArenaBase + 3U * page;
        const auto token = vm.allocation_id_at(GuestThreadGroup::kStackArenaBase);
        const auto guarded_base = GuestThreadGroup::kStackArenaBase;
        const auto restore_via_range = vm.protect_range(guarded_base, page, rw);
        const auto restore_via_exact = vm.protect(guarded_base, page, rw);
        expect(restore_via_range.error == VmError::protection &&
                   restore_via_exact.error == VmError::protection &&
                   vm.probe_write(guarded_base, 1U).error == VmError::protection &&
                   static_cast<bool>(vm.probe_write(expected_top - 16U, 16U)) &&
                   token == vm.allocation_id_at(guarded_base + page),
               "owned stack guard cannot be made writable through either protect API");
        expect(static_cast<bool>(main_id) &&
                   missing_size.error == GuestThreadAddError::invalid_stack_size &&
                   bad_alignment.error == GuestThreadAddError::invalid_stack_size &&
                   excessive_size.error == GuestThreadAddError::invalid_stack_size &&
                   static_cast<bool>(created) && t != nullptr &&
                   created.thread_id == MachContext::kSyntheticMainThreadId + 1U &&
                   t->cpu.sp == expected_top &&
                   t->owned_stack.has_value() &&
                   t->owned_stack->base == GuestThreadGroup::kStackArenaBase &&
                   token.has_value() &&
                   t->owned_stack->allocation_id == *token &&
                   vm.probe_write(expected_top - 16U, 16U) &&
                   vm.probe_write(GuestThreadGroup::kStackArenaBase, 16U).error ==
                       VmError::protection &&
                   group.reap_stopped_worker(created.thread_id).error ==
                       GuestThreadReapError::still_running &&
                   group.reap_stopped_worker(main_id.thread_id).error ==
                       GuestThreadReapError::main_thread,
               "valid guarded worker stack owns a unique VM allocation and rejects early reap");

        CaptureHost host;
        ScriptedBackend terminate({{svc(1), false, 0, 0, 0, 0}});
        const auto stopped = group.run_slice(created.thread_id, terminate, host, 2U);
        expect(static_cast<bool>(stopped) &&
                   stopped.process.reason == ProcessStopReason::thread_exited &&
                   group.find(created.thread_id)->status == GuestThreadStatus::stopped,
               "owned worker can terminate independently");

        // mprotect divides the original allocation but retains its identity.
        expect(static_cast<bool>(vm.protect_range(
                   GuestThreadGroup::kStackArenaBase + page, page, Protection::read)),
               "stack subrange protect preserves the original allocation lease");
        const auto released = group.reap_stopped_worker(created.thread_id);
        expect(static_cast<bool>(released) &&
                   group.find(created.thread_id) == nullptr &&
                   !vm.allocation_id_at(GuestThreadGroup::kStackArenaBase) &&
                   vm.probe_write(expected_top - 16U, 16U).error == VmError::unmapped &&
                   group.reap_stopped_worker(created.thread_id).error ==
                       GuestThreadReapError::unknown_thread,
               "reaping frees every guarded stack mapping and rejects reused identity");

        const auto reused = group.add_owned_worker(worker, page);
        const GuestThread* t2 = group.find(reused.thread_id);
        expect(static_cast<bool>(reused) && t2 != nullptr &&
                   reused.thread_id != created.thread_id &&
                   t2->owned_stack.has_value() &&
                   t2->owned_stack->base == GuestThreadGroup::kStackArenaBase &&
                   t2->owned_stack->allocation_id != *token &&
                   group.remaining_budget() == 7U,
               "reclaimed synthetic VA slot can be reused without reusing thread ID");
    }
    expect(!vm.allocation_id_at(GuestThreadGroup::kStackArenaBase),
           "group destruction reclaims remaining originally owned stack mappings");

    // A foreign mapping in the first synthetic slot must remain untouched.
    expect(static_cast<bool>(vm.map(GuestThreadGroup::kStackArenaBase, page, rw)),
           "synthetic stack collision maps a foreign page");
    const std::array<std::byte, 4> marker{
        std::byte{0x33}, std::byte{0x44}, std::byte{0x55}, std::byte{0x66}};
    expect(static_cast<bool>(vm.write(GuestThreadGroup::kStackArenaBase, marker)),
           "write foreign stack-slot marker");
    {
        MachContext collision_mach;
        GuestThreadGroup collision(vm, collision_mach, 4U);
        const auto m = collision.add_main(main);
        const auto w = collision.add_owned_worker(worker, page);
        const GuestThread* owned = collision.find(w.thread_id);
        expect(static_cast<bool>(m) && static_cast<bool>(w) &&
                   owned != nullptr && owned->owned_stack.has_value() &&
                   owned->owned_stack->slot == 1U,
               "stack allocator skips reserved foreign guest mappings");
    }
    std::array<std::byte, 4> foreign_bytes{};
    expect(static_cast<bool>(vm.read(GuestThreadGroup::kStackArenaBase,
                                    foreign_bytes)) &&
               foreign_bytes == marker,
           "group stack cleanup preserves foreign mapping and its bytes");

    // A guest can unmap the guard and replace it before a stopped worker is
    // reaped. Never reclaim the new owner's memory or report successful reap.
    {
        MachContext replacement_mach;
        GuestThreadGroup group(vm, replacement_mach, 3U);
        const auto m = group.add_main(main);
        const auto w = group.add_owned_worker(worker, page);
        const GuestThread* owned = group.find(w.thread_id);
        const std::uint64_t owned_base = owned != nullptr &&
                  owned->owned_stack ? owned->owned_stack->base : 0U;
        expect(static_cast<bool>(m) && static_cast<bool>(w) &&
                   owned_base == GuestThreadGroup::kStackArenaBase +
                                     GuestThreadGroup::kStackSlotSize,
               "replacement case uses the second slot");
        CaptureHost host;
        ScriptedBackend terminate({{svc(1), false, 0, 0, 0, 0}});
        const auto exit_result = group.run_slice(w.thread_id, terminate, host, 1U);
        expect(static_cast<bool>(exit_result) &&
                   exit_result.process.reason == ProcessStopReason::thread_exited &&
                   static_cast<bool>(vm.unmap_range(owned_base, page)) &&
                   static_cast<bool>(vm.map(owned_base, page, rw)) &&
                   static_cast<bool>(vm.write(owned_base, marker)),
               "guest replaces guarded allocation's first page");
        const auto rejected = group.reap_stopped_worker(w.thread_id);
        std::array<std::byte, 4> replacement_bytes{};
        expect(rejected.error == GuestThreadReapError::allocation_changed &&
                   group.find(w.thread_id) != nullptr &&
                   static_cast<bool>(vm.read(owned_base, replacement_bytes)) &&
                   replacement_bytes == marker,
               "provenance mismatch refuses to reclaim unrelated replacement pages");
        // Simulate application process teardown: an explicit guest munmap
        // removes both leases, including the foreign replacement.
        expect(static_cast<bool>(vm.unmap_range(owned_base, 2U * page)),
               "guest teardown can remove its own un-reapable stack region");
    }
    expect(static_cast<bool>(vm.read(GuestThreadGroup::kStackArenaBase,
                                    foreign_bytes)) && foreign_bytes == marker,
           "unrelated synthetic slot remains intact after replacement case");

    // Phase51: retain a strict simultaneous-worker bound, but retire identities
    // on reap without recycling stale guest-visible IDs or Mach port names.
    {
        MachContext identity_mach;
        std::array<MachThreadIdentity, MachContext::kMaxGuestThreads - 1U> issued{};
        bool allocations_ok = true;
        for (auto& identity : issued) {
            const auto allocated = identity_mach.allocate_worker_thread_identity();
            if (!allocated) {
                allocations_ok = false;
                break;
            }
            identity = *allocated;
        }
        const auto saturated = identity_mach.allocate_worker_thread_identity();
        const MachThreadIdentity forged{
            issued[0].thread_id, issued[1].thread_self_port};
        const bool rejected_forgery =
            !identity_mach.retire_worker_thread_identity(forged);
        const bool retired =
            identity_mach.retire_worker_thread_identity(issued[0]);
        const bool rejected_duplicate =
            !identity_mach.retire_worker_thread_identity(issued[0]);
        const auto next = identity_mach.allocate_worker_thread_identity();
        expect(allocations_ok && !saturated && rejected_forgery &&
                   retired && rejected_duplicate && next.has_value() &&
                   next->thread_id > issued.back().thread_id &&
                   next->thread_self_port > issued.back().thread_self_port &&
                   !identity_mach.is_active_worker_thread_identity(issued[0]) &&
                   identity_mach.is_active_worker_thread_identity(*next) &&
                   !identity_mach.allocate_worker_thread_identity(),
               "active Mach worker cap remains bounded but retired identities never alias");
    }

    {
        MachContext churn_mach;
        constexpr std::size_t cycles = MachContext::kMaxGuestThreads + 5U;
        GuestThreadGroup churn(vm, churn_mach, cycles + 2U);
        const auto m = churn.add_main(main);
        CaptureHost host;
        bool safe = static_cast<bool>(m);
        std::uint64_t last_id = 0;
        std::uint32_t last_port = 0;
        for (std::size_t index = 0; index < cycles && safe; ++index) {
            const auto added = churn.add_owned_worker(worker, page);
            const GuestThread* current = churn.find(added.thread_id);
            if (!added || current == nullptr || !current->owned_stack ||
                added.thread_id <= last_id ||
                current->identity.thread_self_port <= last_port) {
                safe = false;
                break;
            }
            last_id = added.thread_id;
            last_port = current->identity.thread_self_port;
            // The earlier foreign mapping occupies slot zero. Check the
            // actual leased slot, never unrelated guest memory.
            const std::uint64_t owned_base = current->owned_stack->base;
            ScriptedBackend terminate({{svc(1), false, 0, 0, 0, 0}});
            const auto stopped = churn.run_slice(added.thread_id, terminate, host, 1U);
            const auto reclaimed = churn.reap_stopped_worker(added.thread_id);
            if (!stopped || stopped.process.reason != ProcessStopReason::thread_exited ||
                !reclaimed || churn.find(added.thread_id) != nullptr ||
                churn.size() != 1U ||
                vm.allocation_id_at(owned_base)) {
                safe = false;
            }
        }
        expect(safe && churn.remaining_budget() == 2U,
               "more than 63 guarded workers run and reap sequentially without port aliasing");
    }

    // A host context group ending with live workers also gives its Mach
    // identity slots back, while the old numeric identity remains retired.
    {
        MachContext context;
        std::uint64_t last_id = 0;
        {
            GuestThreadGroup group(vm, context, 2U);
            const auto m = group.add_main(main);
            bool filled = static_cast<bool>(m);
            for (std::size_t index = 0;
                 index < MachContext::kMaxGuestThreads - 1U && filled; ++index) {
                const auto w = group.add_worker(worker);
                filled = static_cast<bool>(w);
                if (w) last_id = w.thread_id;
            }
            expect(filled && !context.allocate_worker_thread_identity(),
                   "active group occupies the entire worker identity cap");
        }
        const auto after_destroy = context.allocate_worker_thread_identity();
        expect(after_destroy && after_destroy->thread_id > last_id,
               "host group destruction retires worker slots without id reuse");
    }
}
