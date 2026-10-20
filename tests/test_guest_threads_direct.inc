// Separate executable guest register contexts bound to one Mach process.
void test_guest_threads_direct() {
    using namespace macosarm;
    constexpr std::uint64_t code = 0x190000000ULL;
    constexpr std::uint64_t stack = 0x1a0000000ULL;
    GuestAddressSpace vm;
    const std::array<std::byte, 4> nop{
        std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5}};
    const auto rw = Protection::read | Protection::write;
    expect(static_cast<bool>(vm.map(code, vm.kPageSize,
                   Protection::read | Protection::execute)) &&
               static_cast<bool>(vm.load_bytes(code, nop)) &&
               static_cast<bool>(vm.map(stack, 2U * vm.kPageSize, rw)),
           "thread tests map executable A64 code and two writable stacks");

    MachContext mach;
    GuestThreadGroup group(vm, mach, 3U);
    CpuState initial{};
    initial.pc = code;
    initial.sp = stack + vm.kPageSize;
    initial.tpidrro_el0 = stack + 0x100U;
    initial.x[16] = kDarwinSysThreadSelfid;
    CpuState worker = initial;
    worker.sp += vm.kPageSize;
    worker.tpidrro_el0 += vm.kPageSize;
    expect(group.add_worker(worker).error == GuestThreadAddError::missing_main,
           "worker cannot be registered without a main thread");
    const auto first = group.add_main(initial);
    const auto duplicate = group.add_main(initial);
    worker.sp -= 1U;
    const auto invalid = group.add_worker(worker);
    worker.sp += 1U;
    const auto second = group.add_worker(worker);
    expect(static_cast<bool>(first) && static_cast<bool>(second) &&
               first.thread_id == mach.thread_id() &&
               first.thread_id != second.thread_id &&
               duplicate.error == GuestThreadAddError::duplicate_main &&
               invalid.error == GuestThreadAddError::invalid_cpu &&
               group.size() == 2U,
           "thread table preserves one main thread and validates worker state");

    CaptureHost host;
    ScriptedBackend first_backend({{svc(1), false, 0, 0, 0, 0}});
    ScriptedBackend second_backend({{svc(1), false, 0, 0, 0, 0}});
    const auto first_slice = group.run_slice(first.thread_id, first_backend, host, 1U);
    const auto second_slice = group.run_slice(second.thread_id, second_backend, host, 1U);
    const GuestThread* a = group.find(first.thread_id);
    const GuestThread* b = group.find(second.thread_id);
    expect(static_cast<bool>(first_slice) && static_cast<bool>(second_slice) &&
               first_slice.process.reason == ProcessStopReason::instruction_budget &&
               second_slice.process.reason == ProcessStopReason::instruction_budget &&
               a != nullptr && b != nullptr &&
               a->cpu.x[0] == first.thread_id && b->cpu.x[0] == second.thread_id &&
               a->cpu.tpidrro_el0 != b->cpu.tpidrro_el0 &&
               group.remaining_budget() == 1U,
           "serialized guest execution has distinct BSD identities, registers and TLS");
    ScriptedBackend unused_backend({{svc(1), false, 0, 0, 0, 0}});
    expect(group.run_slice(first.thread_id, unused_backend, host, 0U).error ==
                   GuestThreadRunError::invalid_quantum &&
               group.run_slice(UINT64_MAX, unused_backend, host, 1U).error ==
                   GuestThreadRunError::unknown_thread &&
               unused_backend.calls() == 0U,
           "zero quantum and unknown identity cannot execute guest instructions");
    ScriptedBackend last_backend({{svc(1), false, 0, 0, 0, 0}});
    const auto last = group.run_slice(first.thread_id, last_backend, host, 10U);
    expect(static_cast<bool>(last) && group.remaining_budget() == 0U &&
               group.run_slice(second.thread_id, unused_backend, host, 1U).error ==
                   GuestThreadRunError::budget_exhausted,
           "process-wide instruction limit caps all thread slices together");

    MachContext port_mach;
    GuestThreadGroup ports(vm, port_mach, 2U);
    initial.x[16] = static_cast<std::uint64_t>(kMachTrapThreadSelf);
    worker.x[16] = static_cast<std::uint64_t>(kMachTrapThreadSelf);
    const auto pm = ports.add_main(initial);
    const auto pw = ports.add_worker(worker);
    ScriptedBackend port_backend({{svc(1), false, 0, 0, 0, 0}});
    const auto port_call = ports.run_slice(pw.thread_id, port_backend, host, 1U);
    const GuestThread* port_worker = ports.find(pw.thread_id);
    expect(static_cast<bool>(pm) && static_cast<bool>(pw) &&
               static_cast<bool>(port_call) && port_worker != nullptr &&
               port_worker->cpu.x[0] == port_worker->identity.thread_self_port &&
               port_worker->identity.thread_self_port != port_mach.thread_self_port(),
           "Mach thread_self returns the executing worker's guest port");

    MachContext exit_mach;
    GuestThreadGroup exiting(vm, exit_mach, 10U);
    initial.x[16] = kDarwinSysExit;
    worker.x[16] = kDarwinSysThreadSelfid;
    const auto exmain = exiting.add_main(initial);
    const auto exworker = exiting.add_worker(worker);
    ScriptedBackend exit_backend({{svc(1), true, 7, 0, 0, kDarwinSysExit}});
    const auto exited = exiting.run_slice(exmain.thread_id, exit_backend, host, 2U);
    expect(static_cast<bool>(exited) && exiting.stopped() &&
               exited.process.reason == ProcessStopReason::exited &&
               exited.process.exit_status == 7 &&
               exiting.run_slice(exworker.thread_id, unused_backend, host, 1U).error ==
                   GuestThreadRunError::stopped &&
               exiting.add_worker(worker).error == GuestThreadAddError::process_stopped,
           "BSD process exit stops sibling contexts and forbids new workers");
    MachContext different_process;
    expect(different_process.process_id() != mach.process_id() &&
               host.calls == 0U,
           "Mach process namespace and host I/O remain isolated");

    // Phase48: a guest context may exit without shutting down sibling
    // contexts. Zero-resource bsdthread_terminate is a bounded subset of
    // XNU syscall 361, not evidence of working pthread registration.
    MachContext terminate_mach;
    GuestThreadGroup terminating(vm, terminate_mach, 8U);
    CpuState terminating_main = initial;
    terminating_main.x[0] = 0U;
    terminating_main.x[1] = 0U;
    terminating_main.x[2] = 0U;
    terminating_main.x[3] = 0U;
    terminating_main.x[16] = kDarwinSysBsdthreadTerminate;
    CpuState survivor = worker;
    survivor.x[16] = kDarwinSysThreadSelfid;
    const auto terminated_id = terminating.add_main(terminating_main);
    const auto survivor_id = terminating.add_worker(survivor);
    ScriptedBackend terminating_backend({{svc(1), false, 0, 0, 0, 0}});
    const auto terminated = terminating.run_slice(
        terminated_id.thread_id, terminating_backend, host, 4U);
    ScriptedBackend survivor_backend({{svc(1), false, 0, 0, 0, 0}});
    const auto survived = terminating.run_slice(
        survivor_id.thread_id, survivor_backend, host, 1U);
    const GuestThread* stopped_context = terminating.find(terminated_id.thread_id);
    const GuestThread* running_context = terminating.find(survivor_id.thread_id);
    expect(static_cast<bool>(terminated_id) && static_cast<bool>(survivor_id) &&
               static_cast<bool>(terminated) &&
               terminated.process.reason == ProcessStopReason::thread_exited &&
               terminated.process.instructions_executed == 1U &&
               !terminating.stopped() &&
               stopped_context != nullptr &&
               stopped_context->status == GuestThreadStatus::stopped &&
               static_cast<bool>(survived) &&
               survived.process.reason == ProcessStopReason::instruction_budget &&
               running_context != nullptr &&
               running_context->status == GuestThreadStatus::runnable &&
               running_context->cpu.x[0] == survivor_id.thread_id &&
               terminating.remaining_budget() == 6U &&
               terminating.run_slice(terminated_id.thread_id, unused_backend,
                                     host, 1U).error == GuestThreadRunError::stopped,
           "bsdthread_terminate stops only its context and sibling keeps running");

    // A registered pthread may hand stack memory, semaphore and port rights
    // to the kernel. Reject requests needing unsupported cleanup, without
    // mutating mappings or claiming the calling thread has exited.
    MachContext cleanup_mach;
    const MachThreadIdentity main_identity = cleanup_mach.main_thread_identity();
    GuestThreadGroup cleanup_group(vm, cleanup_mach, 2U);
    CpuState cleanup_main = terminating_main;
    cleanup_main.x[0] = stack;
    cleanup_main.x[1] = vm.kPageSize;
    const auto cleanup_id = cleanup_group.add_main(cleanup_main);
    ScriptedBackend cleanup_backend({{svc(1), false, 0, 0, 0, 0}});
    const auto cleanup_result = cleanup_group.run_slice(
        cleanup_id.thread_id, cleanup_backend, host, 1U);
    const GuestThread* cleanup_context = cleanup_group.find(cleanup_id.thread_id);
    expect(static_cast<bool>(cleanup_id) &&
               static_cast<bool>(cleanup_result) &&
               cleanup_result.process.reason == ProcessStopReason::instruction_budget &&
               cleanup_context != nullptr &&
               cleanup_context->status == GuestThreadStatus::runnable &&
               cleanup_context->cpu.x[0] == kDarwinErrnoEnosys &&
               (cleanup_context->cpu.pstate & kA64PstateCarry) != 0U &&
               !cleanup_group.stopped() &&
               static_cast<bool>(vm.probe_write(stack, vm.kPageSize)),
           "unsupported stack reclamation fails closed without altering guest VM");

    CpuState port_cleanup = terminating_main;
    port_cleanup.x[2] = terminate_mach.thread_self_port();
    const auto port_rejected = dispatch_darwin_syscall(
        port_cleanup, vm, svc(1), host, cleanup_mach,
        &main_identity);
    expect(port_rejected.action == SyscallAction::resume &&
               port_cleanup.x[0] == kDarwinErrnoEnosys &&
               (port_cleanup.pstate & kA64PstateCarry) != 0U,
           "unimplemented Mach port cleanup fails closed");

    CpuState semaphore_cleanup = terminating_main;
    semaphore_cleanup.x[3] = 1U;
    const auto sem_rejected = dispatch_darwin_syscall(
        semaphore_cleanup, vm, svc(1), host, cleanup_mach,
        &main_identity);
    expect(sem_rejected.action == SyscallAction::resume &&
               semaphore_cleanup.x[0] == kDarwinErrnoEnosys,
           "unimplemented semaphore signaling fails closed");

    CpuState legacy_terminate = terminating_main;
    const auto legacy_result = dispatch_darwin_syscall(
        legacy_terminate, vm, svc(1), host, cleanup_mach);
    expect(legacy_result.action == SyscallAction::resume &&
               legacy_terminate.x[0] == kDarwinErrnoEnosys &&
               (legacy_terminate.pstate & kA64PstateCarry) != 0U,
           "legacy process runner cannot fake a thread termination");


    // Phase54: owned stack and pthread-shaped tail have one provenance lease;
    // TSD slot 0 is pthread_self, slot 3 is the per-worker Mach thread port.
    {
        MachContext tls_mach;
        GuestThreadGroup tls_group(vm, tls_mach, 8U);
        CpuState main_cpu{};
        main_cpu.pc = code;
        main_cpu.sp = stack + vm.kPageSize;
        const auto main_id = tls_group.add_main(main_cpu);
        CpuState worker_cpu = main_cpu;
        worker_cpu.x[16] = kDarwinSysBsdthreadTerminate;
        worker_cpu.tpidrro_el0 = UINT64_MAX;
        expect(static_cast<bool>(main_id) &&
                   tls_group.add_owned_worker_with_tsd(
                       worker_cpu, vm.kPageSize, 16U, 0U).error ==
                       GuestThreadAddError::invalid_stack_size &&
                   tls_group.add_owned_worker_with_tsd(
                       worker_cpu, vm.kPageSize, 256U, 248U).error ==
                       GuestThreadAddError::invalid_stack_size &&
                   tls_group.add_owned_worker_with_tsd(
                       worker_cpu, vm.kPageSize, 512U, 225U).error ==
                       GuestThreadAddError::invalid_stack_size &&
                   tls_group.size() == 1U &&
                   !vm.allocation_id_at(GuestThreadGroup::kStackArenaBase),
               "invalid pthread TLS geometry has no guest VM side effects");
        const auto a = tls_group.add_owned_worker_with_tsd(
            worker_cpu, vm.kPageSize, 512U, 224U);
        const auto b = tls_group.add_owned_worker_with_tsd(
            worker_cpu, vm.kPageSize, 512U, 224U);
        const GuestThread* ta = tls_group.find(a.thread_id);
        const GuestThread* tb = tls_group.find(b.thread_id);
        const auto read64 = [&](std::uint64_t address)
            -> std::optional<std::uint64_t> {
            std::array<std::byte, 8> bytes{};
            if (!vm.read(address, bytes)) return std::nullopt;
            std::uint64_t value = 0;
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                value |= static_cast<std::uint64_t>(
                    std::to_integer<unsigned char>(bytes[i])) << (i * 8U);
            }
            return value;
        };
        expect(a && b && ta && tb && ta->owned_stack && tb->owned_stack &&
                   a.thread_id != b.thread_id &&
                   ta->cpu.tpidrro_el0 != tb->cpu.tpidrro_el0 &&
                   ta->cpu.sp == ta->owned_stack->pthread_base &&
                   tb->cpu.sp == tb->owned_stack->pthread_base &&
                   ta->cpu.tpidrro_el0 == ta->owned_stack->tsd_base &&
                   tb->cpu.tpidrro_el0 == tb->owned_stack->tsd_base &&
                   ta->owned_stack->pthread_size == 512U &&
                   read64(ta->cpu.tpidrro_el0) == ta->owned_stack->pthread_base &&
                   read64(tb->cpu.tpidrro_el0) == tb->owned_stack->pthread_base &&
                   read64(ta->cpu.tpidrro_el0 + 24U) ==
                       ta->identity.thread_self_port &&
                   read64(tb->cpu.tpidrro_el0 + 24U) ==
                       tb->identity.thread_self_port &&
                   vm.probe_write(ta->owned_stack->base, 8U).error ==
                       VmError::protection &&
                   static_cast<bool>(vm.probe_write(ta->cpu.sp - 16U, 16U)) &&
                   !tls_mach.pthread_registered(),
               "worker pthread_self, Mach TLS and guard page are isolated");
        const GuestOwnedStack lease_a = ta && ta->owned_stack
            ? *ta->owned_stack : GuestOwnedStack{};
        const GuestOwnedStack lease_b = tb && tb->owned_stack
            ? *tb->owned_stack : GuestOwnedStack{};
        ScriptedBackend backend_a({{svc(1), false, 0, 0, 0, 0}});
        ScriptedBackend backend_b({{svc(1), false, 0, 0, 0, 0}});
        const auto exit_a = tls_group.run_slice(a.thread_id, backend_a, host, 1U);
        const auto exit_b = tls_group.run_slice(b.thread_id, backend_b, host, 1U);
        const auto reap_a = tls_group.reap_stopped_worker(a.thread_id);
        const auto reap_b = tls_group.reap_stopped_worker(b.thread_id);
        expect(exit_a && exit_b &&
                   exit_a.process.reason == ProcessStopReason::thread_exited &&
                   exit_b.process.reason == ProcessStopReason::thread_exited &&
                   reap_a && reap_b && tls_group.size() == 1U &&
                   !vm.allocation_id_at(lease_a.base) &&
                   !vm.allocation_id_at(lease_b.base) &&
                   !tls_group.stopped() && tls_group.remaining_budget() == 6U,
               "pthread TLS plus stack are reaped by one guarded allocation token");
    }

}
