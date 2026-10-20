// Phase54: real ARM64 loads from TPIDRRO_EL0 and source-observed
// libpthread slots in independently managed worker TLS allocations.
int dynarmic_owned_pthread_tsd_main() {
    using namespace macosarm;
    constexpr std::uint64_t code = 0x330000000ULL;
    constexpr std::uint64_t main_stack = 0x331000000ULL;
    constexpr std::uint64_t results = 0x332000000ULL;
    constexpr std::uint64_t page = GuestAddressSpace::kPageSize;
    GuestAddressSpace vm;
    const auto rw = Protection::read | Protection::write;
    if (!vm.map(code, page, Protection::read | Protection::execute) ||
        !vm.map(main_stack, page, rw) || !vm.map(results, page, rw)) {
        std::cerr << "FAIL: owned pthread TLS mappings\n";
        return EXIT_FAILURE;
    }
    constexpr std::array<std::uint32_t, 7> instructions{
        0xd53bd069U, // mrs x9, TPIDRRO_EL0
        0xf940012aU, // ldr x10, [x9] (pthread_self)
        0xf9400d2bU, // ldr x11, [x9, #24] (Mach thread self)
        0xf900026aU, // str x10, [x19]
        0xf900066bU, // str x11, [x19, #8]
        0xd2802d30U, // mov x16, #361 (bsdthread_terminate)
        0xd4001001U, // svc #0x80
    };
    std::array<std::byte, instructions.size() * 4U> bytes{};
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        for (std::size_t j = 0; j < 4U; ++j) {
            bytes[4U * i + j] = static_cast<std::byte>(
                (instructions[i] >> (8U * j)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code, bytes)) {
        std::cerr << "FAIL: ARM64 TLS program copyin\n";
        return EXIT_FAILURE;
    }
    MachContext mach;
    GuestThreadGroup group(vm, mach, 14U);
    CpuState main{};
    main.pc = code;
    main.sp = main_stack + page;
    CpuState worker = main;
    worker.tpidrro_el0 = UINT64_MAX;
    worker.x[19] = results;
    const auto m = group.add_main(main);
    const auto a = group.add_owned_worker_with_tsd(worker, page, 512U, 224U);
    worker.x[19] = results + 32U;
    const auto b = group.add_owned_worker_with_tsd(worker, page, 512U, 224U);
    const GuestThread* first = group.find(a.thread_id);
    const GuestThread* second = group.find(b.thread_id);
    if (!m || !a || !b || !first || !second ||
        !first->owned_stack || !second->owned_stack ||
        first->cpu.tpidrro_el0 == second->cpu.tpidrro_el0) {
        std::cerr << "FAIL: owned ARM64 pthread workers allocate\n";
        return EXIT_FAILURE;
    }
    const GuestOwnedStack la = *first->owned_stack;
    const GuestOwnedStack lb = *second->owned_stack;
    const MachThreadIdentity ia = first->identity;
    const MachThreadIdentity ib = second->identity;
    DynarmicBackend backend;
    CooperativeThreadsHost host;
    const auto ea = group.run_slice(a.thread_id, backend, host, 7U);
    const auto eb = group.run_slice(b.thread_id, backend, host, 7U);
    const auto read64 = [&](std::uint64_t addr) {
        std::array<std::byte, 8> buf{};
        std::uint64_t value = 0U;
        if (!vm.read(addr, buf)) return value;
        for (std::size_t i = 0; i < buf.size(); ++i) {
            value |= static_cast<std::uint64_t>(
                std::to_integer<unsigned char>(buf[i])) << (8U * i);
        }
        return value;
    };
    if (!ea || !eb ||
        ea.process.reason != ProcessStopReason::thread_exited ||
        eb.process.reason != ProcessStopReason::thread_exited ||
        ea.process.instructions_executed != 7U ||
        eb.process.instructions_executed != 7U ||
        read64(results) != la.pthread_base ||
        read64(results + 32U) != lb.pthread_base ||
        read64(results + 8U) != ia.thread_self_port ||
        read64(results + 40U) != ib.thread_self_port ||
        group.remaining_budget() != 0U || group.stopped() ||
        host.writes != 0U || mach.pthread_registered()) {
        std::cerr << "FAIL: translated ARM64 pthread_self and thread port slots\n";
        return EXIT_FAILURE;
    }
    const auto ra = group.reap_stopped_worker(a.thread_id);
    const auto rb = group.reap_stopped_worker(b.thread_id);
    std::array<std::byte, 8> gone{};
    if (!ra || !rb || group.size() != 1U ||
        vm.read(la.tsd_base, gone).error != VmError::unmapped ||
        vm.read(lb.tsd_base, gone).error != VmError::unmapped ||
        vm.probe_write(la.base, 8U).error != VmError::unmapped ||
        vm.probe_write(lb.base, 8U).error != VmError::unmapped) {
        std::cerr << "FAIL: owned TLS is reclaimed with stopped worker stack\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 owned pthread-shaped TLS passed\n";
    return EXIT_SUCCESS;
}
