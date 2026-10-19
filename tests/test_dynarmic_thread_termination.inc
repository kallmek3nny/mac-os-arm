// Real ARM64 guest syscall #361 exits only the calling manually
// constructed context. A worker continues using the shared VM and its
// distinct TLS, then terminates cleanly. No real pthread registration.
int dynarmic_thread_termination_main() {
    using namespace macosarm;
    constexpr std::uint64_t code_addr = 0x280000000ULL;
    constexpr std::uint64_t stacks = 0x290000000ULL;
    constexpr std::uint64_t output = 0x2a0000000ULL;
    constexpr auto page = GuestAddressSpace::kPageSize;
    GuestAddressSpace vm;
    const auto rw = Protection::read | Protection::write;
    if (!vm.map(code_addr, page, Protection::read | Protection::execute) ||
        !vm.map(stacks, 2U * page, rw) ||
        !vm.map(output, page, rw)) {
        std::cerr << "FAIL: termination ARM64 regions map\n";
        return EXIT_FAILURE;
    }
    // main: bsdthread_terminate(0,0,0,0)
    // worker: thread_selfid -> shared guest VM -> bsdthread_terminate
    constexpr std::array<std::uint32_t, 10> insns{
        0xd2802d30U, // mov x16, #361
        0xd4001001U, // svc #0x80
        0xd503201fU, // nop, must never execute after termination
        0xd503201fU, // alignment padding
        0xd2802e90U, // mov x16, #372
        0xd4001001U, // svc #0x80
        0xf9000260U, // str x0, [x19]
        0xd2800000U, // mov x0, #0
        0xd2802d30U, // mov x16, #361
        0xd4001001U, // svc #0x80
    };
    std::array<std::byte, insns.size() * 4U> bytes{};
    for (std::size_t i = 0; i < insns.size(); ++i) {
        for (std::size_t j = 0; j < 4U; ++j) {
            bytes[i * 4U + j] = static_cast<std::byte>(
                (insns[i] >> (8U * j)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code_addr, bytes)) {
        std::cerr << "FAIL: termination ARM64 code load\n";
        return EXIT_FAILURE;
    }
    MachContext mach;
    GuestThreadGroup group(vm, mach, 8U);
    CpuState main{};
    main.pc = code_addr;
    main.sp = stacks + page;
    main.tpidrro_el0 = stacks + 0x100U;
    CpuState worker = main;
    worker.pc += 16U;
    worker.sp += page;
    worker.tpidrro_el0 += page;
    worker.x[19] = output;
    const auto main_id = group.add_main(main);
    const auto worker_id = group.add_worker(worker);
    if (!main_id || !worker_id) {
        std::cerr << "FAIL: termination guest context setup\n";
        return EXIT_FAILURE;
    }
    DynarmicBackend backend;
    CooperativeThreadsHost host;
    const auto main_stop = group.run_slice(main_id.thread_id, backend, host, 8U);
    const auto stopped_main = group.find(main_id.thread_id);
    if (!main_stop ||
        main_stop.process.reason != ProcessStopReason::thread_exited ||
        main_stop.process.instructions_executed != 2U ||
        group.stopped() || stopped_main == nullptr ||
        stopped_main->status != GuestThreadStatus::stopped) {
        std::cerr << "FAIL: translated bsdthread_terminate did not exit the caller\n";
        return EXIT_FAILURE;
    }
    const auto worker_stop = group.run_slice(worker_id.thread_id, backend, host, 8U);
    std::array<std::byte, 8> id_bytes{};
    if (!worker_stop ||
        worker_stop.process.reason != ProcessStopReason::thread_exited ||
        worker_stop.process.instructions_executed != 6U ||
        !vm.read(output, id_bytes)) {
        std::cerr << "FAIL: translated sibling cannot run and terminate\n";
        return EXIT_FAILURE;
    }
    std::uint64_t observed = 0;
    for (std::size_t i = 0; i < id_bytes.size(); ++i) {
        observed |= static_cast<std::uint64_t>(
            std::to_integer<unsigned char>(id_bytes[i])) << (i * 8U);
    }
    const auto* worker_final = group.find(worker_id.thread_id);
    if (observed != worker_id.thread_id || worker_final == nullptr ||
        worker_final->status != GuestThreadStatus::stopped ||
        worker_final->cpu.tpidrro_el0 == main.tpidrro_el0 ||
        group.remaining_budget() != 0U || group.stopped() ||
        host.writes != 0U) {
        std::cerr << "FAIL: terminated guest context isolation or budget\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 per-context bsdthread_terminate passed\n";
    return EXIT_SUCCESS;
}
