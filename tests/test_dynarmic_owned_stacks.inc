// Phase49: execute *real* A64 guest stack writes and bsdthread_terminate,
// then reclaim the stack only while its VM allocation lease remains valid.
int dynarmic_owned_stacks_main() {
    using namespace macosarm;
    constexpr std::uint64_t code = 0x2d0000000ULL;
    constexpr std::uint64_t main_stack = 0x2e0000000ULL;
    constexpr std::uint64_t sentinel = 0x1122334455667788ULL;
    constexpr auto page = GuestAddressSpace::kPageSize;
    const auto rw = Protection::read | Protection::write;
    GuestAddressSpace vm;
    if (!vm.map(code, page, Protection::read | Protection::execute) ||
        !vm.map(main_stack, page, rw)) {
        std::cerr << "FAIL: real A64 owned-stack mappings\n";
        return EXIT_FAILURE;
    }
    constexpr std::array<std::uint32_t, 4> instructions{
        0xd10043ffU, // sub sp, sp, #16
        0xf90003f3U, // str x19, [sp]
        0xd2802d30U, // mov x16, #361 (bsdthread_terminate)
        0xd4001001U, // svc #0x80
    };
    std::array<std::byte, instructions.size() * 4U> bytes{};
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        for (std::size_t j = 0; j < 4U; ++j) {
            bytes[i * 4U + j] = static_cast<std::byte>(
                (instructions[i] >> (j * 8U)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code, bytes)) {
        std::cerr << "FAIL: real A64 owned-stack code loads\n";
        return EXIT_FAILURE;
    }

    MachContext mach;
    GuestThreadGroup group(vm, mach, 8U);
    CpuState main{};
    main.pc = code;
    main.sp = main_stack + page;
    CpuState worker = main;
    worker.x[19] = sentinel;
    const auto first = group.add_main(main);
    const auto second = group.add_owned_worker(worker, 2U * page);
    const GuestThread* started = group.find(second.thread_id);
    if (!first || !second || started == nullptr || !started->owned_stack) {
        std::cerr << "FAIL: real A64 owned-stack setup\n";
        return EXIT_FAILURE;
    }
    const GuestOwnedStack lease = *started->owned_stack;
    const std::uint64_t top = started->cpu.sp;
    const std::uint64_t probe_address = top - 16U;
    if (lease.base != GuestThreadGroup::kStackArenaBase ||
        vm.probe_write(lease.base, 16U).error != VmError::protection ||
        !vm.probe_write(probe_address, 16U)) {
        std::cerr << "FAIL: real A64 guard/writeable stack permissions\n";
        return EXIT_FAILURE;
    }

    DynarmicBackend backend;
    CooperativeThreadsHost host;
    const auto ended = group.run_slice(second.thread_id, backend, host, 8U);
    const GuestThread* final = group.find(second.thread_id);
    std::array<std::byte, sizeof(std::uint64_t)> stack_bytes{};
    if (!ended || ended.process.reason != ProcessStopReason::thread_exited ||
        ended.process.instructions_executed != 4U || group.stopped() ||
        final == nullptr || final->cpu.sp != probe_address ||
        final->status != GuestThreadStatus::stopped ||
        !vm.read(probe_address, stack_bytes)) {
        std::cerr << "FAIL: translated A64 stack instruction or thread termination\n";
        return EXIT_FAILURE;
    }
    std::uint64_t observed = 0;
    for (std::size_t i = 0; i < stack_bytes.size(); ++i) {
        observed |= static_cast<std::uint64_t>(
            std::to_integer<unsigned char>(stack_bytes[i])) << (i * 8U);
    }
    const auto reaped = group.reap_stopped_worker(second.thread_id);
    if (observed != sentinel || !reaped ||
        group.find(second.thread_id) != nullptr ||
        group.find(first.thread_id) == nullptr ||
        group.remaining_budget() != 4U || host.writes != 0U ||
        vm.read(probe_address, stack_bytes).error != VmError::unmapped ||
        vm.probe_write(lease.base, 16U).error != VmError::unmapped) {
        std::cerr << "FAIL: original stack contents and safe post-exit reclaim\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 guarded worker-stack ownership passed\n";
    return EXIT_SUCCESS;
}
