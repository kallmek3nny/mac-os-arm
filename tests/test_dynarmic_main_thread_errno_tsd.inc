// Phase56: real translated ARM64 main-thread TLS access, not a Darwin
// pthread registration. Both main and worker run with independent errno slots.
int dynarmic_main_thread_errno_tsd_main() {
    using namespace macosarm;
    constexpr std::uint64_t code = 0x3a0000000ULL;
    constexpr std::uint64_t stack = 0x3a1000000ULL;
    constexpr std::uint64_t results = 0x3a2000000ULL;
    constexpr auto page = GuestAddressSpace::kPageSize;
    GuestAddressSpace vm;
    const auto rw = Protection::read | Protection::write;
    if (!vm.map(code, page, Protection::read | Protection::execute) ||
        !vm.map(stack, page, rw) || !vm.map(results, page, rw)) {
        std::cerr << "FAIL: main ARM64 TLS fixture memory\n";
        return EXIT_FAILURE;
    }
    constexpr std::array<std::uint32_t, 12> instructions{
        0xd53bd069U, // mrs x9, TPIDRRO_EL0
        0xf940012aU, // ldr x10, [x9] : pthread_self
        0xf940052bU, // ldr x11, [x9, #8] : errno pointer
        0xf9400d2cU, // ldr x12, [x9, #24] : Mach thread-self
        0xf900026aU, // str x10, [x19]
        0xf900066bU, // str x11, [x19, #8]
        0xf9000a6cU, // str x12, [x19, #16]
        0xb9000174U, // str w20, [x11]
        0xb940016dU, // ldr w13, [x11]
        0xb9001a6dU, // str w13, [x19, #24]
        0xd2802d30U, // mov x16, #361 : resource-free bsdthread_terminate
        0xd4001001U, // svc #0x80
    };
    std::array<std::byte, instructions.size() * 4U> bytes{};
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        for (std::size_t j = 0; j < 4U; ++j) {
            bytes[i * 4U + j] = static_cast<std::byte>(
                (instructions[i] >> (8U * j)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code, bytes)) {
        std::cerr << "FAIL: main ARM64 TLS instructions\n";
        return EXIT_FAILURE;
    }
    MachContext mach;
    GuestThreadGroup group(vm, mach, 24U);
    CpuState main{};
    main.pc = code;
    main.sp = stack + page;
    main.tpidrro_el0 = UINT64_MAX;
    main.x[19] = results;
    main.x[20] = 73U;
    const auto main_id = group.add_main(main);
    const auto tls = group.initialize_main_pthread_errno_tsd(
        512U, 224U, 172U);
    CpuState worker = main;
    worker.x[19] = results + 32U;
    worker.x[20] = 19U;
    const auto worker_id = group.add_owned_worker_with_errno_tsd(
        worker, page, 512U, 224U, 172U);
    const GuestThread* a = group.find(main_id.thread_id);
    const GuestThread* b = group.find(worker_id.thread_id);
    if (!main_id || !tls || !worker_id || !a || !b ||
        !a->owned_stack || !b->owned_stack ||
        a->cpu.tpidrro_el0 == b->cpu.tpidrro_el0) {
        std::cerr << "FAIL: main ARM64 TLS initialization\n";
        return EXIT_FAILURE;
    }
    const GuestOwnedStack la = *a->owned_stack;
    const GuestOwnedStack lb = *b->owned_stack;
    DynarmicBackend backend;
    CooperativeThreadsHost host;
    const auto ea = group.run_slice(main_id.thread_id, backend, host, 12U);
    const auto eb = group.run_slice(worker_id.thread_id, backend, host, 12U);
    const auto read64 = [&](std::uint64_t address) {
        std::array<std::byte, 8> data{};
        std::uint64_t result = 0U;
        if (!vm.read(address, data)) return result;
        for (std::size_t i = 0; i < data.size(); ++i) {
            result |= static_cast<std::uint64_t>(
                std::to_integer<unsigned char>(data[i])) << (8U * i);
        }
        return result;
    };
    const auto read32 = [&](std::uint64_t address) {
        std::array<std::byte, 4> data{};
        std::uint32_t result = 0U;
        if (!vm.read(address, data)) return result;
        for (std::size_t i = 0; i < data.size(); ++i) {
            result |= static_cast<std::uint32_t>(
                std::to_integer<unsigned char>(data[i])) << (8U * i);
        }
        return result;
    };
    if (!ea || !eb ||
        ea.process.reason != ProcessStopReason::thread_exited ||
        eb.process.reason != ProcessStopReason::thread_exited ||
        ea.process.instructions_executed != 12U ||
        eb.process.instructions_executed != 12U ||
        read64(results) != la.pthread_base ||
        read64(results + 32U) != lb.pthread_base ||
        read64(results + 8U) != la.errno_address ||
        read64(results + 40U) != lb.errno_address ||
        read64(results + 16U) != mach.thread_self_port() ||
        read64(results + 48U) != b->identity.thread_self_port ||
        read32(results + 24U) != 73U ||
        read32(results + 56U) != 19U ||
        read32(la.errno_address) != 73U ||
        read32(lb.errno_address) != 19U ||
        group.remaining_budget() != 0U || group.stopped() ||
        host.writes != 0U || mach.pthread_registered()) {
        std::cerr << "FAIL: real ARM64 main versus worker errno isolation\n";
        return EXIT_FAILURE;
    }
    const auto reaped = group.reap_stopped_worker(worker_id.thread_id);
    std::array<std::byte, 4> reclaimed{};
    if (!reaped ||
        vm.read(lb.errno_address, reclaimed).error != VmError::unmapped ||
        !vm.read(la.errno_address, reclaimed) || group.size() != 1U) {
        std::cerr << "FAIL: main TLS survives worker teardown\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 main and worker errno TLS passed\n";
    return EXIT_SUCCESS;
}
