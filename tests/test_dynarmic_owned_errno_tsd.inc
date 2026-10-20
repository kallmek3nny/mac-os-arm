// Phase55: test real arm64 per-worker errno pointers and writable fields
// via TPIDRRO_EL0. This is guest cooperative execution, not pthread_create.
int dynarmic_owned_errno_tsd_main() {
    using namespace macosarm;
    constexpr std::uint64_t code = 0x350000000ULL;
    constexpr std::uint64_t main_stack = 0x351000000ULL;
    constexpr std::uint64_t result_base = 0x352000000ULL;
    constexpr auto page = GuestAddressSpace::kPageSize;
    GuestAddressSpace vm;
    const auto rw = Protection::read | Protection::write;
    if (!vm.map(code, page, Protection::read | Protection::execute) ||
        !vm.map(main_stack, page, rw) || !vm.map(result_base, page, rw)) {
        std::cerr << "FAIL: ARM64 errno TLS VM setup\n";
        return EXIT_FAILURE;
    }
    // Confirmed using clang AArch64 assembler: first four instructions
    // fetch PTHREAD_SELF, ERRNO and MACH_THREAD_SELF TSD addresses.
    constexpr std::array<std::uint32_t, 12> instructions{
        0xd53bd069U, // mrs x9, TPIDRRO_EL0
        0xf940012aU, // ldr x10, [x9] -> pthread
        0xf940052bU, // ldr x11, [x9, #8] -> errno_t*
        0xf9400d2cU, // ldr x12, [x9, #24] -> Mach thread-self
        0xf900026aU, // str x10, [x19]
        0xf900066bU, // str x11, [x19, #8]
        0xf9000a6cU, // str x12, [x19, #16]
        0xb9000174U, // str w20, [x11] -> worker-owned errno_t
        0xb940016dU, // ldr w13, [x11]
        0xb9001a6dU, // str w13, [x19, #24]
        0xd2802d30U, // mov x16, #361 (resource-free terminate)
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
        std::cerr << "FAIL: ARM64 errno test instructions load\n";
        return EXIT_FAILURE;
    }
    MachContext mach;
    GuestThreadGroup group(vm, mach, 24U);
    CpuState main{};
    main.pc = code;
    main.sp = main_stack + page;
    CpuState worker = main;
    worker.tpidrro_el0 = UINT64_MAX;
    worker.x[19] = result_base;
    worker.x[20] = 42U;
    const auto parent = group.add_main(main);
    const auto a = group.add_owned_worker_with_errno_tsd(
        worker, page, 512U, 224U, 172U);
    worker.x[19] = result_base + 32U;
    worker.x[20] = 14U;
    const auto b = group.add_owned_worker_with_errno_tsd(
        worker, page, 512U, 224U, 172U);
    const GuestThread* first = group.find(a.thread_id);
    const GuestThread* second = group.find(b.thread_id);
    if (!parent || !a || !b || !first || !second ||
        !first->owned_stack || !second->owned_stack ||
        first->cpu.tpidrro_el0 == second->cpu.tpidrro_el0) {
        std::cerr << "FAIL: errno TSD worker startup\n";
        return EXIT_FAILURE;
    }
    const GuestOwnedStack la = *first->owned_stack;
    const GuestOwnedStack lb = *second->owned_stack;
    const MachThreadIdentity ia = first->identity;
    const MachThreadIdentity ib = second->identity;
    DynarmicBackend backend;
    CooperativeThreadsHost host;
    const auto ea = group.run_slice(a.thread_id, backend, host, 12U);
    const auto eb = group.run_slice(b.thread_id, backend, host, 12U);
    const auto read64 = [&](std::uint64_t address) {
        std::array<std::byte, 8> value{};
        std::uint64_t result = 0U;
        if (!vm.read(address, value)) return result;
        for (std::size_t i = 0; i < value.size(); ++i) {
            result |= static_cast<std::uint64_t>(
                std::to_integer<unsigned char>(value[i])) << (8U * i);
        }
        return result;
    };
    const auto read32 = [&](std::uint64_t address) {
        std::array<std::byte, 4> value{};
        std::uint32_t result = 0U;
        if (!vm.read(address, value)) return result;
        for (std::size_t i = 0; i < value.size(); ++i) {
            result |= static_cast<std::uint32_t>(
                std::to_integer<unsigned char>(value[i])) << (8U * i);
        }
        return result;
    };
    if (!ea || !eb ||
        ea.process.reason != ProcessStopReason::thread_exited ||
        eb.process.reason != ProcessStopReason::thread_exited ||
        ea.process.instructions_executed != 12U ||
        eb.process.instructions_executed != 12U ||
        read64(result_base) != la.pthread_base ||
        read64(result_base + 32U) != lb.pthread_base ||
        read64(result_base + 8U) != la.errno_address ||
        read64(result_base + 40U) != lb.errno_address ||
        read64(result_base + 16U) != ia.thread_self_port ||
        read64(result_base + 48U) != ib.thread_self_port ||
        read32(result_base + 24U) != 42U ||
        read32(result_base + 56U) != 14U ||
        read32(la.errno_address) != 42U ||
        read32(lb.errno_address) != 14U ||
        group.remaining_budget() != 0U || group.stopped() ||
        host.writes != 0U || mach.pthread_registered()) {
        std::cerr << "FAIL: real ARM64 independent errno TSD values\n";
        return EXIT_FAILURE;
    }
    const auto ra = group.reap_stopped_worker(a.thread_id);
    const auto rb = group.reap_stopped_worker(b.thread_id);
    std::array<std::byte, 4> reclaimed{};
    if (!ra || !rb || group.size() != 1U ||
        vm.read(la.errno_address, reclaimed).error != VmError::unmapped ||
        vm.read(lb.errno_address, reclaimed).error != VmError::unmapped) {
        std::cerr << "FAIL: ARM64 errno worker backing retirement\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 independent worker errno TLS passed\n";
    return EXIT_SUCCESS;
}
