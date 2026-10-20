// Phase56: main TLS is a guarded host-managed lease, independent of the
// externally owned main stack. It is not successful bsdthread_register.
void test_main_thread_errno_tls_direct() {
    using namespace macosarm;
    GuestAddressSpace vm;
    constexpr std::uint64_t code = 0x390000000ULL;
    constexpr std::uint64_t stack = 0x391000000ULL;
    constexpr auto page = GuestAddressSpace::kPageSize;
    const std::array<std::byte, 4> nop{
        std::byte{0x1f}, std::byte{0x20}, std::byte{0x03}, std::byte{0xd5}};
    const auto rw = Protection::read | Protection::write;
    expect(static_cast<bool>(vm.map(code, page,
                   Protection::read | Protection::execute)) &&
               static_cast<bool>(vm.load_bytes(code, nop)) &&
               static_cast<bool>(vm.map(stack, page, rw)),
           "main TLS test maps ARM64 entrypoint and externally owned stack");
    std::uint64_t tls_address = 0U;
    std::uint64_t pthread_address = 0U;
    {
        MachContext mach;
        GuestThreadGroup group(vm, mach, 8U);
        CpuState cpu{};
        cpu.pc = code;
        cpu.sp = stack + page;
        const auto early = group.initialize_main_pthread_errno_tsd(
            512U, 224U, 172U);
        const auto main = group.add_main(cpu);
        const auto bad_align = group.initialize_main_pthread_errno_tsd(
            512U, 224U, 173U);
        const auto bad_range = group.initialize_main_pthread_errno_tsd(
            512U, 224U, 224U);
        const auto bad_tsd = group.initialize_main_pthread_errno_tsd(
            512U, 504U, 172U);
        expect(early.error == GuestThreadAddError::missing_main &&
                   static_cast<bool>(main) &&
                   bad_align.error == GuestThreadAddError::invalid_stack_size &&
                   bad_range.error == GuestThreadAddError::invalid_stack_size &&
                   bad_tsd.error == GuestThreadAddError::invalid_stack_size &&
                   group.size() == 1U &&
                   group.find(main.thread_id)->cpu.tpidrro_el0 == 0U &&
                   !vm.allocation_id_at(GuestThreadGroup::kMainTlsArenaBase),
               "invalid main TLS configuration has no side effects");

        const auto ready = group.initialize_main_pthread_errno_tsd(
            512U, 224U, 172U);
        const GuestThread* main_thread = group.find(main.thread_id);
        const auto read64 = [&](std::uint64_t at) -> std::optional<std::uint64_t> {
            std::array<std::byte, 8> bytes{};
            if (!vm.read(at, bytes)) return std::nullopt;
            std::uint64_t value = 0U;
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                value |= static_cast<std::uint64_t>(
                    std::to_integer<unsigned char>(bytes[i])) << (8U * i);
            }
            return value;
        };
        const GuestOwnedStack lease = main_thread && main_thread->owned_stack
            ? *main_thread->owned_stack : GuestOwnedStack{};
        pthread_address = lease.pthread_base;
        tls_address = lease.tsd_base;
        std::array<std::byte, 4> errno_value{};
        expect(ready && ready.thread_id == main.thread_id &&
                   main_thread && main_thread->owned_stack &&
                   main_thread->cpu.sp == cpu.sp &&
                   main_thread->cpu.tpidrro_el0 == tls_address &&
                   lease.base == GuestThreadGroup::kMainTlsArenaBase &&
                   lease.pthread_size == 512U &&
                   read64(tls_address) == pthread_address &&
                   read64(tls_address + 8U) == lease.errno_address &&
                   read64(tls_address + 16U) == 0U &&
                   read64(tls_address + 24U) == mach.thread_self_port() &&
                   static_cast<bool>(vm.read(lease.errno_address, errno_value)) &&
                   errno_value == std::array<std::byte, 4>{} &&
                   vm.probe_write(lease.base, 8U).error == VmError::protection &&
                   static_cast<bool>(vm.probe_write(cpu.sp - 16U, 16U)) &&
                   !mach.pthread_registered(),
               "main has its own pthread_self, errno, Mach self and sealed guard");

        const auto duplicate = group.initialize_main_pthread_errno_tsd(
            512U, 224U, 172U);
        expect(duplicate.error == GuestThreadAddError::duplicate_main &&
                   group.find(main.thread_id)->cpu.tpidrro_el0 == tls_address,
               "main TLS is initialized only once without losing state");

        CpuState worker = cpu;
        const auto added = group.add_owned_worker_with_errno_tsd(
            worker, page, 512U, 224U, 172U);
        const GuestThread* other = group.find(added.thread_id);
        expect(added && other && other->owned_stack &&
                   other->cpu.tpidrro_el0 != tls_address &&
                   other->owned_stack->errno_address != lease.errno_address &&
                   other->identity.thread_self_port != mach.thread_self_port() &&
                   group.size() == 2U &&
                   !mach.pthread_registered(),
               "owned worker TLS and main TLS are independent and unregistered");
        std::array<std::byte, 4> errno_write{
            std::byte{0x2a}, std::byte{0}, std::byte{0}, std::byte{0}};
        expect(static_cast<bool>(vm.write(lease.errno_address, errno_write)) &&
                   static_cast<bool>(vm.read(lease.errno_address, errno_value)) &&
                   errno_value == errno_write,
               "main errno field is guest-writable through its TLS pointer");
    }
    std::array<std::byte, 8> reclaimed{};
    expect(vm.read(tls_address, reclaimed).error == VmError::unmapped &&
               vm.read(pthread_address, reclaimed).error == VmError::unmapped &&
               !vm.allocation_id_at(GuestThreadGroup::kMainTlsArenaBase) &&
               static_cast<bool>(vm.probe_write(stack, page)),
           "main TLS lease is reclaimed on group destruction, external stack kept");
}
