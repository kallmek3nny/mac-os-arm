#include "macosarm/mach_trap.hpp"

#include <bit>

namespace {

class PthreadMainThreadHost final : public macosarm::DarwinHostServices {
public:
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> bytes) override {
        return {bytes.size(), 0};
    }
};

void pthread_main_put_instruction(
    std::array<std::byte, macosarm::GuestAddressSpace::kPageSize>& page,
    std::size_t offset,
    std::uint32_t instruction) {
    for (std::size_t index = 0; index < 4U; ++index) {
        page.at(offset + index) =
            static_cast<std::byte>((instruction >> (index * 8U)) & 0xffU);
    }
}

void pthread_main_put_u32(
    std::span<std::byte> bytes,
    std::size_t offset,
    std::uint32_t value) {
    for (std::size_t index = 0; index < 4U; ++index) {
        bytes[offset + index] =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

std::uint64_t pthread_main_read_u64(
    const macosarm::GuestAddressSpace& vm,
    std::uint64_t address) {
    std::array<std::byte, 8> bytes{};
    if (!vm.read(address, bytes)) {
        return 0;
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return value;
}

std::uint32_t pthread_main_read_u32(
    const macosarm::GuestAddressSpace& vm,
    std::uint64_t address) {
    std::array<std::byte, 4> bytes{};
    if (!vm.read(address, bytes)) {
        return 0;
    }
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return value;
}

macosarm::ExecutionResult pthread_main_svc() {
    return {
        macosarm::StopReason::supervisor_call,
        1,
        macosarm::kDarwinSvcImmediate,
        macosarm::VmError::none,
    };
}

} // namespace

int dynarmic_pthread_main_thread_init_main() {
    using macosarm::CpuState;
    using macosarm::DynarmicBackend;
    using macosarm::GuestAddressSpace;
    using macosarm::MachContext;
    using macosarm::Protection;

    constexpr std::uint64_t code_base = 0x1a0000000ULL;
    constexpr std::uint64_t data_base = 0x2a0000000ULL;
    constexpr std::uint64_t pthread_base = data_base + 0x100ULL;
    constexpr std::uint64_t pthread_tsd = pthread_base + 224ULL;
    constexpr std::uint64_t pthread_errno = pthread_base + 172ULL;
    constexpr std::uint64_t options_address = data_base + 0x800ULL;
    constexpr std::uint64_t name_address = data_base + 0x900ULL;
    constexpr std::uint64_t fixture_qos = 0x15ULL;
    constexpr std::uint64_t fixture_ptr_munge = 0x123456789abcdef0ULL;

    GuestAddressSpace vm;
    if (!vm.map(
            code_base,
            GuestAddressSpace::kPageSize,
            Protection::read | Protection::execute) ||
        !vm.map(
            data_base,
            GuestAddressSpace::kPageSize,
            Protection::read | Protection::write)) {
        std::cerr << "FAIL: pthread main-thread probe maps guest pages\n";
        return EXIT_FAILURE;
    }

    std::array<std::byte, GuestAddressSpace::kPageSize> code{};
    const std::array<std::uint32_t, 62> instructions{
        0xd53bd069U, // mrs x9, TPIDRRO_EL0
        0xb4000749U, // cbz x9, failure
        0xd103812aU, // sub x10, x9, #224 -> pthread_self
        0xf900012aU, // str x10, [x9] -> PTHREAD_SELF slot 0
        0x9102b14bU, // add x11, x10, #172 -> &pthread->err_no
        0xf900052bU, // str x11, [x9, #8] -> ERRNO slot 1
        0xf9001134U, // str x20, [x9, #32] -> PTHREAD_QOS_CLASS slot 4
        0xf9001d35U, // str x21, [x9, #56] -> PTR_MUNGE slot 7
        0xf940012cU, // ldr x12, [x9]
        0xeb0a019fU, // cmp x12, x10
        0x54000621U, // b.ne failure
        0xf940052cU, // ldr x12, [x9, #8]
        0xeb0b019fU, // cmp x12, x11
        0x540005c1U, // b.ne failure
        0xf940112cU, // ldr x12, [x9, #32]
        0xeb14019fU, // cmp x12, x20
        0x54000561U, // b.ne failure
        0xf9401d2cU, // ldr x12, [x9, #56]
        0xeb15019fU, // cmp x12, x21
        0x54000501U, // b.ne failure
        0x92800350U, // mov x16, #-27 -> thread_self_trap
        0xd4001001U, // svc #0x80
        0xb40004a0U, // cbz x0, failure
        0xf9000d20U, // str x0, [x9, #24] -> MACH_THREAD_SELF slot 3
        0xf9400d32U, // ldr x18, [x9, #24]
        0xeb00025fU, // cmp x18, x0
        0x54000421U, // b.ne failure
        0x92800370U, // mov x16, #-28 -> task_self_trap
        0xd4001001U, // svc #0x80
        0xaa0003f3U, // mov x19, x0
        0xaa1303e0U, // mov x0, x19 -> target task
        0xaa1603e1U, // mov x1, x22 -> mach_port_options_t*
        0xd2800002U, // mov x2, #0 -> context
        0xaa1703e3U, // mov x3, x23 -> mach_port_name_t*
        0x928002f0U, // mov x16, #-24 -> mach_port_construct fast trap
        0xd4001001U, // svc #0x80
        0xb50002e0U, // cbnz x0, failure
        0xb94002f8U, // ldr w24, [x23] -> constructed reply port
        0x340002b8U, // cbz w24, failure
        0xf9000938U, // str x24, [x9, #16] -> MIG_REPLY slot 2
        0xf9400939U, // ldr x25, [x9, #16]
        0xeb18033fU, // cmp x25, x24
        0x54000221U, // b.ne failure
        // Apple's _pthread_main_thread_init clears the two Mach-related cache
        // slots after publishing MIG_REPLY; these are slots 8 and 9.
        0xf900213fU, // str xzr, [x9, #64] -> MACH_SPECIAL_REPLY slot 8
        0xf900253fU, // str xzr, [x9, #72] -> SEMAPHORE_CACHE slot 9
        // First kernel-facing operation after _pthread_main_thread_init:
        // _pthread_bsdthread_init calls __bsdthread_register (BSD #366).
        // Only assert its *current unsupported boundary*; do not manufacture
        // a successful thread registration or advertise kernel feature bits.
        0xaa1a03e0U, // mov x0, x26 -> thread_start fixture
        0xaa1a03e1U, // mov x1, x26 -> start_wqthread fixture
        0xd2880002U, // mov x2, #16384 -> bounded fixture pthread allocation
        0xaa1b03e3U, // mov x3, x27 -> registration data pointer
        0xd2800704U, // mov x4, #56 -> registration data size
        0xd2801405U, // mov x5, #160 -> dispatch queue TSD offset
        0xd2802dd0U, // mov x16, #366 -> bsdthread_register
        0xd4001001U, // svc #0x80
        0x540000c3U, // b.cc failure -> unsupported syscall must set carry
        0x7101381fU, // cmp w0, #78 -> Darwin ENOSYS
        0x54000081U, // b.ne failure
        0xd2800000U, // mov x0, #0
        0xd2800030U, // mov x16, #1 -> exit
        0xd4001001U, // svc #0x80
        0xd2800c60U, // failure: mov x0, #99
        0xd2800030U, // mov x16, #1 -> exit
        0xd4001001U, // svc #0x80
    };
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        pthread_main_put_instruction(code, index * 4U, instructions[index]);
    }
    if (!vm.load_bytes(code_base, code)) {
        std::cerr << "FAIL: pthread main-thread translated probe loads\n";
        return EXIT_FAILURE;
    }

    std::array<std::byte, macosarm::kMachPortOptionsSize> options{};
    pthread_main_put_u32(options, 0, macosarm::kMachPortOptionsReplyPort);
    if (!vm.load_bytes(options_address, options)) {
        std::cerr << "FAIL: pthread main-thread mach_port options load\n";
        return EXIT_FAILURE;
    }

    // Seed the direct slots with nonzero stale values so translated zeroing
    // is observable rather than passing on an initially zero guest page.
    std::array<std::byte, 16> stale_slots{};
    stale_slots.fill(std::byte{0xff});
    if (!vm.load_bytes(pthread_tsd + 64U, stale_slots)) {
        std::cerr << "FAIL: pthread main-thread stale cache TSD seed\n";
        return EXIT_FAILURE;
    }

    // Apple libpthread/kern/kern_internal.h defines a packed 56-byte
    // registration record; only source-observed input fields are populated.
    // The syscall is intentionally still unsupported, so this is not a
    // simulation of a completed bsdthread_register kernel registration.
    constexpr std::uint64_t registration_address = data_base + 0xa00ULL;
    std::array<std::byte, 56> registration_data{};
    pthread_main_put_u32(registration_data, 0U, 56U);   // version
    pthread_main_put_u32(registration_data, 8U, 160U);  // dispatch_queue_offset
    pthread_main_put_u32(registration_data, 24U, 224U); // tsd_offset
    pthread_main_put_u32(registration_data, 28U, 40U);  // return_to_kernel_offset
    pthread_main_put_u32(registration_data, 32U, 24U);  // mach_thread_self_offset
    pthread_main_put_u32(registration_data, 52U, 960U); // wq_quantum_expiry_offset
    if (!vm.load_bytes(registration_address, registration_data)) {
        std::cerr << "FAIL: pthread registration boundary data load\n";
        return EXIT_FAILURE;
    }

    CpuState state{};
    state.pc = code_base;
    state.sp = 0x700000000ULL;
    state.tpidrro_el0 = pthread_tsd;
    state.x[20] = fixture_qos;
    state.x[21] = fixture_ptr_munge;
    state.x[22] = options_address;
    state.x[23] = name_address;
    state.x[26] = code_base;
    state.x[27] = registration_address;

    PthreadMainThreadHost host;
    MachContext context;
    DynarmicBackend backend;
    const auto process = macosarm::run_process(state, vm, backend, host, context, 64U);
    if (process.reason != macosarm::ProcessStopReason::exited || process.exit_status != 0) {
        std::cerr << "FAIL: translated pthread main-thread syscall boundary reaches clean exit\n";
        return EXIT_FAILURE;
    }
    if (process.instructions_executed != 59U) {
        std::cerr << "FAIL: pthread main-thread proof executes exact source-order path\n";
        return EXIT_FAILURE;
    }

    const std::uint32_t reply_port = pthread_main_read_u32(vm, name_address);
    if (reply_port != MachContext::kFirstReplyPort || !context.is_receive_port(reply_port)) {
        std::cerr << "FAIL: mach_port_construct exposes a live synthetic reply receive port\n";
        return EXIT_FAILURE;
    }
    if (pthread_main_read_u64(vm, pthread_tsd) != pthread_base ||
        pthread_main_read_u64(vm, pthread_tsd + 8U) != pthread_errno ||
        pthread_main_read_u64(vm, pthread_tsd + 16U) != reply_port ||
        pthread_main_read_u64(vm, pthread_tsd + 24U) != context.thread_self_port() ||
        pthread_main_read_u64(vm, pthread_tsd + 32U) != fixture_qos ||
        pthread_main_read_u64(vm, pthread_tsd + 56U) != fixture_ptr_munge ||
        pthread_main_read_u64(vm, pthread_tsd + 64U) != 0U ||
        pthread_main_read_u64(vm, pthread_tsd + 72U) != 0U) {
        std::cerr << "FAIL: translated _pthread_main_thread_init clears Mach special-reply and semaphore slots\n";
        return EXIT_FAILURE;
    }

    {
        GuestAddressSpace reject_vm;
        MachContext reject_context;
        if (!reject_vm.map(
                data_base,
                GuestAddressSpace::kPageSize,
                Protection::read | Protection::write)) {
            std::cerr << "FAIL: rejected construct test maps guest data\n";
            return EXIT_FAILURE;
        }
        auto bad_options = options;
        pthread_main_put_u32(
            bad_options,
            0,
            macosarm::kMachPortOptionsReplyPort | 0x1U);
        if (!reject_vm.load_bytes(options_address, bad_options)) {
            std::cerr << "FAIL: rejected construct options load\n";
            return EXIT_FAILURE;
        }

        CpuState rejected{};
        rejected.x[0] = reject_context.task_self_port();
        rejected.x[1] = options_address;
        rejected.x[2] = 0;
        rejected.x[3] = name_address;
        rejected.x[16] = std::bit_cast<std::uint64_t>(macosarm::kMachTrapPortConstruct);
        const auto dispatch = macosarm::dispatch_mach_trap(
            rejected,
            reject_vm,
            pthread_main_svc(),
            reject_context);
        if (!dispatch || rejected.x[0] != macosarm::kMachKernInvalidArgument) {
            std::cerr << "FAIL: unsupported mach_port_construct option bits fail closed\n";
            return EXIT_FAILURE;
        }
        const auto first_after_reject = reject_context.allocate_reply_port();
        if (!first_after_reject.has_value() ||
            *first_after_reject != MachContext::kFirstReplyPort) {
            std::cerr << "FAIL: rejected construct does not consume a reply-port name\n";
            return EXIT_FAILURE;
        }
    }

    {
        GuestAddressSpace reject_vm;
        MachContext reject_context;
        if (!reject_vm.map(
                data_base,
                GuestAddressSpace::kPageSize,
                Protection::read | Protection::write) ||
            !reject_vm.load_bytes(options_address, options)) {
            std::cerr << "FAIL: bad-copyout construct test prepares guest data\n";
            return EXIT_FAILURE;
        }

        CpuState rejected{};
        rejected.x[0] = reject_context.task_self_port();
        rejected.x[1] = options_address;
        rejected.x[2] = 0;
        rejected.x[3] = 0xdead00000000ULL;
        rejected.x[16] = std::bit_cast<std::uint64_t>(macosarm::kMachTrapPortConstruct);
        const auto dispatch = macosarm::dispatch_mach_trap(
            rejected,
            reject_vm,
            pthread_main_svc(),
            reject_context);
        if (!dispatch || rejected.x[0] != macosarm::kMachKernInvalidAddress) {
            std::cerr << "FAIL: bad mach_port_construct copyout is guest-visible invalid address\n";
            return EXIT_FAILURE;
        }
        const auto first_after_reject = reject_context.allocate_reply_port();
        if (!first_after_reject.has_value() ||
            *first_after_reject != MachContext::kFirstReplyPort) {
            std::cerr << "FAIL: failed construct copyout does not consume a reply-port name\n";
            return EXIT_FAILURE;
        }
    }

    std::cout << "Dynarmic pthread main-thread cache TSD and bsdthread_register ENOSYS boundary passed\n";
    return EXIT_SUCCESS;
}
