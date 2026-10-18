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
    const std::array<std::uint32_t, 67> instructions{
        0xd53bd069U, // mrs x9, TPIDRRO_EL0
        0xb40007e9U, // cbz x9, failure
        0xd103812aU, // sub x10, x9, #224 -> pthread_self
        0xf900012aU, // str x10, [x9] -> PTHREAD_SELF slot 0
        0x9102b14bU, // add x11, x10, #172 -> &pthread->err_no
        0xf900052bU, // str x11, [x9, #8] -> ERRNO slot 1
        0xf9001134U, // str x20, [x9, #32] -> PTHREAD_QOS_CLASS slot 4
        0xf9001d35U, // str x21, [x9, #56] -> PTR_MUNGE slot 7
        0xf940012cU, // ldr x12, [x9]
        0xeb0a019fU, // cmp x12, x10
        0x540006c1U, // b.ne failure
        0xf940052cU, // ldr x12, [x9, #8]
        0xeb0b019fU, // cmp x12, x11
        0x54000661U, // b.ne failure
        0xf940112cU, // ldr x12, [x9, #32]
        0xeb14019fU, // cmp x12, x20
        0x54000601U, // b.ne failure
        0xf9401d2cU, // ldr x12, [x9, #56]
        0xeb15019fU, // cmp x12, x21
        0x540005a1U, // b.ne failure
        0x92800350U, // mov x16, #-27 -> thread_self_trap
        0xd4001001U, // svc #0x80
        0xb4000540U, // cbz x0, failure
        0xf9000d20U, // str x0, [x9, #24] -> MACH_THREAD_SELF slot 3
        0xf9400d32U, // ldr x18, [x9, #24]
        0xeb00025fU, // cmp x18, x0
        0x540004c1U, // b.ne failure
        0x92800370U, // mov x16, #-28 -> task_self_trap
        0xd4001001U, // svc #0x80
        0xaa0003f3U, // mov x19, x0
        0xaa1303e0U, // mov x0, x19 -> target task
        0xaa1603e1U, // mov x1, x22 -> mach_port_options_t*
        0xd2800002U, // mov x2, #0 -> context
        0xaa1703e3U, // mov x3, x23 -> mach_port_name_t*
        0x928002f0U, // mov x16, #-24 -> mach_port_construct fast trap
        0xd4001001U, // svc #0x80
        0xb5000380U, // cbnz x0, failure
        0xb94002f8U, // ldr w24, [x23] -> constructed reply port
        0x34000358U, // cbz w24, failure
        0xf9000938U, // str x24, [x9, #16] -> MIG_REPLY slot 2
        0xf9400939U, // ldr x25, [x9, #16]
        0xeb18033fU, // cmp x25, x24
        0x540002c1U, // b.ne failure
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
        0x54000163U, // b.cc failure -> unsupported syscall must set carry
        0x7101381fU, // cmp w0, #78 -> Darwin ENOSYS
        0x54000121U, // b.ne failure
        // Prove that the immediately following malformed registration also
        // receives the XNU size-preflight EINVAL without claiming support.
        0xd28000e4U, // mov x4, #7 -> version field cannot fit
        0xd4001001U, // svc #0x80, x16 still BSD #366
        0x540000c3U, // b.cc failure -> EINVAL must set carry
        0x7100581fU, // cmp w0, #22 -> Darwin EINVAL
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
    // On LP64 ARM64, tl_policy is byte 48 and tl_joinable occupies bit 0
    // of byte 49 (libpthread/src/types_internal.h, pthread_s). Apple sends
    // CHAR_BIT * (offsetof(tl_policy) + 1) to __bsdthread_register.
    pthread_main_put_u32(registration_data, 48U, 392U); // joinable_offset_bits
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
    if (process.instructions_executed != 64U) {
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

    {
        // libpthread/src/pthread.c (_pthread_set_self_dyld and
        // _pthread_set_self_internal) stores BSD thread_selfid into the
        // arm64 pthread_s::thread_id cell, 8 bytes before the TSD base.
        // Reuse the same guest VM and MachContext as the full bootstrap above.
        // This is a separate bounded translated entry, not a larger budget
        // for the existing 64-instruction main-thread probe.
        constexpr std::uint64_t id_code = code_base + 0x1000ULL;
        std::array<std::byte, 8> stale_id{};
        stale_id.fill(std::byte{0xff});
        if (!vm.load_bytes(pthread_tsd - 8U, stale_id)) {
            std::cerr << "FAIL: translated pthread thread_id sentinel load\n";
            return EXIT_FAILURE;
        }

        constexpr std::array<std::uint32_t, 16> thread_id_instructions{
            0xd53bd069U, // mrs x9, TPIDRRO_EL0 -> pthread TSD
            0xd2802e90U, // mov x16, #372 -> BSD thread_selfid
            0xd4001001U, // svc #0x80
            0xd100212aU, // sub x10, x9, #8 -> pthread_s::thread_id
            0xf9000140U, // str x0, [x10] -> persist complete 64-bit ID
            0xf940014bU, // ldr x11, [x10] -> compare with second syscall
            0xd2802e90U, // mov x16, #372 -> BSD thread_selfid
            0xd4001001U, // svc #0x80
            0xeb0b001fU, // cmp x0, x11
            0x54000081U, // b.ne failure
            0xd2800000U, // mov x0, #0
            0xd2800030U, // mov x16, #1 -> BSD exit
            0xd4001001U, // svc #0x80
            0xd2800c60U, // failure: mov x0, #99
            0xd2800030U, // mov x16, #1 -> BSD exit
            0xd4001001U, // svc #0x80
        };
        std::array<std::byte, thread_id_instructions.size() * 4U> thread_id_code{};
        for (std::size_t index = 0; index < thread_id_instructions.size(); ++index) {
            for (std::size_t byte = 0; byte < 4U; ++byte) {
                thread_id_code[index * 4U + byte] = static_cast<std::byte>(
                    (thread_id_instructions[index] >> (byte * 8U)) & 0xffU);
            }
        }
        if (!vm.load_bytes(id_code, thread_id_code)) {
            std::cerr << "FAIL: translated pthread thread_selfid code load\n";
            return EXIT_FAILURE;
        }

        CpuState id_state{};
        id_state.pc = id_code;
        id_state.sp = state.sp;
        id_state.tpidrro_el0 = pthread_tsd;
        macosarm::DynarmicBackend id_backend;
        const auto id_result =
            macosarm::run_process(id_state, vm, id_backend, host, context, 32U);
        if (id_result.reason != macosarm::ProcessStopReason::exited ||
            id_result.exit_status != 0 || id_result.instructions_executed != 13U ||
            id_state.x[11] != context.thread_id() ||
            pthread_main_read_u64(vm, pthread_tsd - 8U) != context.thread_id() ||
            context.thread_id() == context.thread_self_port() ||
            context.thread_id() <= 0xffffffffULL) {
            std::cerr << "FAIL: translated BSD thread_selfid persists the stable 64-bit pthread ID\n";
            return EXIT_FAILURE;
        }
    }

    {
        // libpthread's _pthread_struct_init and _pthread_main_thread_init
        // perform these guest-side writes before bsdthread registration:
        // cleanup_stack = NULL at +8, tl_join_ctx = NULL at +32,
        // tl_exit_gate = MACH_PORT_NULL at +52, and tl_joinable bit 0
        // at +49. The other joinable byte bits must not be overwritten.
        // Keep this additional translated program separately budgeted.
        constexpr std::uint64_t bookkeeping_code = code_base + 0x2000ULL;
        std::array<std::byte, 8> stale_pointer{};
        stale_pointer.fill(std::byte{0xff});
        std::array<std::byte, 4> stale_gate{};
        stale_gate.fill(std::byte{0xff});
        constexpr std::array<std::byte, 1> joinable_seed{std::byte{0xa6}};
        if (!vm.load_bytes(pthread_base + 8U, stale_pointer) ||
            !vm.load_bytes(pthread_base + 32U, stale_pointer) ||
            !vm.load_bytes(pthread_base + 52U, stale_gate) ||
            !vm.load_bytes(pthread_base + 49U, joinable_seed)) {
            std::cerr << "FAIL: translated pthread bookkeeping sentinels load\n";
            return EXIT_FAILURE;
        }

        constexpr std::array<std::uint32_t, 26> bookkeeping_instructions{
            0xd53bd069U, // mrs x9, TPIDRRO_EL0
            0xd103812aU, // sub x10, x9, #224 -> pthread_self
            0xf900055fU, // str xzr, [x10, #8] -> cleanup_stack
            0xf900115fU, // str xzr, [x10, #32] -> tl_join_ctx
            0xb900355fU, // str wzr, [x10, #52] -> tl_exit_gate
            0x3940c54bU, // ldrb w11, [x10, #49] -> joinable flags
            0x3200016bU, // orr w11, w11, #1 -> set joinable only
            0x3900c54bU, // strb w11, [x10, #49]
            0x3940c54cU, // ldrb w12, [x10, #49]
            0x7200019fU, // tst w12, #1
            0x540001a0U, // b.eq failure
            0xf940054dU, // ldr x13, [x10, #8]
            0xb500016dU, // cbnz x13, failure
            0xf940114eU, // ldr x14, [x10, #32]
            0xb500012eU, // cbnz x14, failure
            0xb940354fU, // ldr w15, [x10, #52]
            0x350000efU, // cbnz w15, failure
            0xb9403271U, // ldr w17, [x19, #48] -> registration.joinable_offset_bits
            0x7106223fU, // cmp w17, #392 -> bit immediately after tl_policy
            0x54000081U, // b.ne failure
            0xd2800000U, // mov x0, #0
            0xd2800030U, // mov x16, #1 -> BSD exit
            0xd4001001U, // svc #0x80
            0xd2800c60U, // failure: mov x0, #99
            0xd2800030U, // mov x16, #1 -> BSD exit
            0xd4001001U, // svc #0x80
        };
        std::array<std::byte, bookkeeping_instructions.size() * 4U> bookkeeping_bytes{};
        for (std::size_t index = 0; index < bookkeeping_instructions.size(); ++index) {
            for (std::size_t byte = 0; byte < 4U; ++byte) {
                bookkeeping_bytes[index * 4U + byte] = static_cast<std::byte>(
                    (bookkeeping_instructions[index] >> (byte * 8U)) & 0xffU);
            }
        }
        if (!vm.load_bytes(bookkeeping_code, bookkeeping_bytes)) {
            std::cerr << "FAIL: translated pthread bookkeeping code loads\n";
            return EXIT_FAILURE;
        }

        CpuState bookkeeping_state{};
        bookkeeping_state.pc = bookkeeping_code;
        bookkeeping_state.sp = state.sp;
        bookkeeping_state.tpidrro_el0 = pthread_tsd;
        bookkeeping_state.x[19] = registration_address;
        DynarmicBackend bookkeeping_backend;
        const auto bookkeeping_result = macosarm::run_process(
            bookkeeping_state, vm, bookkeeping_backend, host, context, 32U);
        std::array<std::byte, 1> joinable_after{};
        if (bookkeeping_result.reason != macosarm::ProcessStopReason::exited ||
            bookkeeping_result.exit_status != 0 ||
            bookkeeping_result.instructions_executed != 23U ||
            pthread_main_read_u64(vm, pthread_base + 8U) != 0U ||
            pthread_main_read_u64(vm, pthread_base + 32U) != 0U ||
            pthread_main_read_u32(vm, pthread_base + 52U) != 0U ||
            !vm.read(pthread_base + 49U, joinable_after) ||
            joinable_after[0] != std::byte{0xa7} ||
            pthread_main_read_u32(vm, registration_address + 48U) != 392U ||
            pthread_main_read_u64(vm, pthread_tsd - 8U) != context.thread_id()) {
            std::cerr << "FAIL: translated pthread main-thread bookkeeping and joinable metadata\n";
            return EXIT_FAILURE;
        }
    }

    {
        // A separate bounded real Dynarmic entry checks BSD getpid -> thread_selfid
        // -> getpid through the exact shared MachContext. The same ARM64 program
        // also verifies that an independent context has a distinct POSIX pid.
        // Neither the original 64-instruction bootstrap nor its budgets change.
        constexpr std::uint64_t process_id_code = code_base + 0x3000ULL;
        constexpr std::array<std::uint32_t, 12> process_id_instructions{
            0xd2800290U, // mov x16, #20 -> BSD getpid
            0xd4001001U, // svc #0x80
            0xaa0003f3U, // mov x19, x0 -> first pid
            0xd2802e90U, // mov x16, #372 -> BSD thread_selfid
            0xd4001001U, // svc #0x80
            0xaa0003f4U, // mov x20, x0 -> thread id
            0xd2800290U, // mov x16, #20 -> BSD getpid again
            0xd4001001U, // svc #0x80
            0xaa0003f5U, // mov x21, x0 -> repeated pid
            0xd2800000U, // mov x0, #0
            0xd2800030U, // mov x16, #1 -> BSD exit
            0xd4001001U, // svc #0x80
        };
        std::array<std::byte, process_id_instructions.size() * 4U> process_id_bytes{};
        for (std::size_t index = 0; index < process_id_instructions.size(); ++index) {
            for (std::size_t byte = 0; byte < 4U; ++byte) {
                process_id_bytes[index * 4U + byte] = static_cast<std::byte>(
                    (process_id_instructions[index] >> (byte * 8U)) & 0xffU);
            }
        }
        if (!vm.load_bytes(process_id_code, process_id_bytes)) {
            std::cerr << "FAIL: translated getpid probe code loads\n";
            return EXIT_FAILURE;
        }

        CpuState process_id_state{};
        process_id_state.pc = process_id_code;
        process_id_state.sp = state.sp;
        DynarmicBackend process_id_backend;
        const auto process_id_result = macosarm::run_process(
            process_id_state, vm, process_id_backend, host, context, 16U);
        if (process_id_result.reason != macosarm::ProcessStopReason::exited ||
            process_id_result.exit_status != 0 ||
            process_id_result.instructions_executed != 12U ||
            process_id_state.x[19] != context.process_id() ||
            process_id_state.x[20] != context.thread_id() ||
            process_id_state.x[21] != context.process_id() ||
            (process_id_state.pstate & macosarm::kA64PstateCarry) != 0U) {
            std::cerr << "FAIL: translated getpid identity across BSD syscalls\n";
            return EXIT_FAILURE;
        }

        MachContext other_context;
        CpuState other_state{};
        other_state.pc = process_id_code;
        other_state.sp = state.sp;
        DynarmicBackend other_backend;
        const auto other_result = macosarm::run_process(
            other_state, vm, other_backend, host, other_context, 16U);
        if (other_result.reason != macosarm::ProcessStopReason::exited ||
            other_result.exit_status != 0 ||
            other_result.instructions_executed != 12U ||
            other_context.process_id() == context.process_id() ||
            other_state.x[19] != other_context.process_id() ||
            other_state.x[21] != other_context.process_id() ||
            other_state.x[20] != other_context.thread_id()) {
            std::cerr << "FAIL: translated getpid isolated between process contexts\n";
            return EXIT_FAILURE;
        }
    }

    std::cout << "Dynarmic pthread main-thread structure and registration layout passed\n";
    return EXIT_SUCCESS;
}
