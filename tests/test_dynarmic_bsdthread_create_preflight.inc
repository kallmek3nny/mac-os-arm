// Source: apple-oss-distributions/libpthread/kern/kern_support.c
// _bsdthread_create first checks proc_get_register(p) and returns EINVAL
// when a process never successfully registered. No guest threads are made.
namespace {

class BsdthreadCreateHost final : public macosarm::DarwinHostServices {
public:
    std::size_t write_calls{};

    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> bytes) override {
        ++write_calls;
        return {bytes.size(), 0};
    }
};

} // namespace

int dynarmic_bsdthread_create_preflight_main() {
    using macosarm::CpuState;
    using macosarm::DynarmicBackend;
    using macosarm::GuestAddressSpace;
    using macosarm::MachContext;
    using macosarm::Protection;

    constexpr std::uint64_t code_base = 0x1b0000000ULL;
    GuestAddressSpace vm;
    if (!vm.map(code_base, GuestAddressSpace::kPageSize,
                Protection::read | Protection::execute)) {
        std::cerr << "FAIL: unregistered bsdthread_create probe maps ARM64 code\n";
        return EXIT_FAILURE;
    }

    // Separate bounded translated run: reject twice (including after a
    // seemingly valid entry pointer), check carry and exact Darwin errno,
    // then exit. This does not relax the existing pthread instruction budgets.
    constexpr std::array<std::uint32_t, 16> instructions{
        0xd2802d10U, // mov x16, #360 -> bsdthread_create
        0xd4001001U, // svc #0x80
        0x54000163U, // b.cc failure, registration guard must set carry
        0x7100581fU, // cmp w0, #22 -> Darwin EINVAL
        0x54000121U, // b.ne failure
        0xd2820000U, // mov x0, #0x1000 -> apparently valid entry pointer
        0xd4001001U, // svc #0x80, still unregistered
        0x540000c3U, // b.cc failure
        0x7100581fU, // cmp w0, #22
        0x54000081U, // b.ne failure
        0xd2800000U, // mov x0, #0 -> successful probe
        0xd2800030U, // mov x16, #1 -> exit
        0xd4001001U, // svc #0x80
        0xd2800c60U, // failure: mov x0, #99
        0xd2800030U, // mov x16, #1 -> exit
        0xd4001001U, // svc #0x80
    };

    std::array<std::byte, instructions.size() * 4U> code{};
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        for (std::size_t byte = 0; byte < 4U; ++byte) {
            code[i * 4U + byte] = static_cast<std::byte>(
                (instructions[i] >> (byte * 8U)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code_base, code)) {
        std::cerr << "FAIL: unregistered bsdthread_create probe loads ARM64 code\n";
        return EXIT_FAILURE;
    }

    CpuState state{};
    state.pc = code_base;
    state.x[1] = 0x1000U;
    state.x[2] = 0x2000U;
    state.x[3] = 0x3000U;
    state.x[4] = 0x01000000U;
    BsdthreadCreateHost host;
    MachContext context;
    DynarmicBackend backend;
    const auto result = macosarm::run_process(state, vm, backend, host, context, 20U);
    if (result.reason != macosarm::ProcessStopReason::exited ||
        result.exit_status != 0 || result.instructions_executed != 13U ||
        host.write_calls != 0U || state.x[16] != macosarm::kDarwinSysExit) {
        std::cerr << "FAIL: translated bsdthread_create unregistered guard, EINVAL and carry\n";
        return EXIT_FAILURE;
    }

    std::cout << "real ARM64 unregistered bsdthread_create boundary passed\n";
    return EXIT_SUCCESS;
}
