// Real pinned Dynarmic runs two A64 CPU register/TLS contexts through
// syscall and Mach identities against a single guest address space.
// This does not expose kernel pthread registration or host threading.
namespace {
class CooperativeThreadsHost final : public macosarm::DarwinHostServices {
public:
    std::size_t writes{};
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t, std::span<const std::byte> bytes) override {
        ++writes;
        return {bytes.size(), 0};
    }
};
} // namespace

int dynarmic_cooperative_threads_main() {
    constexpr std::uint64_t code_base = 0x250000000ULL;
    constexpr std::uint64_t stack_base = 0x260000000ULL;
    constexpr std::uint64_t data_base = 0x270000000ULL;
    constexpr auto page = macosarm::GuestAddressSpace::kPageSize;
    const auto rw = macosarm::Protection::read | macosarm::Protection::write;
    macosarm::GuestAddressSpace vm;
    if (!vm.map(code_base, page, macosarm::Protection::read | macosarm::Protection::execute) ||
        !vm.map(stack_base, 2U * page, rw) ||
        !vm.map(data_base, page, rw)) {
        std::cerr << "FAIL: cooperative A64 guest VM maps\n";
        return EXIT_FAILURE;
    }
    constexpr std::array<std::uint32_t, 6> instructions{
        0xd2802e90U, // mov x16, #372 (BSD thread_selfid)
        0xd4001001U, // svc #0x80
        0xf9000260U, // str x0, [x19]
        0x92800350U, // movn x16, #26 (Mach trap -27)
        0xd4001001U, // svc #0x80
        0xb9000280U, // str w0, [x20]
    };
    std::array<std::byte, instructions.size() * 4U> code{};
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        for (std::size_t b = 0; b < 4U; ++b) {
            code[i * 4U + b] = static_cast<std::byte>(
                (instructions[i] >> (8U * b)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code_base, code)) {
        std::cerr << "FAIL: cooperative A64 code loads\n";
        return EXIT_FAILURE;
    }
    macosarm::MachContext mach;
    macosarm::GuestThreadGroup group(vm, mach, 12U);
    macosarm::CpuState a{};
    a.pc = code_base;
    a.sp = stack_base + page;
    a.tpidrro_el0 = stack_base + 0x100U;
    a.x[19] = data_base;
    a.x[20] = data_base + 16U;
    macosarm::CpuState b = a;
    b.sp += page;
    b.tpidrro_el0 += page;
    b.x[19] += 32U;
    b.x[20] += 32U;
    const auto first = group.add_main(a);
    const auto second = group.add_worker(b);
    if (!first || !second) {
        std::cerr << "FAIL: cooperative A64 thread contexts allocate\n";
        return EXIT_FAILURE;
    }

    macosarm::DynarmicBackend backend;
    CooperativeThreadsHost host;
    const auto step_a = group.run_slice(first.thread_id, backend, host, 3U);
    const auto step_b = group.run_slice(second.thread_id, backend, host, 3U);
    const auto end_a = group.run_slice(first.thread_id, backend, host, 3U);
    const auto end_b = group.run_slice(second.thread_id, backend, host, 3U);
    const auto* main_thread = group.find(first.thread_id);
    const auto* worker_thread = group.find(second.thread_id);
    std::array<std::byte, 8> a_id{};
    std::array<std::byte, 8> b_id{};
    std::array<std::byte, 4> a_port{};
    std::array<std::byte, 4> b_port{};
    const auto read_u64 = [](const std::array<std::byte, 8>& bytes) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            value |= static_cast<std::uint64_t>(
                std::to_integer<unsigned char>(bytes[i])) << (i * 8U);
        }
        return value;
    };
    const auto read_u32 = [](const std::array<std::byte, 4>& bytes) {
        std::uint32_t value = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            value |= static_cast<std::uint32_t>(
                std::to_integer<unsigned char>(bytes[i])) << (i * 8U);
        }
        return value;
    };
    if (!step_a || !step_b || !end_a || !end_b ||
        step_a.process.reason != macosarm::ProcessStopReason::instruction_budget ||
        step_b.process.reason != macosarm::ProcessStopReason::instruction_budget ||
        end_a.process.reason != macosarm::ProcessStopReason::instruction_budget ||
        end_b.process.reason != macosarm::ProcessStopReason::instruction_budget ||
        main_thread == nullptr || worker_thread == nullptr ||
        !vm.read(data_base, a_id) || !vm.read(data_base + 32U, b_id) ||
        !vm.read(data_base + 16U, a_port) || !vm.read(data_base + 48U, b_port) ||
        read_u64(a_id) != first.thread_id ||
        read_u64(b_id) != second.thread_id ||
        read_u32(a_port) != mach.thread_self_port() ||
        read_u32(b_port) != worker_thread->identity.thread_self_port ||
        group.remaining_budget() != 0U || host.writes != 0U ||
        main_thread->cpu.tpidrro_el0 == worker_thread->cpu.tpidrro_el0 ||
        main_thread->instructions_executed != 6U ||
        worker_thread->instructions_executed != 6U) {
        std::cerr << "FAIL: translated A64 context identity and TLS isolation\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 cooperative guest thread contexts passed\n";
    return EXIT_SUCCESS;
}
