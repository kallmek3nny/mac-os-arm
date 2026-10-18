// Verify real translated ARM64 loads and stores across mprotect-created
// contiguous mapping records. This is guest memory, not a host pointer alias.
namespace {
class CrossMappingHost final : public macosarm::DarwinHostServices {
public:
    std::size_t writes{};
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t, std::span<const std::byte> bytes) override {
        ++writes;
        return {bytes.size(), 0};
    }
};
} // namespace

int dynarmic_cross_mapping_memory_main() {
    constexpr std::uint64_t code_base = 0x230000000ULL;
    constexpr std::uint64_t data_base = 0x240000000ULL;
    constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
    const auto rw = macosarm::Protection::read | macosarm::Protection::write;
    macosarm::GuestAddressSpace vm;
    if (!vm.map(code_base, page,
                macosarm::Protection::read | macosarm::Protection::execute) ||
        !vm.map(data_base, 2U * page, rw) ||
        !vm.protect_range(data_base + page, page, macosarm::Protection::read) ||
        !vm.protect_range(data_base + page, page, rw) ||
        vm.mappings().size() != 3U) {
        std::cerr << "FAIL: contiguous mprotect-split ARM64 fixture maps\n";
        return EXIT_FAILURE;
    }
    constexpr std::array<std::uint32_t, 5> instructions{
        0xf9000002U, // str x2, [x0], unaligned 8-byte store across pages
        0xf9400003U, // ldr x3, [x0], unaligned 8-byte read across pages
        0xd2800000U, // mov x0, #0
        0xd2800030U, // mov x16, #1 (exit)
        0xd4001001U, // svc #0x80
    };
    std::array<std::byte, instructions.size() * 4U> code{};
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        for (std::size_t b = 0; b < 4U; ++b) {
            code[i * 4U + b] = static_cast<std::byte>(
                (instructions[i] >> (b * 8U)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code_base, code)) {
        std::cerr << "FAIL: contiguous ARM64 fixture loads\n";
        return EXIT_FAILURE;
    }
    macosarm::CpuState state{};
    state.pc = code_base;
    state.x[0] = data_base + page - 4U;
    state.x[2] = 0x1122334455667788ULL;
    CrossMappingHost host;
    macosarm::MachContext context;
    macosarm::DynarmicBackend backend;
    const auto result = macosarm::run_process(state, vm, backend, host, context, 8U);
    std::array<std::byte, 8> copied{};
    const bool memory_ok = static_cast<bool>(vm.read(
        data_base + page - 4U, copied));
    constexpr std::array<std::byte, 8> expected{
        std::byte{0x88}, std::byte{0x77}, std::byte{0x66}, std::byte{0x55},
        std::byte{0x44}, std::byte{0x33}, std::byte{0x22}, std::byte{0x11}};
    if (result.reason != macosarm::ProcessStopReason::exited ||
        result.exit_status != 0 || result.instructions_executed != 5U ||
        state.x[3] != 0x1122334455667788ULL ||
        !memory_ok || copied != expected || host.writes != 0U) {
        std::cerr << "FAIL: translated ARM64 cross-fragment load/store contract\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 cross-fragment guest memory passed\n";
    return EXIT_SUCCESS;
}
