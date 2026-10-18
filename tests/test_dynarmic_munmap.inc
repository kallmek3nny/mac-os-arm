// XNU bsd/kern/kern_mman.c: BSD munmap (#73) page rounding and EINVAL.
namespace {

class MunmapProbeHost final : public macosarm::DarwinHostServices {
public:
    std::size_t writes{};
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t, std::span<const std::byte> data) override {
        ++writes;
        return {data.size(), 0};
    }
};

} // namespace

int dynarmic_munmap_main() {
    constexpr std::uint64_t code_base = 0x1c0000000ULL;
    constexpr std::uint64_t data_base = 0x300000000ULL;
    constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
    macosarm::GuestAddressSpace vm;
    if (!vm.map(code_base, page, macosarm::Protection::read | macosarm::Protection::execute) ||
        !vm.map(data_base, 4U * page, macosarm::Protection::read | macosarm::Protection::write)) {
        std::cerr << "FAIL: real ARM64 munmap probe maps guest memory\n";
        return EXIT_FAILURE;
    }

    const std::array<std::byte, 1> sentinel{std::byte{0x7e}};
    for (std::uint64_t n = 0; n < 4U; ++n) {
        if (!vm.write(data_base + n * page, sentinel)) {
            std::cerr << "FAIL: real ARM64 munmap probe initializes guest pages\n";
            return EXIT_FAILURE;
        }
    }

    // Two guest BSD #73 calls: a valid subpage-sized interior removal
    // clears carry, followed by a zero-length EINVAL that sets carry.
    // This probe has its own 24-instruction budget and cannot alter the
    // original bootstrap, pthread or JIT instruction limits.
    constexpr std::array<std::uint32_t, 21> instructions{
        0xd2880000U, // mov x0, #0x4000
        0xf2c00060U, // movk x0, #3, lsl #32 -> 0x300004000
        0xd2800021U, // mov x1, #1 -> round to 16 KiB page
        0xd2800930U, // mov x16, #73
        0xd4001001U, // svc #0x80
        0x540001a2U, // b.cs failure
        0x7100001fU, // cmp w0, #0
        0x54000161U, // b.ne failure
        0xd2880000U, // mov x0, #0x4000
        0xf2c00060U, // movk x0, #3, lsl #32
        0xd2800001U, // mov x1, #0 -> invalid length
        0xd4001001U, // svc #0x80
        0x540000c3U, // b.cc failure
        0x7100581fU, // cmp w0, #22 -> EINVAL
        0x54000081U, // b.ne failure
        0xd2800000U, // mov x0, #0 -> probe succeeded
        0xd2800030U, // mov x16, #1 -> exit
        0xd4001001U, // svc #0x80
        0xd2800c60U, // failure: mov x0, #99
        0xd2800030U, // mov x16, #1 -> exit
        0xd4001001U, // svc #0x80
    };
    std::array<std::byte, instructions.size() * 4U> code{};
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        for (std::size_t byte = 0; byte < 4U; ++byte) {
            code[i * 4U + byte] =
                static_cast<std::byte>((instructions[i] >> (byte * 8U)) & 0xffU);
        }
    }
    if (!vm.load_bytes(code_base, code)) {
        std::cerr << "FAIL: real ARM64 munmap probe code load\n";
        return EXIT_FAILURE;
    }

    macosarm::CpuState state{};
    state.pc = code_base;
    MunmapProbeHost host;
    macosarm::MachContext context;
    macosarm::DynarmicBackend backend;
    const auto result = macosarm::run_process(state, vm, backend, host, context, 24U);
    std::array<std::byte, 1> surviving{};
    if (result.reason != macosarm::ProcessStopReason::exited ||
        result.exit_status != 0 || result.instructions_executed != 18U ||
        vm.read(data_base + page, surviving).error != macosarm::VmError::unmapped ||
        !vm.read(data_base, surviving) || surviving != sentinel ||
        !vm.read(data_base + 2U * page, surviving) || surviving != sentinel ||
        !vm.read(data_base + 3U * page, surviving) || surviving != sentinel ||
        vm.resident_page_count() != 4U || host.writes != 0U) {
        std::cerr << "FAIL: real ARM64 munmap page removal, carry and EINVAL\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 Darwin munmap partial removal and EINVAL passed\n";
    return EXIT_SUCCESS;
}
