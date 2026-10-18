// Source-backed, bounded Dynarmic execution: mmap then mprotect to
// read-only, restore read-write, store/load, and munmap. No test budgets
// from any previously merged phase are modified.
namespace {
class MprotectProbeHost final : public macosarm::DarwinHostServices {
public:
    std::size_t writes{};
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t, std::span<const std::byte> bytes) override {
        ++writes;
        return {bytes.size(), 0};
    }
};
} // namespace

int dynarmic_mprotect_main() {
    constexpr std::uint64_t code_base = 0x1e0000000ULL;
    macosarm::GuestAddressSpace vm;
    if (!vm.map(code_base, macosarm::GuestAddressSpace::kPageSize,
                macosarm::Protection::read | macosarm::Protection::execute)) {
        std::cerr << "FAIL: mprotect translated code maps\n";
        return EXIT_FAILURE;
    }
    constexpr std::array<std::uint32_t, 38> instructions{
        0xd2800000U, // mov x0, #0
        0xd2880001U, // mov x1, #0x4000
        0xd2800062U, // mov x2, #3
        0xd2820043U, // mov x3, #0x1002
        0x92800004U, // mov x4, #-1
        0xd2800005U, // mov x5, #0
        0xd28018b0U, // mov x16, #197 mmap
        0xd4001001U, // svc #0x80
        0x54000362U, // b.cs failure
        0xaa0003f3U, // mov x19, x0 (guest mapped pointer)
        0xaa1303e0U, // mov x0, x19
        0xd2880001U, // mov x1, #0x4000
        0xd2800022U, // mov x2, #1 read-only
        0xd2800950U, // mov x16, #74 mprotect
        0xd4001001U, // svc #0x80
        0x54000282U, // b.cs failure
        0xaa1303e0U, // mov x0, x19
        0xd2880001U, // mov x1, #0x4000
        0xd2800062U, // mov x2, #3 read-write
        0xd2800950U, // mov x16, #74 mprotect
        0xd4001001U, // svc #0x80
        0x540001c2U, // b.cs failure
        0x52800b4aU, // mov w10, #0x5a
        0x3900026aU, // strb w10, [x19]
        0x3940026bU, // ldrb w11, [x19]
        0x7101697fU, // cmp w11, #0x5a
        0x54000121U, // b.ne failure
        0xaa1303e0U, // mov x0, x19
        0xd2880001U, // mov x1, #0x4000
        0xd2800930U, // mov x16, #73 munmap
        0xd4001001U, // svc #0x80
        0x54000082U, // b.cs failure
        0xd2800000U, // mov x0, #0
        0xd2800030U, // mov x16, #1 exit
        0xd4001001U, // svc #0x80
        0xd2800c60U, // failure: mov x0, #99
        0xd2800030U, // mov x16, #1
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
        std::cerr << "FAIL: mprotect translated code loads\n";
        return EXIT_FAILURE;
    }
    macosarm::CpuState state{};
    state.pc = code_base;
    MprotectProbeHost host;
    macosarm::MachContext context;
    macosarm::DynarmicBackend backend;
    const auto result = macosarm::run_process(
        state, vm, backend, host, context, 40U);
    std::array<std::byte, 1> readback{};
    if (result.reason != macosarm::ProcessStopReason::exited ||
        result.exit_status != 0 || result.instructions_executed != 35U ||
        state.x[19] < 0x100000000ULL ||
        vm.read(state.x[19], readback).error != macosarm::VmError::unmapped ||
        vm.resident_page_count() != 1U || host.writes != 0U) {
        std::cerr << "FAIL: real ARM64 mmap/mprotect/store/load/munmap contract\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 bounded mprotect rights transition passed\n";
    return EXIT_SUCCESS;
}
