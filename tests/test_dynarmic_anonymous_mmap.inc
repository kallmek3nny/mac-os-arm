// XNU BSD #197: anonymous memory through MAP_PRIVATE|MAP_ANON, returned
// guest address is readable/writable before BSD #73 deallocation.
namespace {

class AnonymousMmapHost final : public macosarm::DarwinHostServices {
public:
    std::size_t write_calls{};
    [[nodiscard]] macosarm::HostWriteResult write(
        std::int32_t, std::span<const std::byte> bytes) override {
        ++write_calls;
        return {bytes.size(), 0};
    }
};

} // namespace

int dynarmic_anonymous_mmap_main() {
    constexpr std::uint64_t code_base = 0x1d0000000ULL;
    macosarm::GuestAddressSpace vm;
    if (!vm.map(code_base, macosarm::GuestAddressSpace::kPageSize,
                macosarm::Protection::read | macosarm::Protection::execute)) {
        std::cerr << "FAIL: translated anonymous mmap code maps\n";
        return EXIT_FAILURE;
    }

    // The probe is independent of previous bootstraps and bounded to
    // 32 instructions. Real ARM64 guest stores and loads occur on the
    // address freshly returned from mmap, then munmap frees that page.
    constexpr std::array<std::uint32_t, 28> instructions{
        0xd2800000U, // mov x0, #0 (nonfixed hint)
        0xd2880001U, // mov x1, #0x4000 (16 KiB)
        0xd2800062U, // mov x2, #3 (PROT_READ|PROT_WRITE)
        0xd2820043U, // mov x3, #0x1002 (MAP_PRIVATE|MAP_ANON)
        0x92800004U, // mov x4, #-1 (anonymous fd)
        0xd2800005U, // mov x5, #0 (file position)
        0xd28018b0U, // mov x16, #197 (BSD mmap)
        0xd4001001U, // svc #0x80
        0x54000222U, // b.cs failure (mmap must succeed)
        0xaa0003f3U, // mov x19, x0 (save guest allocation)
        0x52800b4aU, // mov w10, #0x5a
        0x3900026aU, // strb w10, [x19]
        0x3940026bU, // ldrb w11, [x19]
        0x7101697fU, // cmp w11, #0x5a
        0x54000161U, // b.ne failure
        0xaa1303e0U, // mov x0, x19 (munmap address)
        0xd2880001U, // mov x1, #0x4000
        0xd2800930U, // mov x16, #73 (BSD munmap)
        0xd4001001U, // svc #0x80
        0x540000c2U, // b.cs failure
        0x7100001fU, // cmp w0, #0
        0x54000081U, // b.ne failure
        0xd2800000U, // mov x0, #0 (exit status)
        0xd2800030U, // mov x16, #1
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
        std::cerr << "FAIL: translated anonymous mmap code loads\n";
        return EXIT_FAILURE;
    }
    macosarm::CpuState state{};
    state.pc = code_base;
    AnonymousMmapHost host;
    macosarm::MachContext context;
    macosarm::DynarmicBackend backend;
    const auto result = macosarm::run_process(
        state, vm, backend, host, context, 32U);
    std::array<std::byte, 1> probe{};
    if (result.reason != macosarm::ProcessStopReason::exited ||
        result.exit_status != 0 || result.instructions_executed != 25U ||
        state.x[19] < 0x100000000ULL ||
        (state.x[19] % macosarm::GuestAddressSpace::kPageSize) != 0U ||
        vm.read(state.x[19], probe).error != macosarm::VmError::unmapped ||
        vm.resident_page_count() != 1U ||
        host.write_calls != 0U) {
        std::cerr << "FAIL: ARM64 BSD mmap/store/load/munmap contract\n";
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 private anonymous mmap and munmap passed\n";
    return EXIT_SUCCESS;
}
