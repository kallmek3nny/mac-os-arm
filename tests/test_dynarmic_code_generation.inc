// Bounded Dynarmic coverage for the GuestAddressSpace code-generation epoch.
// Translated blocks must be discarded once guest code bytes, execute rights,
// or executable mappings change, whether the host loader patches code between
// runs or the guest stores into writable executable memory mid-run.
namespace dynarmic_code_generation_detail {

constexpr std::uint64_t kCodeBase = 0x1f0000000ULL;
constexpr std::uint32_t kSvc0 = 0xd4000001U; // svc #0

[[nodiscard]] constexpr std::uint32_t movz_x0(std::uint32_t imm16) noexcept {
    return 0xd2800000U | ((imm16 & 0xffffU) << 5U);
}

template <std::size_t N>
[[nodiscard]] bool load_words(macosarm::GuestAddressSpace& vm, std::uint64_t address,
                              const std::array<std::uint32_t, N>& words) {
    std::array<std::byte, N * 4U> bytes{};
    for (std::size_t i = 0; i < N; ++i) {
        for (std::size_t byte = 0; byte < 4U; ++byte) {
            bytes[i * 4U + byte] =
                static_cast<std::byte>((words[i] >> (byte * 8U)) & 0xffU);
        }
    }
    return static_cast<bool>(vm.load_bytes(address, bytes));
}

// Runs from pc to the first SVC and checks the x0 that the block produced.
[[nodiscard]] bool run_to_svc(macosarm::DynarmicBackend& backend,
                              macosarm::CpuState& state,
                              macosarm::GuestAddressSpace& vm,
                              std::uint64_t pc,
                              std::uint64_t expected_x0) {
    state.pc = pc;
    state.x[0] = 0;
    const macosarm::ExecutionResult result = backend.run(state, vm, 16U);
    return result.reason == macosarm::StopReason::supervisor_call &&
           result.supervisor_call == 0U && state.x[0] == expected_x0;
}

} // namespace dynarmic_code_generation_detail

int dynarmic_code_generation_main() {
    using namespace dynarmic_code_generation_detail;
    constexpr std::uint64_t page = macosarm::GuestAddressSpace::kPageSize;
    const auto rx = macosarm::Protection::read | macosarm::Protection::execute;
    int code_generation_failures = 0;
    const auto expect_code_generation =
        [&code_generation_failures](bool condition, const char* message) {
            if (!condition) {
                std::cerr << "FAIL: " << message << '\n';
                ++code_generation_failures;
            }
        };

    {
        // The host loader patches already-translated code between runs.
        macosarm::GuestAddressSpace vm;
        macosarm::DynarmicBackend backend;
        macosarm::CpuState state{};
        expect_code_generation(
            static_cast<bool>(vm.map(kCodeBase, page, rx)) &&
                load_words(vm, kCodeBase, std::array<std::uint32_t, 2>{movz_x0(1U), kSvc0}),
            "host patch fixture maps and loads translated code");
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase, 1U),
                               "original block translates and executes");
        const std::uint64_t before = vm.code_generation();
        expect_code_generation(
            load_words(vm, kCodeBase, std::array<std::uint32_t, 1>{movz_x0(2U)}) &&
                vm.code_generation() != before,
            "loader patch of executable bytes advances the code generation");
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase, 2U),
                               "patched bytes run instead of the stale translation");
    }

    {
        // The guest stores a new instruction into writable executable memory
        // after that instruction was already translated, then runs into it.
        constexpr std::uint32_t kStrW2AtX1 = 0xb9000022U; // str w2, [x1]
        const auto rwx = rx | macosarm::Protection::write;
        macosarm::GuestAddressSpace vm;
        macosarm::DynarmicBackend backend;
        macosarm::CpuState state{};
        expect_code_generation(
            static_cast<bool>(vm.map(kCodeBase, page, rwx)) &&
                load_words(vm, kCodeBase,
                           std::array<std::uint32_t, 3>{kStrW2AtX1, movz_x0(1U), kSvc0}),
            "self-modifying fixture maps writable executable code");
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase + 4U, 1U),
                               "store target translates before the guest patches it");
        state.x[1] = kCodeBase + 4U;
        state.x[2] = movz_x0(3U);
        const std::uint64_t before = vm.code_generation();
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase, 3U),
                               "guest store retires the stale translation mid-run");
        expect_code_generation(vm.code_generation() != before,
                               "guest store into executable memory advances the code generation");
    }

    {
        // Revoking execute rights must retire translations, and restoring them
        // must retire the cached fetch-fault translation so the page runs again.
        const auto rw = macosarm::Protection::read | macosarm::Protection::write;
        const auto rwx = rx | macosarm::Protection::write;
        macosarm::GuestAddressSpace vm;
        macosarm::DynarmicBackend backend;
        macosarm::CpuState state{};
        expect_code_generation(
            static_cast<bool>(vm.map(kCodeBase, page, rx, rwx)) &&
                load_words(vm, kCodeBase, std::array<std::uint32_t, 2>{movz_x0(5U), kSvc0}),
            "protection fixture maps and loads translated code");
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase, 5U),
                               "executable block translates before execute is revoked");
        expect_code_generation(static_cast<bool>(vm.protect_range(kCodeBase, page, rw)),
                               "execute rights can be revoked");
        state.pc = kCodeBase;
        const macosarm::ExecutionResult revoked = backend.run(state, vm, 16U);
        expect_code_generation(revoked.reason == macosarm::StopReason::memory_fault,
                               "revoked execute rights fault instead of running stale code");
        expect_code_generation(static_cast<bool>(vm.protect_range(kCodeBase, page, rx)),
                               "execute rights can be restored");
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase, 5U),
                               "restored execute rights drop the cached fetch fault");
    }

    {
        // Replacing an executable mapping at the same address must not reuse
        // translations made for the previous mapping's bytes.
        macosarm::GuestAddressSpace vm;
        macosarm::DynarmicBackend backend;
        macosarm::CpuState state{};
        expect_code_generation(
            static_cast<bool>(vm.map(kCodeBase, page, rx)) &&
                load_words(vm, kCodeBase, std::array<std::uint32_t, 2>{movz_x0(6U), kSvc0}),
            "remap fixture maps and loads the original code");
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase, 6U),
                               "original mapping translates and executes");
        expect_code_generation(
            static_cast<bool>(vm.unmap(kCodeBase, page)) &&
                static_cast<bool>(vm.map(kCodeBase, page, rx)) &&
                load_words(vm, kCodeBase, std::array<std::uint32_t, 2>{movz_x0(7U), kSvc0}),
            "executable mapping is replaced at the same address");
        expect_code_generation(run_to_svc(backend, state, vm, kCodeBase, 7U),
                               "replacement mapping runs instead of the stale translation");
    }

    if (code_generation_failures != 0) {
        return EXIT_FAILURE;
    }
    std::cout << "real ARM64 code-generation invalidation passed\n";
    return EXIT_SUCCESS;
}
