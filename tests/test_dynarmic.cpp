#include "macosarm/dynarmic_backend.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

void put_instruction(
    std::array<std::byte, macosarm::GuestAddressSpace::kPageSize>& page,
    std::size_t offset,
    std::uint32_t instruction) {
    for (std::size_t i = 0; i < 4; ++i) {
        page.at(offset + i) = static_cast<std::byte>((instruction >> (i * 8)) & 0xffU);
    }
}

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;
    using macosarm::StopReason;

    constexpr std::uint64_t code_base = 0x100000000ULL;

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(code_base, GuestAddressSpace::kPageSize,
                                        Protection::read | Protection::execute)),
               "JIT code page maps");

        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, 0xd2800020U); // mov x0, #1
        put_instruction(page, 4, 0x91000800U); // add x0, x0, #2
        put_instruction(page, 8, 0xd4001001U); // svc #0x80
        expect(static_cast<bool>(vm.load_bytes(code_base, page)), "JIT test program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = 0x700000000ULL;

        macosarm::DynarmicBackend backend;
        const auto result = backend.run(state, vm, 16);
        expect(result.reason == StopReason::supervisor_call, "Dynarmic stops on SVC callback");
        expect(result.supervisor_call == 0x80U, "SVC immediate preserved");
        expect(result.instructions_executed == 3, "three ARM64 instructions executed");
        expect(state.x[0] == 3, "ARM64 MOV+ADD really updates x0 through JIT");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(code_base, GuestAddressSpace::kPageSize,
                                        Protection::read | Protection::execute)),
               "budget code page maps");

        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, 0xd503201fU); // nop
        put_instruction(page, 4, 0xd503201fU); // nop
        put_instruction(page, 8, 0xd503201fU); // nop
        expect(static_cast<bool>(vm.load_bytes(code_base, page)), "budget program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = 0x700000000ULL;

        macosarm::DynarmicBackend backend;
        const auto result = backend.run(state, vm, 2);
        expect(result.reason == StopReason::instruction_budget, "budget is a hard execution stop");
        expect(result.instructions_executed == 2, "exactly two instructions run under budget two");
        expect(state.pc == code_base + 8, "PC advances by exactly two A64 instructions");

        const auto zero = backend.run(state, vm, 0);
        expect(zero.instructions_executed == 0, "zero budget never enters JIT");
        expect(state.pc == code_base + 8, "zero budget leaves PC unchanged");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Dynarmic ARM64 JIT tests passed\n";
    return EXIT_SUCCESS;
}
