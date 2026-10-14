#include "macosarm/execution.hpp"

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

class ProbeBackend final : public macosarm::ExecutionBackend {
public:
    macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace& address_space,
        std::uint64_t instruction_budget) override {

        if (instruction_budget == 0) {
            return {macosarm::StopReason::instruction_budget, 0, 0, macosarm::VmError::none};
        }

        std::uint32_t instruction = 0;
        const auto fetched = macosarm::fetch_instruction(address_space, state.pc, instruction);
        if (!fetched) {
            return {macosarm::StopReason::memory_fault, 0, 0, fetched.error};
        }
        observed_instruction = instruction;
        state.pc += 4;
        return {macosarm::StopReason::instruction_budget, 1, 0, macosarm::VmError::none};
    }

    std::uint32_t observed_instruction{};
};

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;
    using macosarm::VmError;

    {
        macosarm::CpuState state;
        state.x[0] = 99;
        state.vectors[3] = {7, 8};
        state.pstate = 0xffffffffU;

        const macosarm::LoadedImage image{0x100000000ULL, 0x100000200ULL, 2};
        const auto initialized = macosarm::initialize_cpu(state, image, 0x700000000ULL);
        expect(static_cast<bool>(initialized), "aligned CPU startup succeeds");
        expect(state.pc == image.entry_address, "CPU starts at loaded entry address");
        expect(state.sp == 0x700000000ULL, "CPU stack pointer initialized");
        expect(state.x[0] == 0, "CPU GPRs reset before entry");
        expect(state.vectors[3] == macosarm::Vector128{}, "CPU vectors reset before entry");
        expect(state.pstate == 0 && state.fpcr == 0 && state.fpsr == 0,
               "CPU flags reset before entry");
    }

    {
        macosarm::CpuState state;
        const macosarm::LoadedImage bad_entry{0, 0x1003, 1};
        expect(macosarm::initialize_cpu(state, bad_entry, 0x8000).error ==
                   macosarm::CpuInitError::unaligned_entry,
               "unaligned ARM64 entry rejected");

        const macosarm::LoadedImage image{0, 0x1000, 1};
        expect(macosarm::initialize_cpu(state, image, 0x8008).error ==
                   macosarm::CpuInitError::unaligned_stack,
               "non-16-byte stack rejected");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(0x100000000ULL, GuestAddressSpace::kPageSize,
                                        Protection::execute)),
               "execute-only mapping succeeds");
        const std::array<std::byte, 4> mov_x0_1{
            std::byte{0x20}, std::byte{0x00}, std::byte{0x80}, std::byte{0xd2}
        };
        expect(static_cast<bool>(vm.load_bytes(0x100000100ULL, mov_x0_1)),
               "loader populates execute-only page");

        std::uint32_t instruction = 0;
        expect(static_cast<bool>(macosarm::fetch_instruction(vm, 0x100000100ULL, instruction)),
               "instruction fetch accepts execute-only memory");
        expect(instruction == 0xd2800020U, "instruction fetch is little-endian");

        std::array<std::byte, 4> ordinary_read{};
        expect(vm.read(0x100000100ULL, ordinary_read).error == VmError::protection,
               "execute-only memory is not ordinary-readable");
        expect(macosarm::fetch_instruction(vm, 0x100000102ULL, instruction).error == VmError::unaligned,
               "unaligned instruction PC rejected");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(0x200000000ULL, GuestAddressSpace::kPageSize,
                                        Protection::read)),
               "read-only mapping succeeds");
        std::uint32_t instruction = 0;
        expect(macosarm::fetch_instruction(vm, 0x200000000ULL, instruction).error == VmError::protection,
               "instruction fetch requires execute permission");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(0x300000000ULL, GuestAddressSpace::kPageSize,
                                        Protection::execute)),
               "probe executable mapping succeeds");
        const std::array<std::byte, 4> code{
            std::byte{0x20}, std::byte{0x00}, std::byte{0x80}, std::byte{0xd2}
        };
        expect(static_cast<bool>(vm.load_bytes(0x300000000ULL, code)), "probe code loaded");

        macosarm::CpuState state;
        state.pc = 0x300000000ULL;
        ProbeBackend backend;
        const auto result = backend.run(state, vm, 1);
        expect(result.reason == macosarm::StopReason::instruction_budget,
               "backend result carries bounded stop reason");
        expect(result.instructions_executed == 1, "backend reports instruction count");
        expect(backend.observed_instruction == 0xd2800020U,
               "backend consumes shared instruction-fetch helper");
        expect(state.pc == 0x300000004ULL, "backend may update shared CPU state");

        const auto zero_budget = backend.run(state, vm, 0);
        expect(zero_budget.instructions_executed == 0,
               "zero instruction budget executes nothing");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "all execution-contract tests passed\n";
    return EXIT_SUCCESS;
}
