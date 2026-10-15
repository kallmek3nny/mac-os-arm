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

macosarm::PointerAuthKeySet test_keys() {
    macosarm::PointerAuthKeySet keys;
    keys.values[0] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
    keys.values[1] = {0x1111222233334444ULL, 0x5555666677778888ULL};
    keys.values[2] = {0x1020304050607080ULL, 0x90a0b0c0d0e0f000ULL};
    keys.values[3] = {0x0f1e2d3c4b5a6978ULL, 0x8796a5b4c3d2e1f0ULL};
    return keys;
}

} // namespace

int main() {
    using macosarm::DynarmicBackend;
    using macosarm::GuestAddressSpace;
    using macosarm::PointerAuthenticator;
    using macosarm::Protection;
    using macosarm::StopReason;

    constexpr std::uint64_t code_base = 0x100000000ULL;
    constexpr std::uint64_t stack_pointer = 0x700000000ULL;
    constexpr std::uint64_t return_address = 0x100001234ULL;
    constexpr std::uint32_t paciasp = 0xd503233fU;
    constexpr std::uint32_t autiasp = 0xd50323bfU;
    constexpr std::uint32_t pacibsp = 0xd503237fU;
    constexpr std::uint32_t autibsp = 0xd50323ffU;
    constexpr std::uint32_t xpaclri = 0xd50320ffU;
    constexpr std::uint32_t pacia1716 = 0xd503211fU;
    constexpr std::uint32_t autia1716 = 0xd503219fU;
    constexpr std::uint32_t pacib1716 = 0xd503215fU;
    constexpr std::uint32_t autib1716 = 0xd50321dfU;

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "PAUTH default-rejection code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, paciasp);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "PAUTH default-rejection program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[30] = return_address;

        DynarmicBackend backend;
        const auto result = backend.run(state, vm, 1);
        expect(result.reason == StopReason::exception,
               "PAUTH instruction without explicit key policy traps");
        expect(result.instructions_executed == 1,
               "rejected PAUTH instruction consumes one execution slot");
        expect(state.pc == code_base,
               "rejected PAUTH instruction does not advance PC");
        expect(state.x[30] == return_address,
               "rejected PAUTH instruction leaves LR untouched");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "PACIASP/AUTIASP code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, paciasp);
        put_instruction(page, 4, autiasp);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "PACIASP/AUTIASP program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[30] = return_address;

        DynarmicBackend backend(test_keys());
        const auto signed_step = backend.run(state, vm, 1);
        expect(signed_step.reason == StopReason::instruction_budget,
               "PACIASP completes inside execution budget");
        expect(state.pc == code_base + 4,
               "PACIASP advances PC exactly one instruction");
        expect(state.x[30] != return_address,
               "PACIASP writes a signed LR rather than behaving as NOP");
        expect(PointerAuthenticator::strip(state.x[30]) == return_address,
               "PACIASP software signature preserves raw LR bits");

        const auto auth_step = backend.run(state, vm, 1);
        expect(auth_step.reason == StopReason::instruction_budget,
               "AUTIASP completes inside execution budget");
        expect(state.pc == code_base + 8,
               "AUTIASP advances PC exactly one instruction");
        expect(state.x[30] == return_address,
               "AUTIASP authenticates and restores LR");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "PACIBSP/AUTIBSP code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, pacibsp);
        put_instruction(page, 4, autibsp);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "PACIBSP/AUTIBSP program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[30] = return_address;

        DynarmicBackend backend(test_keys());
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "PACIBSP signs LR with IB and SP");
        expect(state.x[30] != return_address,
               "PACIBSP changes LR");
        expect(PointerAuthenticator::strip(state.x[30]) == return_address,
               "PACIBSP preserves raw LR bits under software PAC");
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "AUTIBSP authenticates LR with IB and SP");
        expect(state.x[30] == return_address,
               "AUTIBSP restores raw LR");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "tamper-detection code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, paciasp);
        put_instruction(page, 4, autiasp);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "tamper-detection program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[30] = return_address;
        DynarmicBackend backend(test_keys());
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "tamper test signs LR first");
        state.x[30] ^= 0x20U;
        const std::uint64_t tampered = state.x[30];

        const auto result = backend.run(state, vm, 1);
        expect(result.reason == StopReason::exception,
               "AUTIASP traps on tampered LR");
        expect(state.pc == code_base + 4,
               "failed AUTIASP leaves PC on failing instruction");
        expect(state.x[30] == tampered,
               "failed AUTIASP does not replace tampered LR");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "modifier-mismatch code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, paciasp);
        put_instruction(page, 4, autiasp);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "modifier-mismatch program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[30] = return_address;
        DynarmicBackend backend(test_keys());
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "modifier-mismatch test signs LR first");
        state.sp += 16;
        const auto result = backend.run(state, vm, 1);
        expect(result.reason == StopReason::exception,
               "AUTIASP rejects LR when SP discriminator changed");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "key-mismatch code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, paciasp);
        put_instruction(page, 4, autibsp);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "key-mismatch program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[30] = return_address;
        DynarmicBackend backend(test_keys());
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "key-mismatch test signs LR with IA");
        expect(backend.run(state, vm, 1).reason == StopReason::exception,
               "AUTIBSP rejects LR signed with IA key");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "XPACLRI code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, paciasp);
        put_instruction(page, 4, xpaclri);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "XPACLRI program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[30] = return_address;
        DynarmicBackend backend(test_keys());
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "XPACLRI test signs LR first");
        expect(state.x[30] != return_address,
               "XPACLRI test starts with signed LR");
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "XPACLRI executes under configured PAUTH policy");
        expect(state.x[30] == return_address,
               "XPACLRI strips software PAC from LR");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "IA 1716 PAUTH code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, pacia1716);
        put_instruction(page, 4, autia1716);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "IA 1716 PAUTH program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[16] = 0x12345678ULL;
        state.x[17] = return_address;
        DynarmicBackend backend(test_keys());
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "PACIA1716 signs X17 with X16 modifier");
        expect(state.x[17] != return_address,
               "PACIA1716 changes X17");
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "AUTIA1716 authenticates X17 with X16 modifier");
        expect(state.x[17] == return_address,
               "AUTIA1716 restores raw X17 pointer");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "IB 1716 PAUTH code page maps");
        std::array<std::byte, GuestAddressSpace::kPageSize> page{};
        put_instruction(page, 0, pacib1716);
        put_instruction(page, 4, autib1716);
        expect(static_cast<bool>(vm.load_bytes(code_base, page)),
               "IB 1716 PAUTH program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = stack_pointer;
        state.x[16] = 0x87654321ULL;
        state.x[17] = return_address;
        DynarmicBackend backend(test_keys());
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "PACIB1716 signs X17 with X16 modifier");
        expect(state.x[17] != return_address,
               "PACIB1716 changes X17");
        expect(backend.run(state, vm, 1).reason == StopReason::instruction_budget,
               "AUTIB1716 authenticates X17 with X16 modifier");
        expect(state.x[17] == return_address,
               "AUTIB1716 restores raw X17 pointer");
    }

    if (failures != 0) {
        std::cerr << failures << " Dynarmic PAUTH test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Dynarmic PAUTH tests passed\n";
    return EXIT_SUCCESS;
}
