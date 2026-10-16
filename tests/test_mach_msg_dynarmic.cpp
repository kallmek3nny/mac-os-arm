#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/mach_trap.hpp"
#include "macosarm/process.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
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

void put_u32(std::span<std::byte> bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

void put_u64(std::span<std::byte> bytes, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        bytes[offset + i] = static_cast<std::byte>((value >> (i * 8)) & 0xffU);
    }
}

std::uint32_t get_u32(std::span<const std::byte> bytes, std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        value |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes[offset + i]))
            << (i * 8);
    }
    return value;
}

bool has_mapping(
    const macosarm::GuestAddressSpace& vm,
    std::uint64_t base,
    std::uint64_t size,
    macosarm::Protection protection) {
    for (const auto& mapping : vm.mappings()) {
        if (mapping.base == base && mapping.size == size && mapping.protection == protection) {
            return true;
        }
    }
    return false;
}

struct NullHost final : macosarm::DarwinHostServices {
    macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> data) override {
        return {data.size(), 0};
    }
};

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;

    {
        constexpr std::uint64_t code_base = 0x100000000ULL;
        constexpr std::uint64_t message_base = 0x200000000ULL;

        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "JIT Mach message code page maps");
        expect(static_cast<bool>(vm.map(
                   message_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::write)),
               "JIT Mach message data page maps");

        std::array<std::byte, GuestAddressSpace::kPageSize> code{};
        put_instruction(code, 0, 0x92800330U);  // movn x16, #25 => -26 mach_reply_port
        put_instruction(code, 4, 0xd4001001U);  // svc #0x80
        put_instruction(code, 8, 0xaa0003f4U);  // mov x20, x0 (reply port)
        put_instruction(code, 12, 0xaa1303e0U); // mov x0, x19 (message pointer)
        put_instruction(code, 16, 0x928003d0U); // movn x16, #30 => -31 mach_msg_trap
        put_instruction(code, 20, 0xd4001001U); // svc #0x80
        put_instruction(code, 24, 0xaa0003f5U); // mov x21, x0 (mach_msg return)
        put_instruction(code, 28, 0xd2800000U); // mov x0, #0
        put_instruction(code, 32, 0xd2800030U); // mov x16, #1 (exit)
        put_instruction(code, 36, 0xd4001001U); // svc #0x80
        expect(static_cast<bool>(vm.load_bytes(code_base, code)), "JIT Mach message program loads");

        std::array<std::byte, 32> message{};
        put_u32(message, 0, 19U); // simple remote COPY_SEND disposition
        put_u32(message, 4, static_cast<std::uint32_t>(message.size()));
        put_u32(message, 8, macosarm::MachContext::kFirstReplyPort);
        put_u32(message, 12, 0);
        put_u32(message, 16, 0);
        put_u32(message, 20, 0x4142U);
        message[24] = std::byte{'j'};
        message[25] = std::byte{'i'};
        message[26] = std::byte{'t'};
        message[27] = std::byte{'!'};
        expect(static_cast<bool>(vm.write(message_base, message)), "JIT Mach message payload loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = 0x700000000ULL;
        state.x[19] = message_base;
        state.x[1] = macosarm::kMachSendMsg | macosarm::kMachRcvMsg;
        state.x[2] = message.size();
        state.x[3] = message.size();
        state.x[4] = macosarm::MachContext::kFirstReplyPort;
        state.x[5] = 0;
        state.x[6] = 0;

        NullHost host;
        macosarm::DynarmicBackend backend;
        const auto result = macosarm::run_process(state, vm, backend, host, 32);

        expect(result.reason == macosarm::ProcessStopReason::exited,
               "real JIT resumes after mach_msg and exits through BSD");
        expect(result.exit_status == 0, "Mach message JIT program exits cleanly");
        expect(result.instructions_executed == 10,
               "Mach message path accounts for every translated instruction");
        expect(state.x[20] == macosarm::MachContext::kFirstReplyPort,
               "translated guest observes deterministic reply port");
        expect(state.x[21] == macosarm::kMachMsgSuccess,
               "translated guest observes MACH_MSG_SUCCESS");
        expect(state.pc == code_base + 40, "JIT PC advances past final BSD SVC");

        std::array<std::byte, 32> received{};
        expect(static_cast<bool>(vm.read(message_base, received)), "JIT receive buffer is readable");
        expect(get_u32(received, 4) == received.size(), "JIT received header preserves message size");
        expect(get_u32(received, 8) == 0, "JIT receive remote port is original reply port");
        expect(get_u32(received, 12) == macosarm::MachContext::kFirstReplyPort,
               "JIT receive local port is original destination");
        expect((get_u32(received, 0) & macosarm::kMachMsgBitsLocalMask) == (19U << 8),
               "JIT receive swaps disposition bits into local field");
        expect(received[24] == std::byte{'j'} && received[27] == std::byte{'!'},
               "JIT Mach transport preserves inline payload");
    }

    {
        constexpr std::uint64_t code_base = 0x110000000ULL;
        constexpr std::uint64_t control_base = 0x210000000ULL;
        constexpr std::uint64_t allocation_size = GuestAddressSpace::kPageSize * 2;

        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(
                   code_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::execute)),
               "JIT mach_vm_map code page maps");
        expect(static_cast<bool>(vm.map(
                   control_base,
                   GuestAddressSpace::kPageSize,
                   Protection::read | Protection::write)),
               "JIT mach_vm_map output page maps");

        std::array<std::byte, GuestAddressSpace::kPageSize> code{};
        put_instruction(code, 0, 0x92800370U);  // mov x16, #-28 (task_self_trap)
        put_instruction(code, 4, 0xd4001001U);  // svc #0x80
        put_instruction(code, 8, 0xaa0003e9U);  // mov x9, x0 (task port)
        put_instruction(code, 12, 0xaa0903e0U); // mov x0, x9
        put_instruction(code, 16, 0xaa1303e1U); // mov x1, x19 (address pointer)
        put_instruction(code, 20, 0xd2900002U); // mov x2, #0x8000 (two 16K pages)
        put_instruction(code, 24, 0xd2800003U); // mov x3, #0 (mask)
        put_instruction(code, 28, 0xd2800024U); // mov x4, #1 (VM_FLAGS_ANYWHERE)
        put_instruction(code, 32, 0xf2a92004U); // movk x4, #0x4900, lsl #16 (tag 73)
        put_instruction(code, 36, 0xd2800065U); // mov x5, #3 (VM_PROT_DEFAULT)
        put_instruction(code, 40, 0x928001d0U); // mov x16, #-15 (mach_vm_map trap)
        put_instruction(code, 44, 0xd4001001U); // svc #0x80
        put_instruction(code, 48, 0xaa0003f4U); // mov x20, x0 (kern_return_t)
        put_instruction(code, 52, 0xf9400275U); // ldr x21, [x19] (mapped address)
        put_instruction(code, 56, 0xd2800556U); // mov x22, #42
        put_instruction(code, 60, 0xf90002b6U); // str x22, [x21]
        put_instruction(code, 64, 0xf94002b7U); // ldr x23, [x21]
        put_instruction(code, 68, 0xaa1703e0U); // mov x0, x23
        put_instruction(code, 72, 0xd2800030U); // mov x16, #1 (exit)
        put_instruction(code, 76, 0xd4001001U); // svc #0x80
        expect(static_cast<bool>(vm.load_bytes(code_base, code)),
               "JIT libplatform-style mach_vm_map probe loads");

        std::array<std::byte, 8> address_slot{};
        put_u64(address_slot, 0, GuestAddressSpace::kPageSize);
        expect(static_cast<bool>(vm.write(control_base, address_slot)),
               "JIT mach_vm_map address slot starts at PAGE_SIZE like os_alloc_once");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = 0x700000000ULL;
        state.x[19] = control_base;

        NullHost host;
        macosarm::DynarmicBackend backend;
        const auto result = macosarm::run_process(state, vm, backend, host, 48);

        expect(result.reason == macosarm::ProcessStopReason::exited,
               "real JIT resumes after libplatform-style mach_vm_map and exits");
        expect(result.exit_status == 42,
               "translated guest can write and read the anonymous mapped heap");
        expect(result.instructions_executed == 20,
               "mach_vm_map JIT path accounts for every translated instruction");
        expect(state.x[20] == macosarm::kMachKernSuccess,
               "translated guest observes KERN_SUCCESS from mach_vm_map trap");
        expect(state.x[21] == macosarm::MachContext::kVmAnywhereBase,
               "translated guest receives deterministic VM_FLAGS_ANYWHERE base");
        expect(state.x[23] == 42,
               "translated guest reads durable state back from the mapped heap");
        expect(state.pc == code_base + 80,
               "mach_vm_map JIT probe stops immediately after exit SVC");
        expect(has_mapping(
                   vm,
                   macosarm::MachContext::kVmAnywhereBase,
                   allocation_size,
                   Protection::read | Protection::write),
               "real Dynarmic trap materializes the two-page os_alloc_once mapping");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Dynarmic Mach transport and VM map tests passed\n";
    return EXIT_SUCCESS;
}
