#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/process.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <vector>

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

std::uint64_t read_guest_u64(const macosarm::GuestAddressSpace& vm, std::uint64_t address) {
    std::array<std::byte, 8> bytes{};
    expect(static_cast<bool>(vm.read(address, bytes)), "JIT test reads guest u64");
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[i])) << (i * 8);
    }
    return value;
}

struct CaptureHost final : macosarm::DarwinHostServices {
    std::vector<std::byte> bytes;
    std::int32_t fd{-1};

    macosarm::HostWriteResult write(
        std::int32_t new_fd,
        std::span<const std::byte> data) override {
        fd = new_fd;
        bytes.insert(bytes.end(), data.begin(), data.end());
        return {data.size(), 0};
    }
};

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
        expect(state.pc == code_base + 12, "PC advances past SVC before returning to dispatcher");
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

    {
        constexpr std::uint64_t data_base = 0x200000000ULL;
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(code_base, GuestAddressSpace::kPageSize,
                                        Protection::read | Protection::execute)),
               "process code page maps");
        expect(static_cast<bool>(vm.map(data_base, GuestAddressSpace::kPageSize,
                                        Protection::read)),
               "process data page maps");

        std::array<std::byte, GuestAddressSpace::kPageSize> code{};
        put_instruction(code, 0, 0xd2800090U);  // mov x16, #4 (write)
        put_instruction(code, 4, 0xd4001001U);  // svc #0x80
        put_instruction(code, 8, 0xd28000e0U);  // mov x0, #7
        put_instruction(code, 12, 0xd2800030U); // mov x16, #1 (exit)
        put_instruction(code, 16, 0xd4001001U); // svc #0x80
        expect(static_cast<bool>(vm.load_bytes(code_base, code)), "process program loads");

        const std::array<std::byte, 5> message{
            std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
        expect(static_cast<bool>(vm.load_bytes(data_base, message)), "process message loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = 0x700000000ULL;
        state.x[0] = 1;
        state.x[1] = data_base;
        state.x[2] = message.size();

        CaptureHost host;
        macosarm::DynarmicBackend backend;
        const auto result = macosarm::run_process(state, vm, backend, host, 16);

        expect(result.reason == macosarm::ProcessStopReason::exited,
               "process runner drives real JIT through write and exit");
        expect(result.exit_status == 7, "process runner preserves ARM64 exit status");
        expect(result.instructions_executed == 5,
               "process runner totals real JIT instructions across both syscalls");
        expect(state.pc == code_base + 20, "process runner leaves PC after final SVC");
        expect(state.x[16] == macosarm::kDarwinSysExit, "final JIT syscall number is exit");
        expect(host.fd == 1 && host.bytes == std::vector<std::byte>(message.begin(), message.end()),
               "one process run forwards guest stdout bytes");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(code_base, GuestAddressSpace::kPageSize,
                                        Protection::read | Protection::execute)),
               "Mach process code page maps");

        std::array<std::byte, GuestAddressSpace::kPageSize> code{};
        put_instruction(code, 0, 0x92800370U);  // movn x16, #27 => -28 (task_self_trap)
        put_instruction(code, 4, 0xd4001001U);  // svc #0x80
        put_instruction(code, 8, 0xaa0003f3U);  // mov x19, x0
        put_instruction(code, 12, 0xd2800000U); // mov x0, #0
        put_instruction(code, 16, 0xd2800030U); // mov x16, #1 (exit)
        put_instruction(code, 20, 0xd4001001U); // svc #0x80
        expect(static_cast<bool>(vm.load_bytes(code_base, code)), "Mach process program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = 0x700000000ULL;

        CaptureHost host;
        macosarm::DynarmicBackend backend;
        const auto result = macosarm::run_process(state, vm, backend, host, 16);

        expect(result.reason == macosarm::ProcessStopReason::exited,
               "real JIT resumes from Mach task_self into BSD exit");
        expect(result.exit_status == 0, "mixed Mach/BSD JIT program exits cleanly");
        expect(result.instructions_executed == 6,
               "mixed Mach/BSD path accounts for every translated instruction");
        expect(state.x[19] == macosarm::MachContext::kDefaultTaskSelfPort,
               "translated ARM64 observes the synthetic task-self port");
        expect(state.pc == code_base + 24, "mixed trap program leaves PC after final SVC");
    }

    {
        constexpr std::uint64_t control_base = 0x300000000ULL;
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(code_base, GuestAddressSpace::kPageSize,
                                        Protection::read | Protection::execute)),
               "Mach VM JIT code page maps");
        expect(static_cast<bool>(vm.map(control_base, GuestAddressSpace::kPageSize,
                                        Protection::read | Protection::write)),
               "Mach VM JIT control page maps");

        std::array<std::byte, GuestAddressSpace::kPageSize> code{};
        put_instruction(code, 0, 0x92800370U);  // movn x16, #27 => -28 task_self
        put_instruction(code, 4, 0xd4001001U);  // svc #0x80
        put_instruction(code, 8, 0xaa0003f4U);  // mov x20, x0
        put_instruction(code, 12, 0xaa1403e0U); // mov x0, x20 (target task port)
        put_instruction(code, 16, 0xd2880002U); // mov x2, #0x4000 (one 16K page)
        put_instruction(code, 20, 0xd2800023U); // mov x3, #1 (VM_FLAGS_ANYWHERE)
        put_instruction(code, 24, 0x92800130U); // movn x16, #9 => -10 mach_vm_allocate
        put_instruction(code, 28, 0xd4001001U); // svc #0x80
        put_instruction(code, 32, 0xaa0003f5U); // mov x21, x0 (kern_return_t)
        put_instruction(code, 36, 0xd2800000U); // mov x0, #0
        put_instruction(code, 40, 0xd2800030U); // mov x16, #1 (exit)
        put_instruction(code, 44, 0xd4001001U); // svc #0x80
        expect(static_cast<bool>(vm.load_bytes(code_base, code)), "Mach VM JIT program loads");

        macosarm::CpuState state{};
        state.pc = code_base;
        state.sp = 0x700000000ULL;
        state.x[1] = control_base;

        CaptureHost host;
        macosarm::DynarmicBackend backend;
        const auto result = macosarm::run_process(state, vm, backend, host, 32);

        expect(result.reason == macosarm::ProcessStopReason::exited,
               "real JIT resumes after mach_vm_allocate and reaches BSD exit");
        expect(result.exit_status == 0, "Mach VM JIT program exits cleanly");
        expect(result.instructions_executed == 12,
               "Mach VM JIT path accounts for every translated instruction");
        expect(state.x[20] == macosarm::MachContext::kDefaultTaskSelfPort,
               "Mach VM JIT keeps the task-self port across traps");
        expect(state.x[21] == macosarm::kMachKernSuccess,
               "translated guest observes KERN_SUCCESS from mach_vm_allocate");

        const std::uint64_t allocated = read_guest_u64(vm, control_base);
        expect(allocated == macosarm::MachContext::kVmAnywhereBase,
               "mach_vm_allocate copyout reaches guest memory during real JIT run");
        const std::array<std::byte, 1> marker{std::byte{0x6b}};
        expect(static_cast<bool>(vm.write(allocated, marker)),
               "real JIT Mach allocation is writable guest memory");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Dynarmic ARM64 JIT tests passed\n";
    return EXIT_SUCCESS;
}
