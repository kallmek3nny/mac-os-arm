#include "macosarm/darwin_syscall.hpp"

#include <algorithm>
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

struct CaptureHost final : macosarm::DarwinHostServices {
    std::vector<std::byte> captured;
    std::vector<std::int32_t> fds;
    std::size_t largest_request{};
    std::uint32_t next_error{};
    std::uint64_t short_write{};
    bool violate_contract{};

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        fds.push_back(fd);
        largest_request = std::max(largest_request, bytes.size());

        if (next_error != 0) {
            const std::uint32_t error = next_error;
            next_error = 0;
            return {0, error};
        }
        if (violate_contract) {
            return {static_cast<std::uint64_t>(bytes.size()) + 1, 0};
        }

        std::size_t count = bytes.size();
        if (short_write != 0) {
            count = static_cast<std::size_t>(std::min<std::uint64_t>(short_write, bytes.size()));
            short_write = 0;
        }
        captured.insert(captured.end(), bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(count));
        return {count, 0};
    }
};

macosarm::ExecutionResult svc(std::uint32_t immediate = macosarm::kDarwinSvcImmediate) {
    return {
        macosarm::StopReason::supervisor_call,
        1,
        immediate,
        macosarm::VmError::none,
    };
}

bool carry_is_set(const macosarm::CpuState& state) {
    return (state.pstate & macosarm::kA64PstateCarry) != 0;
}

void load_readable(
    macosarm::GuestAddressSpace& vm,
    std::uint64_t base,
    std::span<const std::byte> bytes) {
    const std::uint64_t rounded =
        ((bytes.size() + macosarm::GuestAddressSpace::kPageSize - 1) /
         macosarm::GuestAddressSpace::kPageSize) * macosarm::GuestAddressSpace::kPageSize;
    expect(static_cast<bool>(vm.map(base, rounded, macosarm::Protection::read)), "test buffer maps");
    expect(static_cast<bool>(vm.load_bytes(base, bytes)), "test buffer loads");
}

} // namespace

int main() {
    constexpr std::uint64_t buffer_base = 0x200000000ULL;

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{
            std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = message.size();
        state.pstate = macosarm::kA64PstateCarry;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "write dispatch succeeds");
        expect(result.action == macosarm::SyscallAction::resume, "write resumes guest");
        expect(result.syscall_number == macosarm::kDarwinSysWrite, "write syscall number reported");
        expect(state.x[0] == message.size(), "write byte count returned in x0");
        expect(!carry_is_set(state), "successful write clears carry");
        expect(host.fds.size() == 1 && host.fds[0] == 1, "write fd forwarded");
        expect(host.captured == message, "write bytes copied from guest memory");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 2;
        state.x[1] = buffer_base;
        state.x[2] = 8;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "guest EFAULT is a handled syscall");
        expect(state.x[0] == macosarm::kDarwinErrnoEfault, "unmapped write returns EFAULT");
        expect(carry_is_set(state), "EFAULT sets carry");
        expect(host.fds.empty(), "EFAULT does not call host write");
    }

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{std::byte{'x'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        host.next_error = 32;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = 1;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "host errno is handled");
        expect(state.x[0] == 32, "host errno returned in x0");
        expect(carry_is_set(state), "host errno sets carry");
    }

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{
            std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        host.short_write = 2;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = message.size();

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "short write is handled");
        expect(state.x[0] == 2, "short write count returned");
        expect(!carry_is_set(state), "short write is still success");
        expect(host.captured.size() == 2, "short write stops after host short count");
    }

    {
        macosarm::GuestAddressSpace vm;
        std::vector<std::byte> large(64 * 1024 + 3, std::byte{0x5a});
        load_readable(vm, buffer_base, large);

        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = large.size();

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "large write succeeds");
        expect(state.x[0] == large.size(), "large write returns full byte count");
        expect(host.fds.size() == 2, "large write is split into bounded chunks");
        expect(host.largest_request <= 64 * 1024, "host write chunk is capped at 64 KiB");
        expect(host.captured == large, "chunked write preserves guest bytes");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = 0xfeed;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "unknown syscall is handled");
        expect(state.x[0] == macosarm::kDarwinErrnoEnosys, "unknown syscall returns ENOSYS");
        expect(carry_is_set(state), "ENOSYS sets carry");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysExit;
        state.x[0] = 0x12345678ULL;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(static_cast<bool>(result), "exit dispatch succeeds");
        expect(result.action == macosarm::SyscallAction::exit_process, "exit terminates guest process");
        expect(result.exit_status == static_cast<std::int32_t>(0x12345678U), "exit preserves 32-bit status");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        macosarm::ExecutionResult execution{};
        execution.reason = macosarm::StopReason::instruction_budget;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, execution, host);
        expect(result.error == macosarm::SyscallDispatchError::not_supervisor_call,
               "non-SVC stop is rejected");

        const auto wrong_svc = macosarm::dispatch_darwin_syscall(state, vm, svc(0x42), host);
        expect(wrong_svc.error == macosarm::SyscallDispatchError::unsupported_svc,
               "non-Darwin SVC immediate is rejected");
    }

    {
        macosarm::GuestAddressSpace vm;
        const std::vector<std::byte> message{std::byte{'z'}};
        load_readable(vm, buffer_base, message);

        CaptureHost host;
        host.violate_contract = true;
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinSysWrite;
        state.x[0] = 1;
        state.x[1] = buffer_base;
        state.x[2] = 1;

        const auto result = macosarm::dispatch_darwin_syscall(state, vm, svc(), host);
        expect(result.error == macosarm::SyscallDispatchError::host_contract_violation,
               "impossible host write count is rejected");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Darwin syscall dispatch tests passed\n";
    return EXIT_SUCCESS;
}
