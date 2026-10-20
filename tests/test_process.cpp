#include "macosarm/process.hpp"
#include "macosarm/guest_threads.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>
#include <utility>
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
    std::vector<std::byte> bytes;
    std::size_t calls{};

    macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte> data) override {
        ++calls;
        bytes.insert(bytes.end(), data.begin(), data.end());
        return {data.size(), 0};
    }
};

struct ScriptStep {
    macosarm::ExecutionResult execution{};
    bool set_registers{};
    std::uint64_t x0{};
    std::uint64_t x1{};
    std::uint64_t x2{};
    std::uint64_t x16{};
};

class ScriptedBackend final : public macosarm::ExecutionBackend {
public:
    explicit ScriptedBackend(std::vector<ScriptStep> steps) : steps_(std::move(steps)) {}

    macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace&,
        std::uint64_t instruction_budget) override {
        budgets.push_back(instruction_budget);
        if (cursor_ >= steps_.size()) {
            return {macosarm::StopReason::backend_error, 0, 0, macosarm::VmError::none};
        }

        const ScriptStep& step = steps_[cursor_++];
        if (step.set_registers) {
            state.x[0] = step.x0;
            state.x[1] = step.x1;
            state.x[2] = step.x2;
            state.x[16] = step.x16;
        }
        return step.execution;
    }

    [[nodiscard]] std::size_t calls() const noexcept { return cursor_; }

    std::vector<std::uint64_t> budgets;

private:
    std::vector<ScriptStep> steps_;
    std::size_t cursor_{};
};

macosarm::ExecutionResult svc(std::uint64_t instructions, std::uint32_t immediate = 0x80) {
    return {
        macosarm::StopReason::supervisor_call,
        instructions,
        immediate,
        macosarm::VmError::none,
    };
}

void load_message(
    macosarm::GuestAddressSpace& vm,
    std::uint64_t base,
    std::span<const std::byte> message) {
    expect(static_cast<bool>(vm.map(
               base,
               macosarm::GuestAddressSpace::kPageSize,
               macosarm::Protection::read)),
           "process test message page maps");
    expect(static_cast<bool>(vm.load_bytes(base, message)), "process test message loads");
}

} // namespace

#include "test_guest_threads_direct.inc"
#include "test_main_thread_errno_tsd.inc"
#include "test_owned_guest_stacks.inc"

int main() {
    constexpr std::uint64_t data_base = 0x200000000ULL;
    const std::vector<std::byte> message{
        std::byte{'h'}, std::byte{'e'}, std::byte{'l'}, std::byte{'l'}, std::byte{'o'}};

    {
        macosarm::GuestAddressSpace vm;
        load_message(vm, data_base, message);
        CaptureHost host;
        macosarm::CpuState state{};
        ScriptedBackend backend({
            {svc(2), true, 1, data_base, message.size(), macosarm::kDarwinSysWrite},
            {svc(3), true, 7, 0, 0, macosarm::kDarwinSysExit},
        });

        const auto result = macosarm::run_process(state, vm, backend, host, 10);
        expect(result.reason == macosarm::ProcessStopReason::exited, "runner reaches guest exit");
        expect(result.exit_status == 7, "runner preserves exit status");
        expect(result.instructions_executed == 5, "runner totals instructions across syscalls");
        expect(backend.calls() == 2, "runner resumes backend after write");
        expect(backend.budgets.size() == 2 && backend.budgets[0] == 10 && backend.budgets[1] == 8,
               "runner decreases the total instruction budget");
        expect(host.bytes == message, "runner dispatches write before exit");
    }

    {
        macosarm::GuestAddressSpace vm;
        load_message(vm, data_base, message);
        CaptureHost host;
        macosarm::CpuState state{};
        ScriptedBackend backend({
            {svc(2), true, 1, data_base, message.size(), macosarm::kDarwinSysWrite},
            {svc(1), true, 9, 0, 0, macosarm::kDarwinSysExit},
        });

        const auto result = macosarm::run_process(state, vm, backend, host, 2);
        expect(result.reason == macosarm::ProcessStopReason::instruction_budget,
               "total budget stops after a resumable syscall");
        expect(result.instructions_executed == 2, "budget result reports exact total");
        expect(backend.calls() == 1, "budget exhaustion prevents another backend run");
        expect(host.bytes == message, "syscall reached at budget edge still dispatches");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        ScriptedBackend backend({
            {{macosarm::StopReason::memory_fault, 4, 0, macosarm::VmError::unmapped}, false, 0, 0, 0, 0},
        });

        const auto result = macosarm::run_process(state, vm, backend, host, 20);
        expect(result.reason == macosarm::ProcessStopReason::memory_fault,
               "runner preserves backend memory faults");
        expect(result.vm_error == macosarm::VmError::unmapped, "runner preserves VM error");
        expect(result.instructions_executed == 4, "fault includes executed instruction count");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        ScriptedBackend backend({
            {svc(1, 0x42), true, 0, 0, 0, macosarm::kDarwinSysWrite},
        });

        const auto result = macosarm::run_process(state, vm, backend, host, 10);
        expect(result.reason == macosarm::ProcessStopReason::syscall_error,
               "runner reports syscall dispatcher failures");
        expect(result.syscall_error == macosarm::SyscallDispatchError::unsupported_svc,
               "runner preserves syscall dispatcher error");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        ScriptedBackend backend({
            {svc(0), true, 0, 0, 0, 0xfeed},
        });

        const auto result = macosarm::run_process(state, vm, backend, host, 10);
        expect(result.reason == macosarm::ProcessStopReason::backend_error,
               "zero-progress resumable stop is rejected");
        expect(backend.calls() == 1, "zero-progress guard prevents an infinite loop");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        ScriptedBackend backend({
            {{macosarm::StopReason::instruction_budget, 11, 0, macosarm::VmError::none}, false, 0, 0, 0, 0},
        });

        const auto result = macosarm::run_process(state, vm, backend, host, 10);
        expect(result.reason == macosarm::ProcessStopReason::backend_error,
               "backend cannot claim more instructions than remaining budget");
        expect(result.instructions_executed == 0, "invalid backend count is not accumulated");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::CpuState state{};
        ScriptedBackend backend({
            {svc(1), true, 0, 0, 0, macosarm::kDarwinSysExit},
        });

        const auto result = macosarm::run_process(state, vm, backend, host, 0);
        expect(result.reason == macosarm::ProcessStopReason::instruction_budget,
               "zero total budget exits immediately");
        expect(result.instructions_executed == 0, "zero budget executes nothing");
        expect(backend.calls() == 0, "zero budget never enters backend");
    }

    {
        macosarm::GuestAddressSpace vm;
        CaptureHost host;
        macosarm::MachContext mach_context;

        macosarm::CpuState first_state{};
        ScriptedBackend first_backend({
            {svc(1), true, 0, 0, 0,
             static_cast<std::uint64_t>(macosarm::kMachTrapReplyPort)},
        });
        const auto first = macosarm::run_process(
            first_state,
            vm,
            first_backend,
            host,
            mach_context,
            1);
        expect(first.reason == macosarm::ProcessStopReason::instruction_budget &&
                   first_state.x[0] == macosarm::MachContext::kFirstReplyPort,
               "caller-owned process Mach context allocates first reply port");

        macosarm::CpuState second_state{};
        ScriptedBackend second_backend({
            {svc(1), true, 0, 0, 0,
             static_cast<std::uint64_t>(macosarm::kMachTrapReplyPort)},
        });
        const auto second = macosarm::run_process(
            second_state,
            vm,
            second_backend,
            host,
            mach_context,
            1);
        expect(second.reason == macosarm::ProcessStopReason::instruction_budget &&
                   second_state.x[0] == macosarm::MachContext::kFirstReplyPort + 1U,
               "caller-owned process Mach context persists across process runs");
    }

    test_guest_threads_direct();
    test_main_thread_errno_tls_direct();
    test_owned_guest_stacks();

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "bounded process runner tests passed\n";
    return EXIT_SUCCESS;
}
