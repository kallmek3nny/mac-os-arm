#include "macosarm/darwin_syscall.hpp"

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

} // namespace

int main() {
    using macosarm::DarwinCallClass;
    using macosarm::UnixReturn;
    using macosarm::UnixReturnDisposition;

    {
        macosarm::CpuState state{};
        state.x[16] = 20;
        for (std::size_t i = 0; i < 8; ++i) {
            state.x[i] = 0x100 + i;
        }

        const auto call = macosarm::decode_darwin_svc(state, 0x80);
        expect(call.call_class == DarwinCallClass::unix_syscall, "positive x16 selects unix syscall");
        expect(call.number == 20, "direct unix syscall number comes from x16");
        expect(call.svc_immediate == 0x80, "SVC immediate preserved as metadata");
        expect(!call.indirect, "direct unix syscall is not marked indirect");
        expect(call.arguments[0] == 0x100 && call.arguments[7] == 0x107,
               "direct unix arguments come from x0 through x7");
    }

    {
        macosarm::CpuState state{};
        state.x[16] = 0;
        state.x[0] = 4;
        for (std::size_t i = 1; i <= 8; ++i) {
            state.x[i] = 0x200 + i;
        }

        const auto call = macosarm::decode_darwin_svc(state, 0x80);
        expect(call.call_class == DarwinCallClass::unix_syscall, "x16 zero remains unix class");
        expect(call.indirect, "x16 zero selects indirect unix ABI");
        expect(call.number == 4, "indirect unix syscall number comes from x0");
        expect(call.arguments[0] == 0x201 && call.arguments[7] == 0x208,
               "indirect unix arguments shift to x1 through x8");
    }

    {
        macosarm::CpuState state{};
        state.x[16] = static_cast<std::uint64_t>(static_cast<std::int64_t>(-10));
        state.x[0] = 0xabc;
        const auto call = macosarm::decode_darwin_svc(state, 0x80);
        expect(call.call_class == DarwinCallClass::mach_trap, "negative x16 selects Mach trap");
        expect(call.number == 10, "Mach trap number is normalized to positive index");
        expect(!call.indirect, "Mach trap is never unix-indirect");
        expect(call.arguments[0] == 0xabc, "Mach arguments start at x0");
    }

    {
        macosarm::CpuState state{};
        state.x[16] = macosarm::kDarwinPlatformTrap;
        const auto call = macosarm::decode_darwin_svc(state, 0x80);
        expect(call.call_class == DarwinCallClass::platform_syscall,
               "0x80000000 selector is platform syscall, not Mach trap");
        expect(call.number == macosarm::kDarwinPlatformTrap, "platform selector preserved");
    }

    {
        macosarm::CpuState state{};
        state.pstate = macosarm::kDarwinPstateCarry | 0x40000000U;
        macosarm::apply_unix_return(state, UnixReturn{
            UnixReturnDisposition::success, 0x1234, 0x5678, 0});
        expect(state.x[0] == 0x1234 && state.x[1] == 0x5678,
               "unix success writes x0/x1 return values");
        expect((state.pstate & macosarm::kDarwinPstateCarry) == 0,
               "unix success clears carry");
        expect((state.pstate & 0x40000000U) != 0, "unix success preserves unrelated PSTATE flags");
    }

    {
        macosarm::CpuState state{};
        state.x[1] = 0xdead;
        macosarm::apply_unix_return(state, UnixReturn{
            UnixReturnDisposition::error, 0, 0, 9});
        expect(state.x[0] == 9, "unix error returns errno in x0");
        expect(state.x[1] == 0, "unix error clears x1");
        expect((state.pstate & macosarm::kDarwinPstateCarry) != 0,
               "unix error sets carry for cerror");
    }

    {
        macosarm::CpuState state{};
        state.pc = 0x1004;
        state.x[0] = 0xaaaa;
        macosarm::apply_unix_return(state, UnixReturn{UnixReturnDisposition::restart});
        expect(state.pc == 0x1000, "ERESTART rewinds PC by one A64 instruction");
        expect(state.x[0] == 0xaaaa, "ERESTART leaves result registers unchanged");
    }

    {
        macosarm::CpuState state{};
        state.pc = 0x2000;
        state.x[0] = 7;
        state.pstate = macosarm::kDarwinPstateCarry;
        macosarm::apply_unix_return(state, UnixReturn{UnixReturnDisposition::just_return});
        expect(state.pc == 0x2000 && state.x[0] == 7,
               "EJUSTRETURN leaves saved user state untouched");
        expect((state.pstate & macosarm::kDarwinPstateCarry) != 0,
               "EJUSTRETURN preserves PSTATE");
    }

    {
        macosarm::CpuState state{};
        state.x[0] = 99;
        state.x[1] = 88;
        state.pstate = macosarm::kDarwinPstateCarry;
        macosarm::apply_mach_return(state, 5);
        expect(state.x[0] == 5, "Mach return writes kern_return_t to x0");
        expect(state.x[1] == 88, "Mach return does not apply BSD x1 convention");
        expect((state.pstate & macosarm::kDarwinPstateCarry) != 0,
               "Mach return does not apply BSD carry convention");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "all Darwin syscall ABI tests passed\n";
    return EXIT_SUCCESS;
}
