#include "macosarm/session.hpp"

#include <array>

namespace {

constexpr std::uint64_t kSessionRootBase = 0x100000000ULL;
constexpr std::uint64_t kSessionRootEntry = kSessionRootBase + 0x200ULL;
constexpr std::uint64_t kSessionDependencyBase = 0x790000000ULL;
constexpr std::uint64_t kSessionInitializer = kSessionDependencyBase + 0x180ULL;
constexpr std::string_view kSessionExecutable =
    "/Applications/Session.app/Contents/MacOS/Session";
constexpr std::string_view kSessionDependency = "/usr/lib/libSystem.B.dylib";

std::vector<std::byte> session_graph_root(std::string_view dependency_path) {
    std::vector<std::byte> commands;
    append_segment(commands, kSessionRootBase);
    append_dylib_command(commands, macosarm::macho::kLcLoadDylib, dependency_path);

    constexpr std::size_t kMainCommandSize = 24U;
    const std::size_t main_command = commands.size();
    commands.resize(main_command + kMainCommandSize, std::byte{0});
    put_u32(commands, main_command, macosarm::macho::kLcMain);
    put_u32(commands, main_command + 4U, static_cast<std::uint32_t>(kMainCommandSize));
    put_u64(commands, main_command + 8U, 0x200ULL);

    if (32U + commands.size() > 0x200U) {
        std::abort();
    }

    std::vector<std::byte> file(0x4000, std::byte{0});
    put_u32(file, 0, macosarm::macho::kMhMagic64);
    put_u32(file, 4, static_cast<std::uint32_t>(macosarm::macho::kCpuTypeArm64));
    put_u32(file, 8, static_cast<std::uint32_t>(macosarm::macho::kCpuSubtypeArm64All));
    put_u32(file, 12, macosarm::macho::kMhExecute);
    put_u32(file, 16, 3U);
    put_u32(file, 20, static_cast<std::uint32_t>(commands.size()));
    put_u32(file, 24, 0x00200000U);
    put_u32(file, 28, 0U);
    std::copy(commands.begin(), commands.end(), file.begin() + 32);
    put_u32(file, 0x200U, 0xd4001001U);
    return file;
}

std::vector<std::byte> session_graph_dependency() {
    auto file = graph_init_add_routines(
        make_dylib(kSessionDependency, kSessionDependencyBase),
        kSessionInitializer,
        0x44ULL);
    put_u32(file, 0x180U, 0xd503201fU);
    return file;
}

struct SessionGraphHost final : macosarm::DarwinHostServices {
    macosarm::HostWriteResult write(
        std::int32_t,
        std::span<const std::byte>) override {
        return {0, 5};
    }
};

class SessionGraphBackend final : public macosarm::ExecutionBackend {
public:
    explicit SessionGraphBackend(std::uint64_t marker_address)
        : marker_address_(marker_address) {}

    [[nodiscard]] macosarm::ExecutionResult run(
        macosarm::CpuState& state,
        macosarm::GuestAddressSpace& address_space,
        std::uint64_t instruction_budget) override {
        ++calls;

        if (initializer_phase_ == 0 && state.pc == kSessionInitializer) {
            if (instruction_budget != 1) {
                return backend_error();
            }
            const std::array<std::byte, 1> marker{std::byte{0x5a}};
            initializer_marker_write =
                static_cast<bool>(address_space.write(marker_address_, marker));
            state.x[16] = static_cast<std::uint64_t>(macosarm::kMachTrapReplyPort);
            state.pc += 4;
            initializer_phase_ = 1;
            return supervisor_call();
        }

        if (initializer_phase_ == 1) {
            if (instruction_budget != 1) {
                return backend_error();
            }
            initializer_reply_port = state.x[0];
            state.pc = state.x[30];
            initializer_phase_ = 2;
            return {
                macosarm::StopReason::instruction_budget,
                1,
                0,
                macosarm::VmError::none,
            };
        }

        if (main_phase_ == 0 && state.pc == kSessionRootEntry) {
            ++main_calls;
            observed_main_pc = state.pc;
            observed_main_sp = state.sp;
            main_initial_x0 = state.x[0];
            std::array<std::byte, 1> marker{};
            main_saw_initializer_marker =
                static_cast<bool>(address_space.read(marker_address_, marker)) &&
                marker[0] == std::byte{0x5a};
            state.x[16] = static_cast<std::uint64_t>(macosarm::kMachTrapReplyPort);
            state.pc += 4;
            main_phase_ = 1;
            return supervisor_call();
        }

        if (main_phase_ == 1) {
            ++main_calls;
            process_reply_port = state.x[0];
            state.x[0] = 41;
            state.x[16] = macosarm::kDarwinSysExit;
            state.pc += 4;
            main_phase_ = 2;
            return supervisor_call();
        }

        return backend_error();
    }

    std::size_t calls{};
    std::size_t main_calls{};
    std::uint64_t initializer_reply_port{};
    std::uint64_t process_reply_port{};
    std::uint64_t observed_main_pc{};
    std::uint64_t observed_main_sp{};
    std::uint64_t main_initial_x0{};
    bool initializer_marker_write{};
    bool main_saw_initializer_marker{};

private:
    [[nodiscard]] static macosarm::ExecutionResult supervisor_call() {
        return {
            macosarm::StopReason::supervisor_call,
            1,
            macosarm::kDarwinSvcImmediate,
            macosarm::VmError::none,
        };
    }

    [[nodiscard]] static macosarm::ExecutionResult backend_error() {
        return {
            macosarm::StopReason::backend_error,
            0,
            0,
            macosarm::VmError::none,
        };
    }

    std::uint64_t marker_address_{};
    std::size_t initializer_phase_{};
    std::size_t main_phase_{};
};

} // namespace

int session_graph_bootstrap_main() {
    using macosarm::MachContext;
    using macosarm::SessionError;
    using macosarm::dyld::DependencyGraphError;
    using macosarm::dyld::ImageGraphBootstrapError;

    const auto root = session_graph_root(kSessionDependency);
    const auto dependency_file = session_graph_dependency();

    {
        constexpr std::uint64_t stack_base = 0x7a0000000ULL;
        MemoryLookup store;
        store.files.emplace(std::string(kSessionDependency), dependency_file);
        const auto lookup = store.callback();
        SessionGraphHost host;
        SessionGraphBackend backend(stack_base + 0x100ULL);
        MachContext mach_context;
        macosarm::SessionConfig config;
        config.stack_base = stack_base;
        config.stack_size = 0x4000ULL;
        config.instruction_budget = 8;
        config.mach_context = &mach_context;
        config.dyld.emplace();
        config.dyld->root_path = kSessionExecutable;
        config.dyld->executable_path = kSessionExecutable;
        config.dyld->image_lookup = lookup;
        config.dyld->bootstrap.execution.instructions_per_initializer = 8;
        config.dyld->bootstrap.execution.total_instruction_budget = 8;

        const auto result = macosarm::run_macho_session(root, backend, host, config);
        expect(static_cast<bool>(result),
               "session high-level path completes dependency bootstrap before main");
        expect(static_cast<bool>(result.bootstrap) &&
                   result.bootstrap.loading.graph.images.size() == 2,
               "session high-level path loads libSystem-style dependency graph");
        expect(result.bootstrap.initialization.planning.plan.calls.size() == 1 &&
                   result.bootstrap.initialization.planning.plan.calls.front().address ==
                       kSessionInitializer,
               "session high-level path plans dependency initializer");
        expect(backend.initializer_marker_write && backend.main_saw_initializer_marker,
               "dependency initializer durable guest-memory state is visible to main");
        expect(backend.observed_main_pc == kSessionRootEntry &&
                   backend.observed_main_sp == result.startup.layout.stack_pointer &&
                   backend.main_initial_x0 == 0,
               "session restores executable CPU entry state after initializer execution");
        expect(backend.initializer_reply_port == MachContext::kFirstReplyPort &&
                   backend.process_reply_port == MachContext::kFirstReplyPort + 1U,
               "initializer and process share one caller-owned Mach namespace");
        expect(result.process.reason == macosarm::ProcessStopReason::exited &&
                   result.process.exit_status == 41 &&
                   backend.main_calls == 2,
               "main executes only after successful graph bootstrap");
    }

    {
        constexpr std::uint64_t stack_base = 0x7b0000000ULL;
        MemoryLookup empty_store;
        const auto lookup = empty_store.callback();
        SessionGraphHost host;
        SessionGraphBackend backend(stack_base + 0x100ULL);
        macosarm::SessionConfig config;
        config.stack_base = stack_base;
        config.stack_size = 0x4000ULL;
        config.dyld.emplace();
        config.dyld->root_path = kSessionExecutable;
        config.dyld->executable_path = kSessionExecutable;
        config.dyld->image_lookup = lookup;

        const auto result = macosarm::run_macho_session(root, backend, host, config);
        expect(result.error == SessionError::bootstrap_failure &&
                   result.bootstrap.error == ImageGraphBootstrapError::dependency_graph_failure &&
                   result.bootstrap.loading.error == DependencyGraphError::dependency_not_found,
               "session propagates dependency bootstrap failure before process execution");
        expect(backend.calls == 0 && backend.main_calls == 0,
               "bootstrap failure prevents main from executing");
    }

    {
        SessionGraphHost host;
        SessionGraphBackend backend(0x7c0000100ULL);
        macosarm::SessionConfig config;
        config.stack_base = 0x7c0000000ULL;
        config.stack_size = 0x4000ULL;
        config.dyld.emplace();
        config.dyld->root_path = kSessionExecutable;
        config.dyld->executable_path = kSessionExecutable;

        const auto result = macosarm::run_macho_session(root, backend, host, config);
        expect(result.error == SessionError::bootstrap_config_failure,
               "session rejects requested dyld bootstrap without an image lookup");
        expect(backend.calls == 0,
               "invalid bootstrap configuration fails closed before guest execution");
    }

    expect(macosarm::session_error_name(SessionError::bootstrap_failure) ==
               "bootstrap_failure" &&
               macosarm::session_error_name(SessionError::bootstrap_config_failure) ==
                   "bootstrap_config_failure",
           "session dyld bootstrap errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " session graph bootstrap test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "session graph bootstrap tests passed\n";
    return EXIT_SUCCESS;
}
