#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/native_host.hpp"
#include "macosarm/session.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <csignal>
#endif

namespace {

constexpr std::uint64_t kMaxInputBytes = 512ULL * 1024ULL * 1024ULL;

void print_usage(const char* program) {
    std::cerr
        << "usage: " << program << " [--budget N] <arm64-mach-o>\n"
        << "       " << program << " --help\n";
}

bool parse_u64(std::string_view text, std::uint64_t& value) {
    if (text.empty()) {
        return false;
    }
    const char* first = text.data();
    const char* last = first + text.size();
    const auto parsed = std::from_chars(first, last, value, 10);
    return parsed.ec == std::errc{} && parsed.ptr == last;
}

bool read_file(const std::string& path, std::vector<std::byte>& bytes) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        std::cerr << "macarm-run: cannot open '" << path << "'\n";
        return false;
    }

    const std::streampos end = input.tellg();
    if (end < 0) {
        std::cerr << "macarm-run: cannot determine file size\n";
        return false;
    }

    const auto unsigned_size = static_cast<std::uint64_t>(end);
    if (unsigned_size > kMaxInputBytes) {
        std::cerr << "macarm-run: input exceeds 512 MiB safety cap\n";
        return false;
    }
    if (unsigned_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        std::cerr << "macarm-run: input does not fit host address space\n";
        return false;
    }

    bytes.assign(static_cast<std::size_t>(unsigned_size), std::byte{0});
    input.seekg(0, std::ios::beg);
    if (!bytes.empty()) {
        input.read(
            reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
        if (!input) {
            std::cerr << "macarm-run: failed while reading input\n";
            return false;
        }
    }
    return true;
}

void print_session_failure(const macosarm::SessionResult& result) {
    std::cerr << "macarm-run: session setup failed: "
              << macosarm::session_error_name(result.error);
    switch (result.error) {
    case macosarm::SessionError::parse_failure:
        std::cerr << " (" << macosarm::macho::error_name(result.parse_error) << ')';
        break;
    case macosarm::SessionError::load_failure:
        std::cerr << " (" << macosarm::load_error_name(result.load_error);
        if (result.vm_error != macosarm::VmError::none) {
            std::cerr << ", " << macosarm::vm_error_name(result.vm_error);
        }
        std::cerr << ')';
        break;
    case macosarm::SessionError::stack_failure:
        std::cerr << " (" << macosarm::vm_error_name(result.vm_error) << ')';
        break;
    case macosarm::SessionError::cpu_init_failure:
        std::cerr << " (" << macosarm::cpu_init_error_name(result.cpu_error) << ')';
        break;
    case macosarm::SessionError::none:
        break;
    }
    std::cerr << '\n';
}

int process_exit_code(const macosarm::SessionResult& result) {
    switch (result.process.reason) {
    case macosarm::ProcessStopReason::exited:
        return static_cast<int>(static_cast<std::uint32_t>(result.process.exit_status) & 0xffU);
    case macosarm::ProcessStopReason::instruction_budget:
        std::cerr << "macarm-run: instruction budget exhausted after "
                  << result.process.instructions_executed << " instructions\n";
        return 124;
    case macosarm::ProcessStopReason::memory_fault:
        std::cerr << "macarm-run: guest memory fault: "
                  << macosarm::vm_error_name(result.process.vm_error) << '\n';
        return 70;
    case macosarm::ProcessStopReason::syscall_error:
        std::cerr << "macarm-run: syscall bridge error: "
                  << macosarm::syscall_dispatch_error_name(result.process.syscall_error) << '\n';
        return 70;
    case macosarm::ProcessStopReason::exception:
    case macosarm::ProcessStopReason::backend_error:
        std::cerr << "macarm-run: guest stopped: "
                  << macosarm::process_stop_reason_name(result.process.reason) << '\n';
        return 70;
    }
    return 70;
}

} // namespace

int main(int argc, char** argv) {
#ifndef _WIN32
    (void)std::signal(SIGPIPE, SIG_IGN);
#endif

    macosarm::SessionConfig config{};
    std::string path;

    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--help" || argument == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        if (argument == "--budget") {
            if (index + 1 >= argc || !parse_u64(argv[++index], config.instruction_budget)) {
                std::cerr << "macarm-run: --budget requires an unsigned integer\n";
                return 64;
            }
            continue;
        }
        constexpr std::string_view prefix = "--budget=";
        if (argument.starts_with(prefix)) {
            if (!parse_u64(argument.substr(prefix.size()), config.instruction_budget)) {
                std::cerr << "macarm-run: invalid --budget value\n";
                return 64;
            }
            continue;
        }
        if (!argument.empty() && argument.front() == '-') {
            std::cerr << "macarm-run: unknown option '" << argument << "'\n";
            return 64;
        }
        if (!path.empty()) {
            std::cerr << "macarm-run: only one input file is supported\n";
            return 64;
        }
        path.assign(argument);
    }

    if (path.empty()) {
        print_usage(argv[0]);
        return 64;
    }

    std::vector<std::byte> file_bytes;
    if (!read_file(path, file_bytes)) {
        return 66;
    }

    macosarm::DynarmicBackend backend;
    macosarm::NativeHostServices host;
    const macosarm::SessionResult result =
        macosarm::run_macho_session(file_bytes, backend, host, config);
    if (!result) {
        print_session_failure(result);
        return 65;
    }
    return process_exit_code(result);
}
