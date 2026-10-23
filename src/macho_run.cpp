#include "macosarm/dynarmic_backend.hpp"
#include "macosarm/session.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

// getentropy(2) is served only from the host operating system's CSPRNG.
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#include <unistd.h>
#endif

namespace {

// XNU bsd/sys/errno.h values reported to the guest, never host errno values.
constexpr std::uint32_t kGuestErrnoEio = 5;
constexpr std::uint32_t kGuestErrnoEbadf = 9;

// The guest's stdin, stdout and stderr reach the host's, as raw bytes. No
// other descriptor exists in the translated process yet, so those report EBADF.
class ConsoleHost final : public macosarm::DarwinHostServices {
public:
    // Like a canonical-mode terminal read, return after a newline, a full
    // buffer or end-of-file rather than blocking until the buffer fills.
    // A zero-length request only validates the descriptor and consumes nothing.
    macosarm::HostReadResult read(
        std::int32_t fd,
        std::span<std::byte> bytes) override {
        if (fd != 0) {
            return {0, kGuestErrnoEbadf};
        }
        std::size_t received = 0;
        while (received < bytes.size()) {
            const int value = std::fgetc(stdin);
            if (value == EOF) {
                break;
            }
            bytes[received++] = static_cast<std::byte>(static_cast<unsigned char>(value));
            if (value == '\n') {
                break;
            }
        }
        const bool failed = received == 0 && !bytes.empty() && std::ferror(stdin) != 0;
        // Keep end-of-file non-sticky, like a terminal after an EOF keystroke.
        std::clearerr(stdin);
        if (failed) {
            return {0, kGuestErrnoEio};
        }
        return {received, 0};
    }

    macosarm::HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override {
        std::FILE* const stream = fd == 1 ? stdout : fd == 2 ? stderr : nullptr;
        if (stream == nullptr) {
            return {0, kGuestErrnoEbadf};
        }
        const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), stream);
        std::fflush(stream);
        if (written == 0 && !bytes.empty()) {
            return {0, kGuestErrnoEio};
        }
        return {written, 0};
    }

    // getentropy(2) bytes come only from the host operating system's CSPRNG,
    // drawn in bounded chunks. Any host failure reports EIO; the dispatcher
    // then discards the staging buffer rather than copying partial output.
    macosarm::HostEntropyResult fill_entropy(std::span<std::byte> bytes) override {
        constexpr std::size_t kEntropyChunk = 256;
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            const std::size_t remaining = bytes.size() - offset;
            const std::size_t count = remaining < kEntropyChunk ? remaining : kEntropyChunk;
#if defined(_WIN32)
            const NTSTATUS status = ::BCryptGenRandom(
                nullptr,
                reinterpret_cast<PUCHAR>(bytes.data() + offset),
                static_cast<ULONG>(count),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!BCRYPT_SUCCESS(status)) {
                return {kGuestErrnoEio};
            }
#else
            if (::getentropy(bytes.data() + offset, count) != 0) {
                return {kGuestErrnoEio};
            }
#endif
            offset += count;
        }
        return {0};
    }
};

int usage() {
    std::cerr << "usage: macho-run [--budget <instructions>] <arm64-mach-o> [guest-args...]\n";
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    std::uint64_t budget = macosarm::SessionConfig{}.instruction_budget;
    int index = 1;
    if (index < argc && std::string_view(argv[index]) == "--budget") {
        if (index + 1 >= argc) {
            return usage();
        }
        const std::string_view text(argv[index + 1]);
        const char* const last = text.data() + text.size();
        const auto parsed = std::from_chars(text.data(), last, budget);
        if (parsed.ec != std::errc{} || parsed.ptr != last || budget == 0) {
            std::cerr << "error: invalid instruction budget '" << text << "'\n";
            return 2;
        }
        index += 2;
    }
    if (index >= argc) {
        return usage();
    }

    std::ifstream input(argv[index], std::ios::binary);
    if (!input) {
        std::cerr << "error: unable to open '" << argv[index] << "'\n";
        return 2;
    }
    const std::vector<char> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::vector<std::byte> bytes;
    bytes.reserve(raw.size());
    for (const char value : raw) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }

    // The guest argv starts with the image path, like a native exec.
    const std::vector<std::string_view> arguments(argv + index, argv + argc);
    macosarm::DynarmicBackend backend;
    ConsoleHost host;
    macosarm::SessionConfig config{};
    config.instruction_budget = budget;
    config.startup.arguments = std::span<const std::string_view>(arguments);

    const auto result = macosarm::run_macho_session(bytes, backend, host, config);
    if (!result) {
        std::cerr << "macho-run: session error [" << macosarm::session_error_name(result.error) << ']';
        if (result.error == macosarm::SessionError::parse_failure) {
            std::cerr << " parse=" << macosarm::macho::error_name(result.parse_error);
        } else if (result.error == macosarm::SessionError::cpu_init_failure) {
            std::cerr << " cpu=" << macosarm::cpu_init_error_name(result.cpu_error);
        }
        std::cerr << '\n';
        return 1;
    }

    const macosarm::ProcessResult& process = result.process;
    if (process.reason == macosarm::ProcessStopReason::exited) {
        return process.exit_status;
    }
    // Any other stop means the guest did not finish; never report success.
    std::cerr << "macho-run: stop=" << macosarm::process_stop_reason_name(process.reason)
              << " instructions=" << process.instructions_executed
              << " pc=0x" << std::hex << result.final_state.pc << std::dec;
    if (process.syscall_error != macosarm::SyscallDispatchError::none) {
        std::cerr << " syscall=" << macosarm::syscall_dispatch_error_name(process.syscall_error);
    }
    std::cerr << '\n';
    return 1;
}
