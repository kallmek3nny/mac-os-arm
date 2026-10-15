#include "macosarm/native_host.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
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
#ifdef EINTR
    expect(macosarm::translate_write_errno(EINTR) == macosarm::kDarwinErrnoEintr,
           "EINTR maps to Darwin EINTR");
#endif
#ifdef EBADF
    expect(macosarm::translate_write_errno(EBADF) == macosarm::kDarwinErrnoEbadf,
           "EBADF maps to Darwin EBADF");
#endif
#ifdef EACCES
    expect(macosarm::translate_write_errno(EACCES) == macosarm::kDarwinErrnoEacces,
           "EACCES maps to Darwin EACCES");
#endif
#ifdef EINVAL
    expect(macosarm::translate_write_errno(EINVAL) == macosarm::kDarwinErrnoEinval,
           "EINVAL maps to Darwin EINVAL");
#endif
#ifdef ENOSPC
    expect(macosarm::translate_write_errno(ENOSPC) == macosarm::kDarwinErrnoEnospc,
           "ENOSPC maps to Darwin ENOSPC");
#endif
#ifdef EPIPE
    expect(macosarm::translate_write_errno(EPIPE) == macosarm::kDarwinErrnoEpipe,
           "EPIPE maps to Darwin EPIPE");
#endif
    expect(macosarm::translate_write_errno(0x7fffffff) == macosarm::kDarwinErrnoEio,
           "unknown host errno degrades to Darwin EIO");

    macosarm::NativeHostServices host;
    const std::array<std::byte, 1> byte{std::byte{0x41}};
    const auto invalid = host.write(-1, byte);
    expect(!static_cast<bool>(invalid), "native write reports invalid fd failure");
    expect(invalid.bytes_written == 0, "invalid fd writes no bytes");
    expect(invalid.error == macosarm::kDarwinErrnoEbadf,
           "invalid native fd becomes Darwin EBADF");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "native host service tests passed\n";
    return EXIT_SUCCESS;
}
