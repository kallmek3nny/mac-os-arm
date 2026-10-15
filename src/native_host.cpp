#include "macosarm/native_host.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace macosarm {

std::uint32_t translate_write_errno(int host_errno) noexcept {
#ifdef EINTR
    if (host_errno == EINTR) return kDarwinErrnoEintr;
#endif
#ifdef EIO
    if (host_errno == EIO) return kDarwinErrnoEio;
#endif
#ifdef EBADF
    if (host_errno == EBADF) return kDarwinErrnoEbadf;
#endif
#ifdef EACCES
    if (host_errno == EACCES) return kDarwinErrnoEacces;
#endif
#ifdef EFAULT
    if (host_errno == EFAULT) return kDarwinErrnoEfault;
#endif
#ifdef EINVAL
    if (host_errno == EINVAL) return kDarwinErrnoEinval;
#endif
#ifdef EFBIG
    if (host_errno == EFBIG) return kDarwinErrnoEfbig;
#endif
#ifdef ENOSPC
    if (host_errno == ENOSPC) return kDarwinErrnoEnospc;
#endif
#ifdef EPIPE
    if (host_errno == EPIPE) return kDarwinErrnoEpipe;
#endif
    return kDarwinErrnoEio;
}

HostWriteResult NativeHostServices::write(
    std::int32_t fd,
    std::span<const std::byte> bytes) {
#ifdef _WIN32
    const std::size_t capped = std::min<std::size_t>(
        bytes.size(),
        static_cast<std::size_t>(std::numeric_limits<unsigned int>::max()));
    const int written = ::_write(
        fd,
        bytes.data(),
        static_cast<unsigned int>(capped));
    if (written < 0) {
        return {0, translate_write_errno(errno)};
    }
    return {static_cast<std::uint64_t>(written), 0};
#else
    const ssize_t written = ::write(fd, bytes.data(), bytes.size());
    if (written < 0) {
        return {0, translate_write_errno(errno)};
    }
    return {static_cast<std::uint64_t>(written), 0};
#endif
}

} // namespace macosarm
