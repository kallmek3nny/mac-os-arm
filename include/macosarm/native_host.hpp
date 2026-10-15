#pragma once

#include "macosarm/darwin_syscall.hpp"

namespace macosarm {

class NativeHostServices final : public DarwinHostServices {
public:
    [[nodiscard]] HostWriteResult write(
        std::int32_t fd,
        std::span<const std::byte> bytes) override;
};

[[nodiscard]] std::uint32_t translate_write_errno(int host_errno) noexcept;

} // namespace macosarm
