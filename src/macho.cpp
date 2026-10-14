#include "macosarm/macho.hpp"

#include <limits>
#include <utility>

namespace macosarm::macho {
namespace {

class Reader {
public:
    explicit Reader(std::span<const std::byte> bytes) : bytes_(bytes) {}

    [[nodiscard]] bool contains(std::size_t offset, std::size_t size) const noexcept {
        return offset <= bytes_.size() && size <= bytes_.size() - offset;
    }

    [[nodiscard]] bool read_u32(std::size_t offset, std::uint32_t& out) const noexcept {
        if (!contains(offset, 4)) {
            return false;
        }
        out = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            out |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes_[offset + i])) << (i * 8);
        }
        return true;
    }

    [[nodiscard]] bool read_i32(std::size_t offset, std::int32_t& out) const noexcept {
        std::uint32_t value = 0;
        if (!read_u32(offset, value)) {
            return false;
        }
        out = static_cast<std::int32_t>(value);
        return true;
    }

    [[nodiscard]] bool read_u64(std::size_t offset, std::uint64_t& out) const noexcept {
        if (!contains(offset, 8)) {
            return false;
        }
        out = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            out |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes_[offset + i])) << (i * 8);
        }
        return true;
    }

    [[nodiscard]] std::string read_fixed_string(std::size_t offset, std::size_t size) const {
        if (!contains(offset, size)) {
            return {};
        }
        std::string value;
        value.reserve(size);
        for (std::size_t i = 0; i < size; ++i) {
            const auto ch = static_cast<char>(std::to_integer<unsigned char>(bytes_[offset + i]));
            if (ch == '\0') {
                break;
            }
            value.push_back(ch);
        }
        return value;
    }

private:
    std::span<const std::byte> bytes_;
};

[[nodiscard]] ParseResult fail(ErrorCode code, std::string message) {
    ParseResult result;
    result.error = code;
    result.message = std::move(message);
    return result;
}

[[nodiscard]] bool add_overflows(std::uint64_t a, std::uint64_t b) noexcept {
    return b > std::numeric_limits<std::uint64_t>::max() - a;
}

} // namespace

ParseResult parse(std::span<const std::byte> bytes) {
    constexpr std::size_t kHeaderSize = 32;
    constexpr std::size_t kLoadCommandHeaderSize = 8;
    constexpr std::size_t kSegment64Size = 72;
    constexpr std::size_t kEntryPointSize = 24;

    const Reader reader(bytes);
    if (!reader.contains(0, kHeaderSize)) {
        return fail(ErrorCode::truncated, "file is smaller than a mach_header_64");
    }

    std::uint32_t magic = 0;
    std::int32_t cpu_type = 0;
    std::int32_t cpu_subtype = 0;
    std::uint32_t file_type = 0;
    std::uint32_t command_count = 0;
    std::uint32_t commands_size = 0;
    std::uint32_t flags = 0;

    if (!reader.read_u32(0, magic) || !reader.read_i32(4, cpu_type) ||
        !reader.read_i32(8, cpu_subtype) || !reader.read_u32(12, file_type) ||
        !reader.read_u32(16, command_count) || !reader.read_u32(20, commands_size) ||
        !reader.read_u32(24, flags)) {
        return fail(ErrorCode::truncated, "unable to read mach_header_64");
    }

    if (magic != kMhMagic64) {
        return fail(ErrorCode::bad_magic, "not a little-endian 64-bit Mach-O image");
    }
    if (cpu_type != kCpuTypeArm64) {
        return fail(ErrorCode::unsupported_cpu, "image is not ARM64");
    }
    if (file_type != kMhExecute) {
        return fail(ErrorCode::unsupported_file_type, "only MH_EXECUTE images are supported in phase 0");
    }
    if (!reader.contains(kHeaderSize, commands_size)) {
        return fail(ErrorCode::malformed_load_commands, "load-command region extends past end of file");
    }

    ParseResult result;
    result.image.cpu_type = cpu_type;
    result.image.cpu_subtype = cpu_subtype;
    result.image.file_type = file_type;
    result.image.flags = flags;

    std::size_t cursor = kHeaderSize;
    const std::size_t commands_end = kHeaderSize + static_cast<std::size_t>(commands_size);

    for (std::uint32_t index = 0; index < command_count; ++index) {
        if (cursor > commands_end || commands_end - cursor < kLoadCommandHeaderSize) {
            return fail(ErrorCode::malformed_load_commands, "load-command header exceeds declared command region");
        }

        std::uint32_t command = 0;
        std::uint32_t command_size = 0;
        if (!reader.read_u32(cursor, command) || !reader.read_u32(cursor + 4, command_size)) {
            return fail(ErrorCode::malformed_load_commands, "truncated load-command header");
        }
        if (command_size < kLoadCommandHeaderSize || command_size > commands_end - cursor) {
            return fail(ErrorCode::malformed_load_commands, "invalid load-command size");
        }

        if (command == kLcSegment64) {
            if (command_size < kSegment64Size) {
                return fail(ErrorCode::malformed_segment, "LC_SEGMENT_64 is smaller than segment_command_64");
            }

            Segment segment;
            segment.name = reader.read_fixed_string(cursor + 8, 16);
            std::uint32_t max_protection = 0;
            std::uint32_t initial_protection = 0;
            std::uint32_t section_count = 0;

            if (!reader.read_u64(cursor + 24, segment.vm_address) ||
                !reader.read_u64(cursor + 32, segment.vm_size) ||
                !reader.read_u64(cursor + 40, segment.file_offset) ||
                !reader.read_u64(cursor + 48, segment.file_size) ||
                !reader.read_u32(cursor + 56, max_protection) ||
                !reader.read_u32(cursor + 60, initial_protection) ||
                !reader.read_u32(cursor + 64, section_count)) {
                return fail(ErrorCode::malformed_segment, "truncated LC_SEGMENT_64");
            }
            segment.max_protection = max_protection;
            segment.initial_protection = initial_protection;

            constexpr std::uint64_t kSection64Size = 80;
            const std::uint64_t required_size = kSegment64Size + static_cast<std::uint64_t>(section_count) * kSection64Size;
            if (required_size > command_size) {
                return fail(ErrorCode::malformed_segment, "LC_SEGMENT_64 section table exceeds command size");
            }
            if (segment.file_size != 0) {
                if (add_overflows(segment.file_offset, segment.file_size) ||
                    segment.file_offset + segment.file_size > bytes.size()) {
                    return fail(ErrorCode::malformed_segment, "segment file range exceeds image size");
                }
            }
            result.image.segments.push_back(std::move(segment));
        } else if (command == kLcMain) {
            if (command_size < kEntryPointSize) {
                return fail(ErrorCode::malformed_load_commands, "LC_MAIN is smaller than entry_point_command");
            }
            if (result.image.has_entry_point) {
                return fail(ErrorCode::duplicate_entry_point, "multiple LC_MAIN commands are not supported");
            }
            if (!reader.read_u64(cursor + 8, result.image.entry_file_offset)) {
                return fail(ErrorCode::malformed_load_commands, "truncated LC_MAIN");
            }
            if (result.image.entry_file_offset >= bytes.size()) {
                return fail(ErrorCode::malformed_load_commands, "LC_MAIN entry offset exceeds image size");
            }
            result.image.has_entry_point = true;
        }

        cursor += command_size;
    }

    if (cursor != commands_end) {
        return fail(ErrorCode::malformed_load_commands, "load-command count does not consume declared command region");
    }

    return result;
}

std::string_view error_name(ErrorCode error) noexcept {
    switch (error) {
    case ErrorCode::none: return "none";
    case ErrorCode::truncated: return "truncated";
    case ErrorCode::bad_magic: return "bad_magic";
    case ErrorCode::unsupported_cpu: return "unsupported_cpu";
    case ErrorCode::unsupported_file_type: return "unsupported_file_type";
    case ErrorCode::malformed_load_commands: return "malformed_load_commands";
    case ErrorCode::malformed_segment: return "malformed_segment";
    case ErrorCode::duplicate_entry_point: return "duplicate_entry_point";
    }
    return "unknown";
}

} // namespace macosarm::macho
