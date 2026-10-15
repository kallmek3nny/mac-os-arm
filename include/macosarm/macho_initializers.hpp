#pragma once

#include "macosarm/macho.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace macosarm::macho {

constexpr std::uint32_t kLcRoutines64 = 0x1aU;
constexpr std::uint32_t kSectionTypeMask = 0x000000ffU;
constexpr std::uint32_t kSModInitFuncPointers = 0x9U;

struct InitializerPointerSection {
    std::string segment_name;
    std::string section_name;
    std::uint64_t address{};
    std::uint64_t size{};
    std::uint32_t file_offset{};

    [[nodiscard]] std::size_t pointer_count() const noexcept {
        return static_cast<std::size_t>(size / sizeof(std::uint64_t));
    }
};

struct RoutinesInitializer {
    std::uint64_t address{};
    std::uint64_t module{};
    bool present{};
};

struct InitializerMetadata {
    std::vector<InitializerPointerSection> pointer_sections;
    RoutinesInitializer routines;
};

enum class InitializerMetadataError {
    none,
    truncated,
    invalid_image,
    malformed_load_commands,
    malformed_segment,
    malformed_initializer_section,
    malformed_routines,
    duplicate_routines,
};

struct InitializerMetadataResult {
    InitializerMetadata metadata;
    InitializerMetadataError error{InitializerMetadataError::none};
    std::string message;

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == InitializerMetadataError::none;
    }
};

namespace initializer_detail {

class Reader {
public:
    explicit Reader(std::span<const std::byte> bytes) : bytes_(bytes) {}

    [[nodiscard]] bool contains(std::size_t offset, std::size_t size) const noexcept {
        return offset <= bytes_.size() && size <= bytes_.size() - offset;
    }

    [[nodiscard]] bool read_u32(std::size_t offset, std::uint32_t& out) const noexcept {
        if (!contains(offset, sizeof(std::uint32_t))) {
            return false;
        }
        out = 0;
        for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i) {
            out |= static_cast<std::uint32_t>(std::to_integer<unsigned char>(bytes_[offset + i])) << (i * 8U);
        }
        return true;
    }

    [[nodiscard]] bool read_u64(std::size_t offset, std::uint64_t& out) const noexcept {
        if (!contains(offset, sizeof(std::uint64_t))) {
            return false;
        }
        out = 0;
        for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
            out |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes_[offset + i])) << (i * 8U);
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
            const char ch = static_cast<char>(std::to_integer<unsigned char>(bytes_[offset + i]));
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

[[nodiscard]] inline InitializerMetadataResult fail(
    InitializerMetadataError error,
    std::string message) {
    InitializerMetadataResult result;
    result.error = error;
    result.message = std::move(message);
    return result;
}

[[nodiscard]] inline bool add_overflows(std::uint64_t lhs, std::uint64_t rhs) noexcept {
    return rhs > std::numeric_limits<std::uint64_t>::max() - lhs;
}

} // namespace initializer_detail

[[nodiscard]] inline InitializerMetadataResult parse_initializer_metadata(
    std::span<const std::byte> bytes) {
    using namespace initializer_detail;

    constexpr std::size_t kHeaderSize = 32;
    constexpr std::size_t kLoadCommandHeaderSize = 8;
    constexpr std::uint64_t kSegment64Size = 72;
    constexpr std::uint64_t kSection64Size = 80;
    constexpr std::size_t kRoutines64Size = 72;

    const Reader reader(bytes);
    if (!reader.contains(0, kHeaderSize)) {
        return fail(InitializerMetadataError::truncated,
                    "file is smaller than a mach_header_64");
    }

    std::uint32_t magic = 0;
    std::uint32_t command_count = 0;
    std::uint32_t commands_size = 0;
    if (!reader.read_u32(0, magic) || !reader.read_u32(16, command_count) ||
        !reader.read_u32(20, commands_size)) {
        return fail(InitializerMetadataError::truncated,
                    "unable to read mach_header_64 initializer fields");
    }
    if (magic != kMhMagic64) {
        return fail(InitializerMetadataError::invalid_image,
                    "initializer metadata requires a little-endian 64-bit Mach-O image");
    }
    if (!reader.contains(kHeaderSize, commands_size)) {
        return fail(InitializerMetadataError::malformed_load_commands,
                    "load-command region extends past end of file");
    }

    InitializerMetadataResult result;
    std::size_t cursor = kHeaderSize;
    const std::size_t commands_end = kHeaderSize + static_cast<std::size_t>(commands_size);

    for (std::uint32_t command_index = 0; command_index < command_count; ++command_index) {
        if (cursor > commands_end || commands_end - cursor < kLoadCommandHeaderSize) {
            return fail(InitializerMetadataError::malformed_load_commands,
                        "load-command header exceeds declared command region");
        }

        std::uint32_t command = 0;
        std::uint32_t command_size = 0;
        if (!reader.read_u32(cursor, command) || !reader.read_u32(cursor + 4, command_size) ||
            command_size < kLoadCommandHeaderSize || command_size > commands_end - cursor) {
            return fail(InitializerMetadataError::malformed_load_commands,
                        "invalid initializer load-command size");
        }

        if (command == kLcSegment64) {
            if (command_size < kSegment64Size) {
                return fail(InitializerMetadataError::malformed_segment,
                            "LC_SEGMENT_64 is smaller than segment_command_64");
            }

            const std::string segment_name = reader.read_fixed_string(cursor + 8, 16);
            std::uint64_t segment_address = 0;
            std::uint64_t segment_size = 0;
            std::uint64_t segment_file_offset = 0;
            std::uint64_t segment_file_size = 0;
            std::uint32_t section_count = 0;
            if (!reader.read_u64(cursor + 24, segment_address) ||
                !reader.read_u64(cursor + 32, segment_size) ||
                !reader.read_u64(cursor + 40, segment_file_offset) ||
                !reader.read_u64(cursor + 48, segment_file_size) ||
                !reader.read_u32(cursor + 64, section_count)) {
                return fail(InitializerMetadataError::malformed_segment,
                            "truncated LC_SEGMENT_64 while parsing initializers");
            }

            const std::uint64_t section_bytes =
                static_cast<std::uint64_t>(section_count) * kSection64Size;
            if (section_bytes > std::numeric_limits<std::uint64_t>::max() - kSegment64Size ||
                kSegment64Size + section_bytes > command_size) {
                return fail(InitializerMetadataError::malformed_segment,
                            "LC_SEGMENT_64 section table exceeds command size");
            }
            if (add_overflows(segment_address, segment_size) ||
                add_overflows(segment_file_offset, segment_file_size) ||
                segment_file_offset + segment_file_size > bytes.size()) {
                return fail(InitializerMetadataError::malformed_segment,
                            "initializer segment range overflows image bounds");
            }

            const std::uint64_t segment_end = segment_address + segment_size;
            const std::uint64_t segment_file_end = segment_file_offset + segment_file_size;
            for (std::uint32_t section_index = 0; section_index < section_count; ++section_index) {
                const std::size_t section_cursor =
                    cursor + static_cast<std::size_t>(kSegment64Size +
                        static_cast<std::uint64_t>(section_index) * kSection64Size);

                std::uint64_t section_address = 0;
                std::uint64_t section_size = 0;
                std::uint32_t section_file_offset = 0;
                std::uint32_t section_flags = 0;
                if (!reader.read_u64(section_cursor + 32, section_address) ||
                    !reader.read_u64(section_cursor + 40, section_size) ||
                    !reader.read_u32(section_cursor + 48, section_file_offset) ||
                    !reader.read_u32(section_cursor + 64, section_flags)) {
                    return fail(InitializerMetadataError::malformed_segment,
                                "truncated section_64 while parsing initializers");
                }

                if ((section_flags & kSectionTypeMask) != kSModInitFuncPointers) {
                    continue;
                }

                if ((section_size % sizeof(std::uint64_t)) != 0) {
                    return fail(InitializerMetadataError::malformed_initializer_section,
                                "S_MOD_INIT_FUNC_POINTERS size is not pointer aligned");
                }
                if (add_overflows(section_address, section_size) ||
                    section_address < segment_address || section_address + section_size > segment_end) {
                    return fail(InitializerMetadataError::malformed_initializer_section,
                                "S_MOD_INIT_FUNC_POINTERS VM range escapes its segment");
                }

                if (section_size != 0) {
                    const std::uint64_t section_file_begin = section_file_offset;
                    if (add_overflows(section_file_begin, section_size) ||
                        section_file_begin < segment_file_offset ||
                        section_file_begin + section_size > segment_file_end ||
                        section_file_begin + section_size > bytes.size()) {
                        return fail(InitializerMetadataError::malformed_initializer_section,
                                    "S_MOD_INIT_FUNC_POINTERS file range escapes its segment");
                    }
                }

                InitializerPointerSection section;
                section.segment_name = reader.read_fixed_string(section_cursor + 16, 16);
                if (section.segment_name.empty()) {
                    section.segment_name = segment_name;
                }
                section.section_name = reader.read_fixed_string(section_cursor, 16);
                section.address = section_address;
                section.size = section_size;
                section.file_offset = section_file_offset;
                result.metadata.pointer_sections.push_back(std::move(section));
            }
        } else if (command == kLcRoutines64) {
            if (command_size < kRoutines64Size) {
                return fail(InitializerMetadataError::malformed_routines,
                            "LC_ROUTINES_64 is smaller than routines_command_64");
            }
            if (result.metadata.routines.present) {
                return fail(InitializerMetadataError::duplicate_routines,
                            "multiple LC_ROUTINES_64 commands are not supported");
            }
            if (!reader.read_u64(cursor + 8, result.metadata.routines.address) ||
                !reader.read_u64(cursor + 16, result.metadata.routines.module)) {
                return fail(InitializerMetadataError::malformed_routines,
                            "truncated LC_ROUTINES_64 command");
            }
            result.metadata.routines.present = true;
        }

        cursor += command_size;
    }

    if (cursor != commands_end) {
        return fail(InitializerMetadataError::malformed_load_commands,
                    "load-command count does not consume declared command region");
    }

    return result;
}

[[nodiscard]] inline std::string_view initializer_metadata_error_name(
    InitializerMetadataError error) noexcept {
    switch (error) {
    case InitializerMetadataError::none: return "none";
    case InitializerMetadataError::truncated: return "truncated";
    case InitializerMetadataError::invalid_image: return "invalid_image";
    case InitializerMetadataError::malformed_load_commands: return "malformed_load_commands";
    case InitializerMetadataError::malformed_segment: return "malformed_segment";
    case InitializerMetadataError::malformed_initializer_section: return "malformed_initializer_section";
    case InitializerMetadataError::malformed_routines: return "malformed_routines";
    case InitializerMetadataError::duplicate_routines: return "duplicate_routines";
    }
    return "unknown";
}

} // namespace macosarm::macho
