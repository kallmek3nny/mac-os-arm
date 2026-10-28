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

    [[nodiscard]] bool read_cstring(std::size_t offset, std::size_t end, std::string& out) const {
        if (offset >= end || end > bytes_.size()) {
            return false;
        }
        out.clear();
        for (std::size_t cursor = offset; cursor < end; ++cursor) {
            const auto ch = static_cast<char>(std::to_integer<unsigned char>(bytes_[cursor]));
            if (ch == '\0') {
                return !out.empty();
            }
            out.push_back(ch);
        }
        out.clear();
        return false;
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

[[nodiscard]] bool command_string(
    const Reader& reader,
    std::size_t cursor,
    std::uint32_t command_size,
    std::uint32_t string_offset,
    std::uint32_t minimum_offset,
    std::string& out) {
    if (string_offset < minimum_offset || string_offset >= command_size) {
        return false;
    }
    const std::size_t start = cursor + static_cast<std::size_t>(string_offset);
    const std::size_t end = cursor + static_cast<std::size_t>(command_size);
    return reader.read_cstring(start, end, out);
}

[[nodiscard]] bool linkedit_range_valid(
    std::size_t image_size,
    std::uint32_t offset,
    std::uint32_t size) noexcept {
    const std::uint64_t end = static_cast<std::uint64_t>(offset) + static_cast<std::uint64_t>(size);
    return static_cast<std::uint64_t>(offset) <= image_size && end <= image_size;
}

[[nodiscard]] bool dylib_kind_for_command(std::uint32_t command, DylibLoadKind& kind) noexcept {
    switch (command) {
    case kLcLoadDylib:
        kind = DylibLoadKind::normal;
        return true;
    case kLcLoadWeakDylib:
        kind = DylibLoadKind::weak;
        return true;
    case kLcReexportDylib:
        kind = DylibLoadKind::reexport;
        return true;
    case kLcLazyLoadDylib:
        kind = DylibLoadKind::lazy;
        return true;
    case kLcLoadUpwardDylib:
        kind = DylibLoadKind::upward;
        return true;
    default:
        return false;
    }
}

[[nodiscard]] bool supported_file_type(std::uint32_t file_type) noexcept {
    return file_type == kMhExecute || file_type == kMhDylib || file_type == kMhDylinker;
}

} // namespace

ParseResult parse(std::span<const std::byte> bytes) {
    constexpr std::size_t kHeaderSize = 32;
    constexpr std::size_t kLoadCommandHeaderSize = 8;
    constexpr std::size_t kSegment64Size = 72;
    constexpr std::size_t kEntryPointSize = 24;
    constexpr std::size_t kDylinkerCommandSize = 12;
    constexpr std::size_t kDylibCommandSize = 24;
    constexpr std::size_t kRpathCommandSize = 12;
    constexpr std::size_t kLinkeditDataCommandSize = 16;

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
    if (!supported_file_type(file_type)) {
        return fail(ErrorCode::unsupported_file_type, "unsupported Mach-O file type");
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
            const std::uint64_t required_size =
                kSegment64Size + static_cast<std::uint64_t>(section_count) * kSection64Size;
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
        } else if (command == kLcIdDylib) {
            if (result.image.file_type != kMhDylib) {
                return fail(ErrorCode::malformed_dylib_identity, "LC_ID_DYLIB is only valid in MH_DYLIB images");
            }
            if (command_size < kDylibCommandSize) {
                return fail(ErrorCode::malformed_dylib_identity, "LC_ID_DYLIB is too small");
            }
            if (result.image.has_dylib_identity) {
                return fail(ErrorCode::duplicate_dylib_identity, "multiple LC_ID_DYLIB commands are not supported");
            }

            std::uint32_t path_offset = 0;
            DylibIdentity identity;
            if (!reader.read_u32(cursor + 8, path_offset) ||
                !reader.read_u32(cursor + 12, identity.timestamp) ||
                !reader.read_u32(cursor + 16, identity.current_version) ||
                !reader.read_u32(cursor + 20, identity.compatibility_version) ||
                !command_string(reader, cursor, command_size, path_offset,
                                static_cast<std::uint32_t>(kDylibCommandSize), identity.install_name)) {
                return fail(ErrorCode::malformed_dylib_identity, "invalid LC_ID_DYLIB command");
            }
            result.image.dylib_identity = std::move(identity);
            result.image.has_dylib_identity = true;
        } else if (command == kLcLoadDylinker) {
            if (command_size < kDylinkerCommandSize) {
                return fail(ErrorCode::malformed_dynamic_linker, "LC_LOAD_DYLINKER is too small");
            }
            if (result.image.has_dynamic_linker) {
                return fail(ErrorCode::duplicate_dynamic_linker, "multiple LC_LOAD_DYLINKER commands are not supported");
            }
            std::uint32_t path_offset = 0;
            if (!reader.read_u32(cursor + 8, path_offset) ||
                !command_string(reader, cursor, command_size, path_offset,
                                static_cast<std::uint32_t>(kDylinkerCommandSize),
                                result.image.dynamic_linker)) {
                return fail(ErrorCode::malformed_dynamic_linker, "invalid LC_LOAD_DYLINKER path");
            }
            result.image.has_dynamic_linker = true;
        } else if (command == kLcRpath) {
            if (command_size < kRpathCommandSize) {
                return fail(ErrorCode::malformed_runpath, "LC_RPATH is too small");
            }
            std::uint32_t path_offset = 0;
            std::string path;
            if (!reader.read_u32(cursor + 8, path_offset) ||
                !command_string(reader, cursor, command_size, path_offset,
                                static_cast<std::uint32_t>(kRpathCommandSize), path)) {
                return fail(ErrorCode::malformed_runpath, "invalid LC_RPATH path");
            }
            result.image.runpaths.push_back(std::move(path));
        } else if (command == kLcSymtab) {
            constexpr std::size_t kSymtabCommandSize = 24;
            constexpr std::uint64_t kNlist64Size = 16;
            if (command_size < kSymtabCommandSize) {
                return fail(ErrorCode::malformed_symbol_table, "LC_SYMTAB is too small");
            }
            if (result.image.symbol_table.present) {
                return fail(ErrorCode::duplicate_load_command, "multiple LC_SYMTAB commands are not supported");
            }
            SymbolTable& table = result.image.symbol_table;
            if (!reader.read_u32(cursor + 8, table.symbol_offset) ||
                !reader.read_u32(cursor + 12, table.symbol_count) ||
                !reader.read_u32(cursor + 16, table.string_offset) ||
                !reader.read_u32(cursor + 20, table.string_size)) {
                return fail(ErrorCode::malformed_symbol_table, "truncated LC_SYMTAB");
            }
            const std::uint64_t symbols_end = static_cast<std::uint64_t>(table.symbol_offset) +
                                              static_cast<std::uint64_t>(table.symbol_count) * kNlist64Size;
            if (symbols_end > bytes.size() ||
                !linkedit_range_valid(bytes.size(), table.string_offset, table.string_size)) {
                return fail(ErrorCode::malformed_symbol_table, "LC_SYMTAB range exceeds image size");
            }
            table.present = true;
        } else if (command == kLcDysymtab) {
            constexpr std::size_t kDysymtabCommandSize = 80;
            constexpr std::uint64_t kIndirectSymbolSize = 4;
            if (command_size < kDysymtabCommandSize) {
                return fail(ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB is too small");
            }
            if (result.image.dynamic_symbol_table.present) {
                return fail(ErrorCode::duplicate_load_command, "multiple LC_DYSYMTAB commands are not supported");
            }
            DynamicSymbolTable& table = result.image.dynamic_symbol_table;
            if (!reader.read_u32(cursor + 8, table.local_symbol_index) ||
                !reader.read_u32(cursor + 12, table.local_symbol_count) ||
                !reader.read_u32(cursor + 16, table.external_symbol_index) ||
                !reader.read_u32(cursor + 20, table.external_symbol_count) ||
                !reader.read_u32(cursor + 24, table.undefined_symbol_index) ||
                !reader.read_u32(cursor + 28, table.undefined_symbol_count) ||
                !reader.read_u32(cursor + 56, table.indirect_symbol_offset) ||
                !reader.read_u32(cursor + 60, table.indirect_symbol_count)) {
                return fail(ErrorCode::malformed_dynamic_symbol_table, "truncated LC_DYSYMTAB");
            }
            // Each LC_DYSYMTAB file table is an (offset, count) pair of fixed-size entries, summed in 64 bits so
            // counts near UINT32_MAX cannot wrap back inside the image.
            struct DysymtabTable {
                std::size_t field;
                std::uint64_t entry_size;
                const char* message;
            };
            constexpr DysymtabTable kDysymtabTables[] = {
                {32, 8, "LC_DYSYMTAB table of contents exceeds image size"},
                {40, 56, "LC_DYSYMTAB module table exceeds image size"},
                {48, 4, "LC_DYSYMTAB external reference table exceeds image size"},
                {56, kIndirectSymbolSize, "LC_DYSYMTAB indirect symbol table exceeds image size"},
                {64, 8, "LC_DYSYMTAB external relocation table exceeds image size"},
                {72, 8, "LC_DYSYMTAB local relocation table exceeds image size"},
            };
            for (const auto& file_table : kDysymtabTables) {
                std::uint32_t table_offset = 0;
                std::uint32_t entry_count = 0;
                if (!reader.read_u32(cursor + file_table.field, table_offset) ||
                    !reader.read_u32(cursor + file_table.field + 4, entry_count)) {
                    return fail(ErrorCode::malformed_dynamic_symbol_table, "truncated LC_DYSYMTAB");
                }
                const std::uint64_t table_end = static_cast<std::uint64_t>(table_offset) +
                                                static_cast<std::uint64_t>(entry_count) * file_table.entry_size;
                if (table_end > bytes.size()) {
                    return fail(ErrorCode::malformed_dynamic_symbol_table, file_table.message);
                }
            }
            table.present = true;
        } else if (command == kLcUuid) {
            constexpr std::size_t kUuidCommandSize = 24;
            if (command_size < kUuidCommandSize) {
                return fail(ErrorCode::malformed_uuid, "LC_UUID is too small");
            }
            if (result.image.has_uuid) {
                return fail(ErrorCode::duplicate_load_command, "multiple LC_UUID commands are not supported");
            }
            std::uint64_t low = 0;
            std::uint64_t high = 0;
            if (!reader.read_u64(cursor + 8, low) || !reader.read_u64(cursor + 16, high)) {
                return fail(ErrorCode::malformed_uuid, "truncated LC_UUID");
            }
            for (std::size_t i = 0; i < 8; ++i) {
                result.image.uuid[i] = static_cast<std::uint8_t>((low >> (i * 8)) & 0xffU);
                result.image.uuid[i + 8] = static_cast<std::uint8_t>((high >> (i * 8)) & 0xffU);
            }
            result.image.has_uuid = true;
        } else if (command == kLcBuildVersion) {
            constexpr std::uint64_t kBuildVersionCommandSize = 24;
            constexpr std::uint64_t kBuildToolVersionSize = 8;
            if (command_size < kBuildVersionCommandSize) {
                return fail(ErrorCode::malformed_build_version, "LC_BUILD_VERSION is too small");
            }
            BuildVersion build;
            std::uint32_t tool_count = 0;
            if (!reader.read_u32(cursor + 8, build.platform) ||
                !reader.read_u32(cursor + 12, build.minimum_os) ||
                !reader.read_u32(cursor + 16, build.sdk) ||
                !reader.read_u32(cursor + 20, tool_count)) {
                return fail(ErrorCode::malformed_build_version, "truncated LC_BUILD_VERSION");
            }
            if (kBuildVersionCommandSize + static_cast<std::uint64_t>(tool_count) * kBuildToolVersionSize > command_size) {
                return fail(ErrorCode::malformed_build_version, "LC_BUILD_VERSION tool table exceeds command size");
            }
            for (const auto& existing : result.image.build_versions) {
                if (existing.platform == build.platform) {
                    return fail(ErrorCode::duplicate_load_command, "multiple LC_BUILD_VERSION commands name one platform");
                }
            }
            build.tools.reserve(tool_count);
            for (std::uint32_t tool = 0; tool < tool_count; ++tool) {
                const std::size_t entry = cursor + static_cast<std::size_t>(kBuildVersionCommandSize) +
                                          static_cast<std::size_t>(tool) * static_cast<std::size_t>(kBuildToolVersionSize);
                BuildTool tool_version;
                if (!reader.read_u32(entry, tool_version.tool) || !reader.read_u32(entry + 4, tool_version.version)) {
                    return fail(ErrorCode::malformed_build_version, "truncated LC_BUILD_VERSION tool entry");
                }
                build.tools.push_back(tool_version);
            }
            result.image.build_versions.push_back(std::move(build));
        } else if (command == kLcSourceVersion) {
            constexpr std::size_t kSourceVersionCommandSize = 16;
            if (command_size < kSourceVersionCommandSize) {
                return fail(ErrorCode::malformed_source_version, "LC_SOURCE_VERSION is too small");
            }
            if (result.image.has_source_version) {
                return fail(ErrorCode::duplicate_load_command, "multiple LC_SOURCE_VERSION commands are not supported");
            }
            if (!reader.read_u64(cursor + 8, result.image.source_version)) {
                return fail(ErrorCode::malformed_source_version, "truncated LC_SOURCE_VERSION");
            }
            result.image.has_source_version = true;
        } else if (command == kLcDyldExportsTrie || command == kLcDyldChainedFixups || command == kLcCodeSignature ||
                   command == kLcFunctionStarts || command == kLcDataInCode) {
            if (command_size < kLinkeditDataCommandSize) {
                return fail(ErrorCode::malformed_linkedit_data, "dyld linkedit command is too small");
            }
            std::uint32_t data_offset = 0;
            std::uint32_t data_size = 0;
            if (!reader.read_u32(cursor + 8, data_offset) ||
                !reader.read_u32(cursor + 12, data_size) ||
                !linkedit_range_valid(bytes.size(), data_offset, data_size)) {
                return fail(ErrorCode::malformed_linkedit_data, "dyld linkedit range exceeds image size");
            }

            FileRange* destination = nullptr;
            ErrorCode duplicate_error = ErrorCode::duplicate_load_command;
            if (command == kLcDyldExportsTrie) {
                destination = &result.image.exports_trie;
                duplicate_error = ErrorCode::duplicate_exports_trie;
            } else if (command == kLcDyldChainedFixups) {
                destination = &result.image.chained_fixups;
                duplicate_error = ErrorCode::duplicate_chained_fixups;
            } else if (command == kLcCodeSignature) {
                destination = &result.image.code_signature;
            } else if (command == kLcFunctionStarts) {
                destination = &result.image.function_starts;
            } else {
                destination = &result.image.data_in_code;
            }
            if (destination->present) {
                return fail(duplicate_error, "duplicate dyld linkedit command");
            }
            destination->offset = data_offset;
            destination->size = data_size;
            destination->present = true;
        } else {
            DylibLoadKind kind = DylibLoadKind::normal;
            if (dylib_kind_for_command(command, kind)) {
                if (command_size < kDylibCommandSize) {
                    return fail(ErrorCode::malformed_dylib, "dylib load command is too small");
                }

                std::uint32_t path_offset = 0;
                DylibDependency dependency;
                dependency.kind = kind;
                if (!reader.read_u32(cursor + 8, path_offset) ||
                    !reader.read_u32(cursor + 12, dependency.timestamp) ||
                    !reader.read_u32(cursor + 16, dependency.current_version) ||
                    !reader.read_u32(cursor + 20, dependency.compatibility_version) ||
                    !command_string(reader, cursor, command_size, path_offset,
                                    static_cast<std::uint32_t>(kDylibCommandSize), dependency.path)) {
                    return fail(ErrorCode::malformed_dylib, "invalid dylib load command");
                }
                result.image.dependencies.push_back(std::move(dependency));
            }
        }

        cursor += command_size;
    }

    if (cursor != commands_end) {
        return fail(ErrorCode::malformed_load_commands, "load-command count does not consume declared command region");
    }
    // LC_DYSYMTAB only partitions the LC_SYMTAB nlist array, so it needs that
    // table, and its local, external and undefined ranges must stay inside the
    // declared symbol count.
    if (result.image.dynamic_symbol_table.present) {
        if (!result.image.symbol_table.present) {
            return fail(ErrorCode::malformed_dynamic_symbol_table, "LC_DYSYMTAB requires LC_SYMTAB");
        }
        const DynamicSymbolTable& dynamic = result.image.dynamic_symbol_table;
        const std::uint64_t symbol_count = result.image.symbol_table.symbol_count;
        const auto partition_fits = [symbol_count](std::uint32_t index, std::uint32_t count) {
            return static_cast<std::uint64_t>(index) + static_cast<std::uint64_t>(count) <= symbol_count;
        };
        if (!partition_fits(dynamic.local_symbol_index, dynamic.local_symbol_count) ||
            !partition_fits(dynamic.external_symbol_index, dynamic.external_symbol_count) ||
            !partition_fits(dynamic.undefined_symbol_index, dynamic.undefined_symbol_count)) {
            return fail(ErrorCode::malformed_dynamic_symbol_table,
                        "LC_DYSYMTAB symbol partition exceeds LC_SYMTAB symbol count");
        }
    }
    if (result.image.file_type == kMhDylib && !result.image.has_dylib_identity) {
        return fail(ErrorCode::missing_dylib_identity, "MH_DYLIB image is missing LC_ID_DYLIB");
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
    case ErrorCode::malformed_dynamic_linker: return "malformed_dynamic_linker";
    case ErrorCode::malformed_dylib: return "malformed_dylib";
    case ErrorCode::malformed_dylib_identity: return "malformed_dylib_identity";
    case ErrorCode::malformed_runpath: return "malformed_runpath";
    case ErrorCode::malformed_linkedit_data: return "malformed_linkedit_data";
    case ErrorCode::missing_dylib_identity: return "missing_dylib_identity";
    case ErrorCode::duplicate_entry_point: return "duplicate_entry_point";
    case ErrorCode::duplicate_dynamic_linker: return "duplicate_dynamic_linker";
    case ErrorCode::duplicate_dylib_identity: return "duplicate_dylib_identity";
    case ErrorCode::duplicate_exports_trie: return "duplicate_exports_trie";
    case ErrorCode::duplicate_chained_fixups: return "duplicate_chained_fixups";
    case ErrorCode::malformed_symbol_table: return "malformed_symbol_table";
    case ErrorCode::malformed_dynamic_symbol_table: return "malformed_dynamic_symbol_table";
    case ErrorCode::malformed_uuid: return "malformed_uuid";
    case ErrorCode::malformed_build_version: return "malformed_build_version";
    case ErrorCode::malformed_source_version: return "malformed_source_version";
    case ErrorCode::duplicate_load_command: return "duplicate_load_command";
    }
    return "unknown";
}

std::string_view dylib_load_kind_name(DylibLoadKind kind) noexcept {
    switch (kind) {
    case DylibLoadKind::normal: return "normal";
    case DylibLoadKind::weak: return "weak";
    case DylibLoadKind::reexport: return "reexport";
    case DylibLoadKind::lazy: return "lazy";
    case DylibLoadKind::upward: return "upward";
    }
    return "unknown";
}

} // namespace macosarm::macho
