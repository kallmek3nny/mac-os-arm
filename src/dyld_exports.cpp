#include "macosarm/dyld_exports.hpp"

#include <algorithm>
#include <limits>
#include <unordered_set>
#include <utility>

namespace macosarm::dyld {
namespace {

[[nodiscard]] unsigned byte_value(std::byte value) noexcept {
    return static_cast<unsigned>(std::to_integer<unsigned char>(value));
}

[[nodiscard]] bool read_uleb(
    std::span<const std::byte> bytes,
    std::size_t& cursor,
    std::uint64_t& value) noexcept {

    value = 0;
    unsigned shift = 0;
    for (unsigned index = 0; index < 10; ++index) {
        if (cursor >= bytes.size()) {
            return false;
        }
        const unsigned byte = byte_value(bytes[cursor++]);
        const std::uint64_t payload = static_cast<std::uint64_t>(byte & 0x7fU);
        if (shift == 63 && payload > 1) {
            return false;
        }
        value |= payload << shift;
        if ((byte & 0x80U) == 0) {
            return true;
        }
        shift += 7;
    }
    return false;
}

class TrieParser {
public:
    explicit TrieParser(std::span<const std::byte> bytes)
        : bytes_(bytes), active_(bytes.size(), false) {}

    [[nodiscard]] ExportTrieResult run() {
        if (bytes_.empty()) {
            return result_;
        }
        (void)parse_node(0, {}, 0);
        return std::move(result_);
    }

private:
    struct ActiveGuard {
        std::vector<bool>& active;
        std::size_t offset;
        ~ActiveGuard() { active[offset] = false; }
    };

    [[nodiscard]] bool fail(ExportTrieError error, std::size_t offset) {
        if (result_.error == ExportTrieError::none) {
            result_.error = error;
            result_.error_offset = offset;
        }
        return false;
    }

    [[nodiscard]] bool parse_terminal(
        std::string_view symbol_name,
        std::span<const std::byte> payload,
        std::size_t payload_file_offset) {

        if (symbol_name.empty()) {
            return fail(ExportTrieError::malformed_terminal, payload_file_offset);
        }

        std::size_t cursor = 0;
        std::uint64_t flags = 0;
        if (!read_uleb(payload, cursor, flags)) {
            return fail(ExportTrieError::malformed_uleb, payload_file_offset + cursor);
        }
        if ((flags & ~kExportKnownFlagsMask) != 0) {
            return fail(ExportTrieError::unknown_flags, payload_file_offset);
        }

        const std::uint64_t kind_bits = flags & kExportKindMask;
        if (kind_bits != kExportKindRegular &&
            kind_bits != kExportKindThreadLocal &&
            kind_bits != kExportKindAbsolute) {
            return fail(ExportTrieError::unsupported_kind, payload_file_offset);
        }

        const bool reexport = (flags & kExportReexport) != 0;
        const bool stub_resolver = (flags & kExportStubAndResolver) != 0;
        const bool function_variant = (flags & kExportFunctionVariant) != 0;
        if ((static_cast<unsigned>(reexport) + static_cast<unsigned>(stub_resolver) +
             static_cast<unsigned>(function_variant)) > 1U) {
            return fail(ExportTrieError::incompatible_flags, payload_file_offset);
        }
        if ((reexport || stub_resolver || function_variant) && kind_bits != kExportKindRegular) {
            return fail(ExportTrieError::incompatible_flags, payload_file_offset);
        }

        std::uint64_t value = 0;
        if (!read_uleb(payload, cursor, value)) {
            return fail(ExportTrieError::malformed_uleb, payload_file_offset + cursor);
        }

        ExportSymbol symbol;
        symbol.name = std::string(symbol_name);
        symbol.flags = flags;
        symbol.value = value;
        symbol.weak_definition = (flags & kExportWeakDefinition) != 0;

        if (reexport) {
            symbol.kind = ExportKind::reexport;
            const std::size_t name_start = cursor;
            while (cursor < payload.size() && payload[cursor] != std::byte{0}) {
                ++cursor;
            }
            if (cursor >= payload.size()) {
                return fail(ExportTrieError::malformed_terminal, payload_file_offset + name_start);
            }
            if (cursor == name_start) {
                symbol.import_name = symbol.name;
            } else {
                symbol.import_name.reserve(cursor - name_start);
                for (std::size_t index = name_start; index < cursor; ++index) {
                    symbol.import_name.push_back(
                        static_cast<char>(byte_value(payload[index])));
                }
            }
            ++cursor;
        } else if (function_variant) {
            symbol.kind = ExportKind::function_variant;
            if (!read_uleb(payload, cursor, symbol.other)) {
                return fail(ExportTrieError::malformed_uleb, payload_file_offset + cursor);
            }
        } else if (stub_resolver) {
            symbol.kind = ExportKind::stub_and_resolver;
            if (!read_uleb(payload, cursor, symbol.other)) {
                return fail(ExportTrieError::malformed_uleb, payload_file_offset + cursor);
            }
        } else if (kind_bits == kExportKindThreadLocal) {
            symbol.kind = ExportKind::thread_local;
        } else if (kind_bits == kExportKindAbsolute) {
            symbol.kind = ExportKind::absolute;
        } else {
            symbol.kind = ExportKind::regular;
        }

        if (cursor != payload.size()) {
            return fail(ExportTrieError::malformed_terminal, payload_file_offset + cursor);
        }
        if (!names_.insert(symbol.name).second) {
            return fail(ExportTrieError::duplicate_symbol, payload_file_offset);
        }
        result_.symbols.push_back(std::move(symbol));
        return true;
    }

    [[nodiscard]] bool parse_node(
        std::size_t node_offset,
        std::string_view prefix,
        std::size_t depth) {

        if (depth > kMaxExportTrieDepth) {
            return fail(ExportTrieError::too_deep, node_offset);
        }
        if (node_offset >= bytes_.size()) {
            return fail(ExportTrieError::child_offset_out_of_bounds, node_offset);
        }
        if (active_[node_offset]) {
            return fail(ExportTrieError::cycle, node_offset);
        }
        active_[node_offset] = true;
        ActiveGuard guard{active_, node_offset};

        std::size_t cursor = node_offset;
        const std::size_t terminal_size_offset = cursor;
        std::uint64_t terminal_size = 0;
        if (!read_uleb(bytes_, cursor, terminal_size)) {
            return fail(ExportTrieError::malformed_uleb, terminal_size_offset);
        }
        if (terminal_size > static_cast<std::uint64_t>(bytes_.size() - cursor)) {
            return fail(ExportTrieError::terminal_out_of_bounds, terminal_size_offset);
        }

        const std::size_t terminal_start = cursor;
        const std::size_t terminal_end =
            terminal_start + static_cast<std::size_t>(terminal_size);
        if (terminal_size != 0) {
            if (!parse_terminal(
                    prefix,
                    bytes_.subspan(terminal_start, static_cast<std::size_t>(terminal_size)),
                    terminal_start)) {
                return false;
            }
        }

        cursor = terminal_end;
        if (cursor >= bytes_.size()) {
            return fail(ExportTrieError::missing_children_count, cursor);
        }
        const unsigned child_count = byte_value(bytes_[cursor++]);

        for (unsigned child_index = 0; child_index < child_count; ++child_index) {
            const std::size_t edge_start = cursor;
            while (cursor < bytes_.size() && bytes_[cursor] != std::byte{0}) {
                ++cursor;
            }
            if (cursor >= bytes_.size()) {
                return fail(ExportTrieError::child_name_unterminated, edge_start);
            }
            if (cursor == edge_start) {
                return fail(ExportTrieError::empty_child_name, edge_start);
            }

            std::string child_name(prefix);
            const std::size_t edge_length = cursor - edge_start;
            if (child_name.size() > kMaxExportNameLength -
                    std::min(kMaxExportNameLength, edge_length)) {
                return fail(ExportTrieError::symbol_name_too_long, edge_start);
            }
            if (child_name.size() + edge_length > kMaxExportNameLength) {
                return fail(ExportTrieError::symbol_name_too_long, edge_start);
            }
            child_name.reserve(child_name.size() + edge_length);
            for (std::size_t index = edge_start; index < cursor; ++index) {
                child_name.push_back(static_cast<char>(byte_value(bytes_[index])));
            }
            ++cursor;

            const std::size_t offset_start = cursor;
            std::uint64_t child_offset = 0;
            if (!read_uleb(bytes_, cursor, child_offset)) {
                return fail(ExportTrieError::malformed_uleb, offset_start);
            }
            if (child_offset == 0) {
                return fail(ExportTrieError::child_offset_zero, offset_start);
            }
            if (child_offset >= bytes_.size()) {
                return fail(ExportTrieError::child_offset_out_of_bounds, offset_start);
            }
            if (!parse_node(
                    static_cast<std::size_t>(child_offset),
                    child_name,
                    depth + 1)) {
                return false;
            }
        }

        return true;
    }

    std::span<const std::byte> bytes_;
    std::vector<bool> active_;
    std::unordered_set<std::string> names_;
    ExportTrieResult result_;
};

} // namespace

ExportTrieResult parse_exports_trie(std::span<const std::byte> trie_bytes) {
    return TrieParser(trie_bytes).run();
}

ExportTrieResult parse_image_exports(
    const macho::Image& image,
    std::span<const std::byte> file_bytes) {

    if (!image.exports_trie.present || image.exports_trie.size == 0) {
        return {};
    }
    const std::size_t offset = image.exports_trie.offset;
    const std::size_t size = image.exports_trie.size;
    if (offset > file_bytes.size() || size > file_bytes.size() - offset) {
        ExportTrieResult result;
        result.error = ExportTrieError::range_out_of_bounds;
        result.error_offset = offset;
        return result;
    }
    return parse_exports_trie(file_bytes.subspan(offset, size));
}

std::string_view export_kind_name(ExportKind kind) noexcept {
    switch (kind) {
    case ExportKind::regular: return "regular";
    case ExportKind::thread_local: return "thread_local";
    case ExportKind::absolute: return "absolute";
    case ExportKind::reexport: return "reexport";
    case ExportKind::stub_and_resolver: return "stub_and_resolver";
    case ExportKind::function_variant: return "function_variant";
    }
    return "unknown";
}

std::string_view export_trie_error_name(ExportTrieError error) noexcept {
    switch (error) {
    case ExportTrieError::none: return "none";
    case ExportTrieError::range_out_of_bounds: return "range_out_of_bounds";
    case ExportTrieError::malformed_uleb: return "malformed_uleb";
    case ExportTrieError::terminal_out_of_bounds: return "terminal_out_of_bounds";
    case ExportTrieError::missing_children_count: return "missing_children_count";
    case ExportTrieError::child_name_unterminated: return "child_name_unterminated";
    case ExportTrieError::empty_child_name: return "empty_child_name";
    case ExportTrieError::child_offset_zero: return "child_offset_zero";
    case ExportTrieError::child_offset_out_of_bounds: return "child_offset_out_of_bounds";
    case ExportTrieError::cycle: return "cycle";
    case ExportTrieError::too_deep: return "too_deep";
    case ExportTrieError::symbol_name_too_long: return "symbol_name_too_long";
    case ExportTrieError::unknown_flags: return "unknown_flags";
    case ExportTrieError::unsupported_kind: return "unsupported_kind";
    case ExportTrieError::incompatible_flags: return "incompatible_flags";
    case ExportTrieError::malformed_terminal: return "malformed_terminal";
    case ExportTrieError::duplicate_symbol: return "duplicate_symbol";
    }
    return "unknown";
}

} // namespace macosarm::dyld
