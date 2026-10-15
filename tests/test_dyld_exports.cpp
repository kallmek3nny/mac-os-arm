#include "macosarm/dyld_exports.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

void push_byte(std::vector<std::byte>& out, unsigned value) {
    out.push_back(static_cast<std::byte>(value & 0xffU));
}

void push_uleb(std::vector<std::byte>& out, std::uint64_t value) {
    do {
        unsigned byte = static_cast<unsigned>(value & 0x7fU);
        value >>= 7;
        if (value != 0) {
            byte |= 0x80U;
        }
        push_byte(out, byte);
    } while (value != 0);
}

std::size_t uleb_size(std::uint64_t value) {
    std::size_t size = 0;
    do {
        ++size;
        value >>= 7;
    } while (value != 0);
    return size;
}

struct Leaf {
    std::string name;
    std::vector<std::byte> payload;
};

std::vector<std::byte> terminal_payload(
    std::uint64_t flags,
    std::uint64_t value,
    std::uint64_t other = 0,
    bool include_other = false,
    std::string reexport_name = {},
    bool include_reexport_name = false) {

    std::vector<std::byte> payload;
    push_uleb(payload, flags);
    push_uleb(payload, value);
    if (include_other) {
        push_uleb(payload, other);
    }
    if (include_reexport_name) {
        for (char ch : reexport_name) {
            push_byte(payload, static_cast<unsigned char>(ch));
        }
        push_byte(payload, 0);
    }
    return payload;
}

std::vector<std::byte> flat_trie(const std::vector<Leaf>& leaves) {
    std::size_t root_size = 2;
    std::vector<std::size_t> leaf_sizes;
    leaf_sizes.reserve(leaves.size());
    for (const Leaf& leaf : leaves) {
        const std::size_t leaf_size = uleb_size(leaf.payload.size()) + leaf.payload.size() + 1;
        leaf_sizes.push_back(leaf_size);
        root_size += leaf.name.size() + 1 + 1;
    }

    for (;;) {
        std::size_t cursor = root_size;
        std::size_t recomputed = 2;
        for (std::size_t index = 0; index < leaves.size(); ++index) {
            recomputed += leaves[index].name.size() + 1 + uleb_size(cursor);
            cursor += leaf_sizes[index];
        }
        if (recomputed == root_size) {
            break;
        }
        root_size = recomputed;
    }

    std::vector<std::byte> trie;
    push_byte(trie, 0);
    push_byte(trie, static_cast<unsigned>(leaves.size()));

    std::size_t leaf_offset = root_size;
    for (std::size_t index = 0; index < leaves.size(); ++index) {
        for (char ch : leaves[index].name) {
            push_byte(trie, static_cast<unsigned char>(ch));
        }
        push_byte(trie, 0);
        push_uleb(trie, leaf_offset);
        leaf_offset += leaf_sizes[index];
    }

    for (const Leaf& leaf : leaves) {
        push_uleb(trie, leaf.payload.size());
        trie.insert(trie.end(), leaf.payload.begin(), leaf.payload.end());
        push_byte(trie, 0);
    }
    return trie;
}

const macosarm::dyld::ExportSymbol* find_symbol(
    const macosarm::dyld::ExportTrieResult& result,
    const std::string& name) {
    for (const auto& symbol : result.symbols) {
        if (symbol.name == name) {
            return &symbol;
        }
    }
    return nullptr;
}

} // namespace

int main() {
    using macosarm::dyld::ExportKind;
    using macosarm::dyld::ExportTrieError;

    {
        const std::vector<Leaf> leaves{
            {"_reg", terminal_payload(macosarm::dyld::kExportKindRegular, 0x123)},
            {"_weak", terminal_payload(
                macosarm::dyld::kExportKindRegular | macosarm::dyld::kExportWeakDefinition,
                0x44)},
            {"_tls", terminal_payload(macosarm::dyld::kExportKindThreadLocal, 0x88)},
            {"_abs", terminal_payload(macosarm::dyld::kExportKindAbsolute, 0xfeed)},
            {"_re", terminal_payload(
                macosarm::dyld::kExportReexport | macosarm::dyld::kExportWeakDefinition,
                2,
                0,
                false,
                "_target",
                true)},
            {"_stub", terminal_payload(
                macosarm::dyld::kExportStubAndResolver,
                0x200,
                0x300,
                true)},
            {"_fv", terminal_payload(
                macosarm::dyld::kExportFunctionVariant,
                0x400,
                7,
                true)},
        };
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie(leaves));
        expect(static_cast<bool>(result), "valid mixed exports trie parses");
        expect(result.symbols.size() == leaves.size(), "all export terminals decoded");

        const auto* regular = find_symbol(result, "_reg");
        expect(regular != nullptr && regular->kind == ExportKind::regular && regular->value == 0x123,
               "regular export decoded");
        const auto* weak = find_symbol(result, "_weak");
        expect(weak != nullptr && weak->weak_definition && weak->value == 0x44,
               "weak definition flag decoded");
        const auto* tls = find_symbol(result, "_tls");
        expect(tls != nullptr && tls->kind == ExportKind::thread_local && tls->value == 0x88,
               "thread-local export decoded");
        const auto* absolute = find_symbol(result, "_abs");
        expect(absolute != nullptr && absolute->kind == ExportKind::absolute && absolute->value == 0xfeed,
               "absolute export decoded");
        const auto* reexport = find_symbol(result, "_re");
        expect(reexport != nullptr && reexport->kind == ExportKind::reexport && reexport->value == 2 &&
                   reexport->import_name == "_target" && reexport->weak_definition,
               "reexport ordinal, rename, and weak flag decoded");
        const auto* stub = find_symbol(result, "_stub");
        expect(stub != nullptr && stub->kind == ExportKind::stub_and_resolver &&
                   stub->value == 0x200 && stub->other == 0x300,
               "stub/resolver offsets decoded");
        const auto* variant = find_symbol(result, "_fv");
        expect(variant != nullptr && variant->kind == ExportKind::function_variant &&
                   variant->value == 0x400 && variant->other == 7,
               "function-variant default and table index decoded");
    }

    {
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({
            {"_same", terminal_payload(
                macosarm::dyld::kExportReexport,
                1,
                0,
                false,
                "",
                true)},
        }));
        expect(static_cast<bool>(result), "same-name reexport parses");
        expect(result.symbols.size() == 1 && result.symbols[0].import_name == "_same",
               "empty reexport import name means original symbol name");
    }

    {
        macosarm::macho::Image image;
        std::vector<std::byte> file(64, std::byte{0});
        const auto trie = flat_trie({
            {"_file", terminal_payload(macosarm::dyld::kExportKindRegular, 9)},
        });
        image.exports_trie = macosarm::macho::FileRange{16, static_cast<std::uint32_t>(trie.size()), true};
        std::copy(trie.begin(), trie.end(), file.begin() + 16);
        const auto result = macosarm::dyld::parse_image_exports(image, file);
        expect(static_cast<bool>(result) && result.symbols.size() == 1 && result.symbols[0].value == 9,
               "Mach-O exports range dispatches into trie parser");
    }

    {
        macosarm::macho::Image image;
        const std::vector<std::byte> file(8, std::byte{0});
        expect(static_cast<bool>(macosarm::dyld::parse_image_exports(image, file)),
               "absent exports trie is valid and empty");
        image.exports_trie = macosarm::macho::FileRange{0, 0, true};
        expect(static_cast<bool>(macosarm::dyld::parse_image_exports(image, file)),
               "zero-sized exports trie is valid and empty");
        image.exports_trie = macosarm::macho::FileRange{7, 2, true};
        const auto bad = macosarm::dyld::parse_image_exports(image, file);
        expect(bad.error == ExportTrieError::range_out_of_bounds,
               "out-of-file exports range rejected");
    }

    {
        const std::vector<std::byte> empty;
        const auto result = macosarm::dyld::parse_exports_trie(empty);
        expect(static_cast<bool>(result) && result.symbols.empty(), "empty raw trie is valid");
    }

    {
        std::vector<std::byte> bytes(10, std::byte{0x80});
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::malformed_uleb, "overlong root ULEB rejected");
    }

    {
        const std::vector<std::byte> bytes{std::byte{5}, std::byte{0}, std::byte{0}};
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::terminal_out_of_bounds,
               "terminal payload past trie end rejected");
    }

    {
        const std::vector<std::byte> bytes{std::byte{0}};
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::missing_children_count,
               "node without child-count byte rejected");
    }

    {
        const std::vector<std::byte> bytes{
            std::byte{0}, std::byte{1}, std::byte{'x'}};
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::child_name_unterminated,
               "unterminated child edge rejected");
    }

    {
        const std::vector<std::byte> bytes{
            std::byte{0}, std::byte{1}, std::byte{0}, std::byte{4}, std::byte{0}};
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::empty_child_name, "empty child edge rejected");
    }

    {
        const std::vector<std::byte> bytes{
            std::byte{0}, std::byte{1}, std::byte{'x'}, std::byte{0}, std::byte{0}};
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::child_offset_zero, "zero child offset rejected");
    }

    {
        const std::vector<std::byte> bytes{
            std::byte{0}, std::byte{1}, std::byte{'x'}, std::byte{0}, std::byte{0x7f}};
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::child_offset_out_of_bounds,
               "out-of-range child offset rejected");
    }

    {
        const std::vector<std::byte> bytes{
            std::byte{0}, std::byte{1}, std::byte{'a'}, std::byte{0}, std::byte{5},
            std::byte{0}, std::byte{1}, std::byte{'b'}, std::byte{0}, std::byte{5}};
        const auto result = macosarm::dyld::parse_exports_trie(bytes);
        expect(result.error == ExportTrieError::cycle, "active-path cycle rejected");
    }

    {
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({
            {"_badflags", terminal_payload(0x40, 0)},
        }));
        expect(result.error == ExportTrieError::unknown_flags, "unknown export flag bit rejected");
    }

    {
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({
            {"_badkind", terminal_payload(0x03, 0)},
        }));
        expect(result.error == ExportTrieError::unsupported_kind, "reserved export kind rejected");
    }

    {
        auto payload = terminal_payload(
            macosarm::dyld::kExportReexport | macosarm::dyld::kExportStubAndResolver,
            1,
            2,
            true,
            "_x",
            true);
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({{"_mix", payload}}));
        expect(result.error == ExportTrieError::incompatible_flags,
               "reexport plus resolver flags rejected");
    }

    {
        auto payload = terminal_payload(macosarm::dyld::kExportKindRegular, 1);
        payload.push_back(std::byte{0xaa});
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({{"_garbage", payload}}));
        expect(result.error == ExportTrieError::malformed_terminal,
               "trailing regular-terminal bytes rejected");
    }

    {
        std::vector<std::byte> payload;
        push_uleb(payload, macosarm::dyld::kExportReexport);
        push_uleb(payload, 1);
        push_byte(payload, 'x');
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({{"_rename", payload}}));
        expect(result.error == ExportTrieError::malformed_terminal,
               "unterminated reexport rename rejected");
    }

    {
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({
            {"_dup", terminal_payload(0, 1)},
            {"_dup", terminal_payload(0, 2)},
        }));
        expect(result.error == ExportTrieError::duplicate_symbol,
               "duplicate terminal symbol name rejected");
    }

    {
        std::string long_name(macosarm::dyld::kMaxExportNameLength + 1, 'a');
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({
            {long_name, terminal_payload(0, 1)},
        }));
        expect(result.error == ExportTrieError::symbol_name_too_long,
               "oversized cumulative export name rejected");
    }

    {
        std::vector<std::byte> payload;
        push_uleb(payload, 0);
        for (int index = 0; index < 10; ++index) {
            push_byte(payload, 0x80);
        }
        const auto result = macosarm::dyld::parse_exports_trie(flat_trie({{"_uleb", payload}}));
        expect(result.error == ExportTrieError::malformed_uleb,
               "malformed terminal value ULEB rejected");
    }

    expect(macosarm::dyld::export_kind_name(ExportKind::stub_and_resolver) == "stub_and_resolver",
           "export kinds have stable names");
    expect(macosarm::dyld::export_trie_error_name(ExportTrieError::cycle) == "cycle",
           "export trie errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "dyld exports trie tests passed\n";
    return EXIT_SUCCESS;
}
