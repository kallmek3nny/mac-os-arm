#include "macosarm/macho.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

// LC_BUILD_VERSION packs X.Y.Z as xxxx.yy.zz nibbles.
void print_version(std::uint32_t version) {
    std::cout << (version >> 16) << '.' << ((version >> 8) & 0xffU) << '.' << (version & 0xffU);
}

void print_range(const char* name, const macosarm::macho::FileRange& range) {
    if (range.present) {
        std::cout << name << " file=0x" << std::hex << range.offset << "+0x" << range.size << std::dec << '\n';
    }
}

void print_load_metadata(const macosarm::macho::Image& image) {
    if (image.has_uuid) {
        std::cout << "uuid=" << std::hex << std::uppercase << std::setfill('0');
        for (std::size_t i = 0; i < image.uuid.size(); ++i) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                std::cout << '-';
            }
            std::cout << std::setw(2) << static_cast<unsigned>(image.uuid[i]);
        }
        std::cout << std::nouppercase << std::setfill(' ') << std::dec << '\n';
    }
    for (const auto& build : image.build_versions) {
        std::cout << "build platform=" << build.platform << " minos=";
        print_version(build.minimum_os);
        std::cout << " sdk=";
        print_version(build.sdk);
        std::cout << " tools=" << build.tools.size() << '\n';
    }
    if (image.has_source_version) {
        // LC_SOURCE_VERSION packs A.B.C.D.E as 24.10.10.10.10 bits.
        const std::uint64_t version = image.source_version;
        std::cout << "source_version=" << (version >> 40) << '.' << ((version >> 30) & 0x3ffU) << '.'
                  << ((version >> 20) & 0x3ffU) << '.' << ((version >> 10) & 0x3ffU) << '.' << (version & 0x3ffU)
                  << '\n';
    }
    if (image.symbol_table.present) {
        const auto& symbols = image.symbol_table;
        std::cout << "symtab symbols=" << symbols.symbol_count << " symoff=0x" << std::hex << symbols.symbol_offset
                  << " stroff=0x" << symbols.string_offset << " strsize=0x" << symbols.string_size << std::dec
                  << '\n';
    }
    if (image.dynamic_symbol_table.present) {
        const auto& dynamic = image.dynamic_symbol_table;
        std::cout << "dysymtab local=" << dynamic.local_symbol_index << '+' << dynamic.local_symbol_count
                  << " external=" << dynamic.external_symbol_index << '+' << dynamic.external_symbol_count
                  << " undefined=" << dynamic.undefined_symbol_index << '+' << dynamic.undefined_symbol_count
                  << " indirect=" << dynamic.indirect_symbol_count << '\n';
    }
    print_range("exports_trie", image.exports_trie);
    print_range("chained_fixups", image.chained_fixups);
    print_range("code_signature", image.code_signature);
    print_range("function_starts", image.function_starts);
    print_range("data_in_code", image.data_in_code);
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: macho-inspect <arm64-mach-o>\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        std::cerr << "error: unable to open '" << argv[1] << "'\n";
        return 2;
    }

    const std::vector<char> raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::vector<std::byte> bytes;
    bytes.reserve(raw.size());
    for (const char value : raw) {
        bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(value)));
    }

    const auto result = macosarm::macho::parse(bytes);
    if (!result) {
        std::cerr << "parse error [" << macosarm::macho::error_name(result.error) << "]: " << result.message << '\n';
        return 1;
    }

    std::cout << "cpu=arm64\n";
    std::cout << "subtype=" << result.image.cpu_subtype << '\n';
    std::cout << "segments=" << result.image.segments.size() << '\n';
    std::cout << "has_entry=" << (result.image.has_entry_point ? "yes" : "no") << '\n';
    if (result.image.has_entry_point) {
        std::cout << "entry_file_offset=0x" << std::hex << result.image.entry_file_offset << std::dec << '\n';
    }
    for (const auto& segment : result.image.segments) {
        std::cout << "segment " << segment.name
                  << " vm=0x" << std::hex << segment.vm_address
                  << " size=0x" << segment.vm_size
                  << " file=0x" << segment.file_offset
                  << "+0x" << segment.file_size << std::dec << '\n';
    }
    print_load_metadata(result.image);
    return 0;
}
