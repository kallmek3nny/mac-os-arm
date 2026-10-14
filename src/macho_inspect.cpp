#include "macosarm/macho.hpp"

#include <cstddef>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

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
    return 0;
}
