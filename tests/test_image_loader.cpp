#include "macosarm/image_loader.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

struct Fixture {
    macosarm::macho::Image image;
    std::vector<std::byte> file;
};

Fixture valid_fixture() {
    Fixture fixture;
    fixture.file.assign(0x5000, std::byte{0});
    fixture.file[0x200] = std::byte{0x20};
    fixture.file[0x201] = std::byte{0x00};
    fixture.file[0x202] = std::byte{0x80};
    fixture.file[0x203] = std::byte{0xd2};
    fixture.file[0x4000] = std::byte{0xaa};
    fixture.file[0x4001] = std::byte{0xbb};

    fixture.image.cpu_type = macosarm::macho::kCpuTypeArm64;
    fixture.image.cpu_subtype = macosarm::macho::kCpuSubtypeArm64All;
    fixture.image.file_type = macosarm::macho::kMhExecute;
    fixture.image.has_entry_point = true;
    fixture.image.entry_file_offset = 0x200;
    fixture.image.segments = {
        macosarm::macho::Segment{"__PAGEZERO", 0, 0x100000000ULL, 0, 0, 0, 0},
        macosarm::macho::Segment{"__TEXT", 0x100000000ULL, 0x4000, 0, 0x4000, 5, 5},
        macosarm::macho::Segment{"__DATA", 0x100004000ULL, 0x4000, 0x4000, 2, 3, 3},
    };
    return fixture;
}

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::LoadError;
    using macosarm::Protection;
    using macosarm::VmError;

    {
        auto fixture = valid_fixture();
        GuestAddressSpace vm;
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(static_cast<bool>(result), "valid executable loads");
        expect(result.image.preferred_load_address == 0x100000000ULL, "preferred load address computed");
        expect(result.image.entry_address == 0x100000200ULL, "entry address computed from LC_MAIN");
        expect(result.image.mapped_segments == 3, "all non-empty segments mapped");
        expect(vm.mappings().size() == 3, "address space contains three mappings");
        expect(vm.resident_page_count() == 2, "PAGEZERO stays sparse while file-backed pages materialize");

        std::array<std::byte, 4> code{};
        expect(static_cast<bool>(vm.read(0x100000200ULL, code)), "entry bytes readable");
        expect(code[0] == std::byte{0x20} && code[1] == std::byte{0x00} &&
               code[2] == std::byte{0x80} && code[3] == std::byte{0xd2},
               "entry bytes match file image");

        std::array<std::byte, 4> data{};
        expect(static_cast<bool>(vm.read(0x100004000ULL, data)), "data segment readable");
        expect(data[0] == std::byte{0xaa} && data[1] == std::byte{0xbb} &&
               data[2] == std::byte{0} && data[3] == std::byte{0},
               "file bytes copied and BSS tail zero-filled");

        const std::array<std::byte, 1> patch{std::byte{0xcc}};
        expect(vm.write(0x100000200ULL, patch).error == VmError::protection,
               "loaded __TEXT remains non-writable");
        expect(static_cast<bool>(vm.write(0x100004010ULL, patch)),
               "loaded __DATA remains writable");
    }

    {
        auto fixture = valid_fixture();
        fixture.image.has_entry_point = false;
        GuestAddressSpace vm;
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(result.error == LoadError::missing_entry_point, "missing LC_MAIN rejected");
        expect(vm.mappings().empty(), "missing entry failure is atomic");
    }

    {
        auto fixture = valid_fixture();
        fixture.image.segments.erase(fixture.image.segments.begin() + 1);
        GuestAddressSpace vm;
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(result.error == LoadError::missing_text_segment, "missing __TEXT rejected");
        expect(vm.mappings().empty(), "missing text failure is atomic");
    }

    {
        auto fixture = valid_fixture();
        fixture.image.segments[1].file_size = 0x8000;
        GuestAddressSpace vm;
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(result.error == LoadError::malformed_segment, "filesize larger than vmsize rejected");
        expect(vm.mappings().empty(), "oversized file segment leaves no mappings");
    }

    {
        auto fixture = valid_fixture();
        fixture.image.segments[2].file_offset = 0x5000;
        fixture.image.segments[2].file_size = 2;
        GuestAddressSpace vm;
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(result.error == LoadError::malformed_segment, "file range past EOF rejected");
        expect(vm.mappings().empty(), "OOB file range leaves no mappings");
    }

    {
        auto fixture = valid_fixture();
        fixture.image.segments[2].vm_address += 1;
        GuestAddressSpace vm;
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(result.error == LoadError::unaligned_segment, "unaligned guest segment rejected");
        expect(vm.mappings().empty(), "unaligned failure leaves no mappings");
    }

    {
        auto fixture = valid_fixture();
        fixture.image.entry_file_offset = 0x4000;
        GuestAddressSpace vm;
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(result.error == LoadError::bad_entry_point, "entry into non-executable data rejected");
        expect(vm.mappings().empty(), "bad entry failure leaves no mappings");
    }

    {
        auto fixture = valid_fixture();
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(0x100000000ULL, 0x4000, Protection::read)),
               "preexisting host mapping installed");
        const auto result = macosarm::load_executable(fixture.image, fixture.file, vm);
        expect(result.error == LoadError::vm_failure, "preexisting overlap reported as VM failure");
        expect(result.vm_error == VmError::overlap, "overlap VM error preserved");
        const auto maps = vm.mappings();
        expect(maps.size() == 1 && maps[0].base == 0x100000000ULL,
               "rollback preserves preexisting mapping and removes PAGEZERO");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "all image-loader tests passed\n";
    return EXIT_SUCCESS;
}
