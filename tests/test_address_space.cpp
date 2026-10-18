#include "macosarm/address_space.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

} // namespace

int main() {
    using macosarm::GuestAddressSpace;
    using macosarm::Protection;
    using macosarm::VmError;

    {
        GuestAddressSpace vm;
        const auto result = vm.map(0x100000000ULL, GuestAddressSpace::kPageSize,
                                   Protection::read | Protection::execute);
        expect(static_cast<bool>(result), "aligned mapping succeeds");
        expect(vm.mappings().size() == 1, "mapping recorded");
        expect(vm.resident_page_count() == 0, "mapping does not eagerly allocate pages");
    }

    {
        GuestAddressSpace vm;
        expect(vm.map(1, GuestAddressSpace::kPageSize, Protection::read).error == VmError::unaligned,
               "unaligned base rejected");
        expect(vm.map(0, GuestAddressSpace::kPageSize - 1, Protection::read).error == VmError::unaligned,
               "unaligned size rejected");
        expect(vm.map(0, 0, Protection::read).error == VmError::zero_size,
               "zero-sized mapping rejected");
    }

    {
        GuestAddressSpace vm;
        const auto near_end = std::numeric_limits<std::uint64_t>::max() - (GuestAddressSpace::kPageSize - 1);
        expect(vm.map(near_end, GuestAddressSpace::kPageSize, Protection::read).error == VmError::address_overflow,
               "wrapping address range rejected");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(0x4000, 0x8000, Protection::read)), "base mapping succeeds");
        expect(vm.map(0x8000, 0x4000, Protection::read).error == VmError::overlap,
               "overlapping mapping rejected");
        expect(static_cast<bool>(vm.map(0xc000, 0x4000, Protection::read)),
               "adjacent mapping succeeds");
    }

    {
        GuestAddressSpace vm;
        constexpr std::uint64_t pagezero_size = 0x100000000ULL;
        expect(static_cast<bool>(vm.map(0, pagezero_size, Protection::none)), "4 GiB PAGEZERO mapping succeeds");
        expect(vm.resident_page_count() == 0, "PAGEZERO remains sparse");
    }

    {
        GuestAddressSpace vm;
        const auto rx = Protection::read | Protection::execute;
        expect(static_cast<bool>(vm.map(0x100000000ULL, 0x8000, rx)), "RX mapping succeeds");

        const std::array<std::byte, 4> code{
            std::byte{0x20}, std::byte{0x00}, std::byte{0x80}, std::byte{0xd2}
        };
        expect(static_cast<bool>(vm.load_bytes(0x100004010ULL, code)), "loader can populate RX memory");
        expect(vm.resident_page_count() == 1, "loader allocates only touched page");

        std::array<std::byte, 8> readback{};
        expect(static_cast<bool>(vm.read(0x10000400cULL, readback)), "RX memory is readable");
        expect(readback[0] == std::byte{0} && readback[1] == std::byte{0} &&
               readback[2] == std::byte{0} && readback[3] == std::byte{0},
               "untouched bytes read as zero");
        expect(readback[4] == code[0] && readback[5] == code[1] &&
               readback[6] == code[2] && readback[7] == code[3],
               "loaded bytes read back exactly");
        expect(vm.write(0x100004010ULL, code).error == VmError::protection,
               "guest write into RX mapping rejected");
    }

    {
        GuestAddressSpace vm;
        const auto rw = Protection::read | Protection::write;
        expect(static_cast<bool>(vm.map(0x200000000ULL, 0x8000, rw)), "RW mapping succeeds");

        std::array<std::byte, 8> payload{
            std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
            std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}
        };
        const std::uint64_t cross_page = 0x200003ffcULL;
        expect(static_cast<bool>(vm.write(cross_page, payload)), "cross-page write succeeds");
        expect(vm.resident_page_count() == 2, "cross-page write allocates two pages");

        std::array<std::byte, 8> readback{};
        expect(static_cast<bool>(vm.read(cross_page, readback)), "cross-page read succeeds");
        expect(readback == payload, "cross-page bytes preserved");

        expect(static_cast<bool>(vm.protect(0x200000000ULL, 0x8000, Protection::read)),
               "exact mapping protection update succeeds");
        expect(vm.write(cross_page, payload).error == VmError::protection,
               "write rejected after removing write permission");

        expect(static_cast<bool>(vm.unmap(0x200000000ULL, 0x8000)), "exact unmap succeeds");
        expect(vm.resident_page_count() == 0, "unmap drops resident pages");
        expect(vm.read(cross_page, readback).error == VmError::unmapped,
               "read after unmap rejected");
    }

    {
        GuestAddressSpace vm;
        expect(static_cast<bool>(vm.map(0x300000000ULL, 0x4000, Protection::read | Protection::write)),
               "single-page mapping succeeds");
        std::array<std::byte, 8> payload{};
        expect(vm.write(0x300003ffcULL, payload).error == VmError::unmapped,
               "access crossing mapping end rejected atomically");
        expect(vm.resident_page_count() == 0, "failed crossing write allocates nothing");
    }


    {
        // BSD munmap needs split/removal of ordinary VM subranges without
        // disturbing the exact-mapping unmap contract used by the loader.
        GuestAddressSpace vm;
        constexpr std::uint64_t base = 0x500000000ULL;
        constexpr std::uint64_t page = GuestAddressSpace::kPageSize;
        const auto rw = Protection::read | Protection::write;
        expect(static_cast<bool>(vm.map(base, 4U * page, rw)),
               "partial-unmap fixture maps four pages");
        const std::array<std::byte, 1> marker{std::byte{0x5a}};
        for (std::uint64_t n = 0; n < 4U; ++n) {
            expect(static_cast<bool>(vm.write(base + n * page, marker)),
                   "partial-unmap fixture initializes each resident page");
        }
        const auto resident_before = vm.resident_page_count();
        const auto mappings_before = vm.mappings();
        expect(vm.unmap_range(base + 1U, page).error == VmError::unaligned,
               "partial-unmap rejects an unaligned start without mutation");
        expect(vm.unmap_range(base, 0).error == VmError::zero_size,
               "partial-unmap rejects zero length without mutation");
        expect(vm.unmap_range(base, page - 1U).error == VmError::unaligned,
               "partial-unmap rejects unrounded length");
        expect(vm.unmap_range(0xffffffffffffc000ULL, 2U * page).error ==
                   VmError::address_overflow,
               "partial-unmap rejects wrapping virtual ranges");
        expect(vm.resident_page_count() == resident_before &&
                   vm.mappings().size() == mappings_before.size(),
               "failed partial-unmap requests preserve mapping and page counts");

        expect(static_cast<bool>(vm.unmap_range(base + page, 2U * page)),
               "interior partial-unmap removes two pages");
        const auto split = vm.mappings();
        expect(split.size() == 2 &&
                   split[0].base == base && split[0].size == page &&
                   split[1].base == base + 3U * page && split[1].size == page &&
                   split[0].protection == rw && split[1].protection == rw,
               "interior removal retains both protected fragments");
        std::array<std::byte, 1> readback{};
        expect(vm.read(base + page, readback).error == VmError::unmapped &&
                   vm.read(base + 2U * page, readback).error == VmError::unmapped,
               "removed interior is inaccessible");
        expect(static_cast<bool>(vm.read(base, readback)) &&
                   readback == marker &&
                   static_cast<bool>(vm.read(base + 3U * page, readback)) &&
                   readback == marker &&
                   vm.resident_page_count() == 2U,
               "surviving fragments retain resident page data");
        expect(vm.unmap(base, 4U * page).error == VmError::not_exact_mapping,
               "old exact-unmap contract remains strict after splitting");
        expect(static_cast<bool>(vm.unmap_range(base + page, 2U * page)) &&
                   vm.resident_page_count() == 2U,
               "repeated unmap on an existing hole is idempotent");
        expect(static_cast<bool>(vm.map(base + page, 2U * page, rw)),
               "removed interior may be mapped again");
        expect(static_cast<bool>(vm.read(base + page, readback)) &&
                   readback[0] == std::byte{0},
               "remapped pages contain zero rather than stale resident data");
        expect(static_cast<bool>(vm.unmap_range(base, 4U * page)) &&
                   vm.mappings().empty() && vm.resident_page_count() == 0U,
               "range unmap spans split mappings and deallocates all resident pages");
    }


    {
        // Independent maximum permissions allow anonymous memory to start
        // inaccessible and later become readable/writable through mprotect.
        GuestAddressSpace vm;
        constexpr std::uint64_t base = 0x700000000ULL;
        constexpr std::uint64_t page = GuestAddressSpace::kPageSize;
        const auto rw = Protection::read | Protection::write;
        expect(static_cast<bool>(vm.map(base, 4U * page, rw)),
               "mprotect fixture maps a maximum-read-write region");
        const std::array<std::byte, 1> marker{std::byte{0x78}};
        expect(static_cast<bool>(vm.write(base, marker)) &&
                   static_cast<bool>(vm.write(base + page, marker)) &&
                   static_cast<bool>(vm.write(base + 3U * page, marker)),
               "mprotect fixture initializes guest memory");
        const auto resident_before = vm.resident_page_count();
        expect(vm.protect_range(base + 1U, page, Protection::read).error ==
                   VmError::unaligned &&
                   vm.protect_range(base, 0U, Protection::read).error == VmError::zero_size &&
                   vm.protect_range(UINT64_MAX - (page - 1U), 2U * page, rw).error ==
                       VmError::address_overflow &&
                   vm.mappings().size() == 1U &&
                   vm.resident_page_count() == resident_before,
               "invalid ranges preserve original mapping and resident pages");

        expect(static_cast<bool>(vm.protect_range(
                   base + page, 2U * page, Protection::read)),
               "mprotect splits a two-page interior region");
        const auto split = vm.mappings();
        expect(split.size() == 3U &&
                   split[0].base == base && split[0].size == page &&
                   split[0].protection == rw &&
                   split[1].base == base + page && split[1].size == 2U * page &&
                   split[1].protection == Protection::read &&
                   split[1].maximum_protection == rw &&
                   split[2].base == base + 3U * page && split[2].size == page &&
                   split[2].protection == rw,
               "middle permissions change without affecting either neighboring fragment");
        expect(vm.write(base + page, marker).error == VmError::protection &&
                   static_cast<bool>(vm.write(base, marker)) &&
                   static_cast<bool>(vm.write(base + 3U * page, marker)),
               "mprotect denies writes only in the downgraded range");
        expect(vm.protect_range(base, 3U * page, Protection::execute).error ==
                   VmError::protection &&
                   vm.mappings()[1].protection == Protection::read,
               "protection beyond original maximum fails atomically");

        expect(static_cast<bool>(vm.unmap_range(base + 2U * page, page)),
               "mprotect hole fixture removes an interior page");
        const auto before_hole = vm.mappings();
        expect(vm.protect_range(base + page, 3U * page, rw).error ==
                   VmError::unmapped &&
                   vm.mappings().size() == before_hole.size() &&
                   vm.mappings()[1].protection == Protection::read,
               "gap across a multi-entry mprotect range leaves earlier rights unchanged");
        expect(static_cast<bool>(vm.protect_range(base + page, page, rw)) &&
                   static_cast<bool>(vm.write(base + page, marker)),
               "mprotect restores rights within the saved maximum");
        GuestAddressSpace anonymous;
        expect(static_cast<bool>(anonymous.map(base, page, Protection::none, rw)),
               "anonymous mapping tracks separate current and maximum permissions");
        std::array<std::byte, 1> readback{};
        expect(anonymous.read(base, readback).error == VmError::protection,
               "PROT_NONE prevents reading");
        expect(static_cast<bool>(anonymous.protect_range(base, page, rw)) &&
                   static_cast<bool>(anonymous.write(base, marker)),
               "PROT_NONE can be promoted within the declared maximum");
        expect(anonymous.map(base + page, page, rw, Protection::read).error ==
                   VmError::protection,
               "new mappings cannot request initial protection above maximum");
    }


    {
        // An mprotect split must not break ordinary access that spans two
        // contiguous VM records. Validate every page before any copyout.
        GuestAddressSpace vm;
        constexpr std::uint64_t base = 0x800000000ULL;
        constexpr std::uint64_t page = GuestAddressSpace::kPageSize;
        constexpr std::uint64_t crossing = base + page - 3U;
        const auto rw = Protection::read | Protection::write;
        const std::array<std::byte, 6> original{
            std::byte{0x11}, std::byte{0x22}, std::byte{0x33},
            std::byte{0x44}, std::byte{0x55}, std::byte{0x66}};
        const std::array<std::byte, 6> replacement{
            std::byte{0x81}, std::byte{0x82}, std::byte{0x83},
            std::byte{0x84}, std::byte{0x85}, std::byte{0x86}};
        std::array<std::byte, 6> readback{};
        expect(static_cast<bool>(vm.map(base, 2U * page, rw)) &&
                   static_cast<bool>(vm.protect_range(
                       base + page, page, Protection::read)),
               "cross-fragment fixture creates a protected interior boundary");
        expect(static_cast<bool>(vm.load_bytes(crossing, original)) &&
                   static_cast<bool>(vm.read(crossing, readback)) &&
                   readback == original,
               "loader and reader span adjacent mapping records");
        expect(vm.probe_write(crossing, replacement.size()).error ==
                   VmError::protection &&
                   vm.write(crossing, replacement).error == VmError::protection,
               "later read-only fragment rejects the entire guest write");
        expect(static_cast<bool>(vm.read(crossing, readback)) &&
                   readback == original,
               "failed cross-fragment write preserves the earlier writable page");
        expect(static_cast<bool>(vm.protect_range(base + page, page, rw)) &&
                   static_cast<bool>(vm.probe_write(crossing, replacement.size())) &&
                   static_cast<bool>(vm.write(crossing, replacement)) &&
                   static_cast<bool>(vm.read(crossing, readback)) &&
                   readback == replacement,
               "restored rights permit atomic cross-fragment copyin and copyout");
        expect(static_cast<bool>(vm.map(base + 2U * page, page, rw)) &&
                   static_cast<bool>(vm.write(base + 2U * page - 3U, original)),
               "cross-fragment access spans separately created adjacent mappings");
        expect(static_cast<bool>(vm.unmap_range(base + page, page)) &&
                   vm.probe_write(crossing, replacement.size()).error == VmError::unmapped &&
                   vm.write(crossing, replacement).error == VmError::unmapped,
               "a true hole is still rejected even when the first page is mapped");
        std::array<std::byte, 3> surviving{};
        expect(static_cast<bool>(vm.read(base + page - 3U, surviving)) &&
                   surviving[0] == original[0] && surviving[1] == original[1] &&
                   surviving[2] == original[2],
               "failed write through a hole preserves the resident prefix");
        expect(vm.read(UINT64_MAX - 2U, readback).error == VmError::unmapped,
               "wrapping cross-fragment reads fail without overflow");

        GuestAddressSpace executable;
        const auto rx = Protection::read | Protection::execute;
        expect(static_cast<bool>(executable.map(base, 2U * page, rx)) &&
                   static_cast<bool>(executable.load_bytes(crossing, original)) &&
                   static_cast<bool>(executable.protect_range(
                       base + page, page, Protection::read)),
               "instruction-fetch fixture has adjacent pages with different rights");
        readback.fill(std::byte{0xfe});
        expect(executable.fetch_code(crossing, readback).error == VmError::protection &&
                   readback[0] == std::byte{0xfe},
               "cross-boundary fetch rejects a non-executable suffix without copying");
        expect(static_cast<bool>(executable.protect_range(base + page, page, rx)) &&
                   static_cast<bool>(executable.fetch_code(crossing, readback)) &&
                   readback == original,
               "instruction fetch spans adjacent executable mapping fragments");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "all guest address-space tests passed\n";
    return EXIT_SUCCESS;
}
