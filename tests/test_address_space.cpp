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

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "all guest address-space tests passed\n";
    return EXIT_SUCCESS;
}
