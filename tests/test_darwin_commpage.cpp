#include "macosarm/darwin_commpage.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
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

const macosarm::Mapping* find_mapping(
    const std::vector<macosarm::Mapping>& mappings,
    std::uint64_t base) {
    const auto it = std::find_if(
        mappings.begin(),
        mappings.end(),
        [base](const macosarm::Mapping& mapping) { return mapping.base == base; });
    return it == mappings.end() ? nullptr : &*it;
}

} // namespace

int main() {
    {
        macosarm::GuestAddressSpace address_space;
        const auto result = macosarm::materialize_darwin_commpage(address_space);
        expect(static_cast<bool>(result), "Darwin commpage materializes");

        const auto mappings = address_space.mappings();
        expect(mappings.size() == 2, "Darwin commpage creates two guest mappings");
        const auto* data = find_mapping(mappings, macosarm::kDarwinCommpageDataAddress);
        const auto* read_only = find_mapping(mappings, macosarm::kDarwinCommpageReadOnlyAddress);
        expect(data != nullptr && data->size == macosarm::GuestAddressSpace::kPageSize &&
                   data->protection == macosarm::Protection::read,
               "commpage data mapping is one guest page and guest-read-only");
        expect(read_only != nullptr &&
                   read_only->size == macosarm::GuestAddressSpace::kPageSize &&
                   read_only->protection == macosarm::Protection::read,
               "commpage RO mapping is one guest page and guest-read-only");

        std::array<std::byte, 4> kdebug{};
        expect(static_cast<bool>(address_space.read(
                   macosarm::kDarwinCommpageKdebugEnableAddress, kdebug)) &&
                   std::all_of(kdebug.begin(), kdebug.end(), [](std::byte value) {
                       return value == std::byte{0};
                   }),
               "libSystem kdebug gate reads as disabled from the data commpage");

        std::array<std::byte, 1> user_shift{};
        std::array<std::byte, 1> kernel_shift{};
        expect(static_cast<bool>(address_space.read(
                   macosarm::kDarwinCommpageUserPageShift64Address, user_shift)) &&
                   std::to_integer<unsigned int>(user_shift[0]) ==
                       macosarm::kDarwinCommpagePageShift,
               "arm64 user page shift is materialized for mach_init");
        expect(static_cast<bool>(address_space.read(
                   macosarm::kDarwinCommpageKernelPageShiftAddress, kernel_shift)) &&
                   std::to_integer<unsigned int>(kernel_shift[0]) ==
                       macosarm::kDarwinCommpagePageShift,
               "kernel page shift is materialized for mach_init");

        const std::array<std::byte, 1> mutation{std::byte{1}};
        expect(address_space.write(
                   macosarm::kDarwinCommpageKdebugEnableAddress, mutation).error ==
                   macosarm::VmError::protection,
               "guest writes cannot mutate the data commpage");
        expect(address_space.write(
                   macosarm::kDarwinCommpageKernelPageShiftAddress, mutation).error ==
                   macosarm::VmError::protection,
               "guest writes cannot mutate the RO commpage");
    }

    {
        macosarm::GuestAddressSpace address_space;
        expect(static_cast<bool>(address_space.map(
                   macosarm::kDarwinCommpageReadOnlyAddress,
                   macosarm::GuestAddressSpace::kPageSize,
                   macosarm::Protection::read)),
               "collision fixture reserves the commpage RO slot");

        const auto result = macosarm::materialize_darwin_commpage(address_space);
        expect(result.error == macosarm::DarwinCommpageError::read_only_map_failure &&
                   result.vm_error == macosarm::VmError::overlap,
               "commpage collision fails closed at the exact overlapping mapping");

        std::array<std::byte, 1> byte{};
        expect(address_space.read(macosarm::kDarwinCommpageDataAddress, byte).error ==
                   macosarm::VmError::unmapped,
               "partial commpage mapping rolls back when the RO slot collides");
        const auto mappings = address_space.mappings();
        expect(mappings.size() == 1 &&
                   mappings.front().base == macosarm::kDarwinCommpageReadOnlyAddress,
               "collision rollback preserves only the caller-owned mapping");
    }

    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "Darwin commpage bootstrap passed\n";
    return EXIT_SUCCESS;
}
