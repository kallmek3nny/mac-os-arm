#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace macosarm {

enum class PointerAuthKey : std::uint8_t {
    instruction_a = 0,
    instruction_b = 1,
    data_a = 2,
    data_b = 3,
};

struct PointerAuthKeyMaterial {
    std::uint64_t low{};
    std::uint64_t high{};

    [[nodiscard]] friend constexpr bool operator==(
        const PointerAuthKeyMaterial&,
        const PointerAuthKeyMaterial&) = default;
};

struct PointerAuthKeySet {
    std::array<PointerAuthKeyMaterial, 4> values{};

    [[nodiscard]] friend constexpr bool operator==(
        const PointerAuthKeySet&,
        const PointerAuthKeySet&) = default;
};

enum class PointerAuthError {
    none,
    invalid_key,
    pointer_out_of_range,
    invalid_signature,
};

struct PointerAuthResult {
    std::uint64_t pointer{};
    PointerAuthError error{PointerAuthError::none};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == PointerAuthError::none;
    }
};

// Functional software model of ARM pointer-authentication semantics for the
// translated guest. The signature algorithm itself is emulator-defined because
// ARM/Apple do not make the hardware PAC hash part of the arm64e ABI. We keep
// the ABI-visible pieces exact: four keys, a 64-bit discriminator, arm64e's
// 16-bit blend operation, explicit authentication, and stripping.
//
// Phase 22 intentionally models low-48-bit user pointers with a 16-bit software
// PAC in bits 63:48. This is a guest policy, not a claim of bit-for-bit Apple
// hardware PAC compatibility or equivalent hardware security.
class PointerAuthenticator {
public:
    static constexpr unsigned kAddressBits = 48;
    static constexpr std::uint64_t kAddressMask =
        (std::uint64_t{1} << kAddressBits) - 1;
    static constexpr std::uint64_t kPacMask = ~kAddressMask;

    explicit constexpr PointerAuthenticator(PointerAuthKeySet keys) noexcept
        : keys_(keys) {}

    [[nodiscard]] PointerAuthResult sign(
        std::uint64_t pointer,
        PointerAuthKey key,
        std::uint64_t discriminator) const noexcept;

    [[nodiscard]] PointerAuthResult authenticate(
        std::uint64_t signed_pointer,
        PointerAuthKey key,
        std::uint64_t discriminator) const noexcept;

    [[nodiscard]] static constexpr std::uint64_t strip(
        std::uint64_t signed_pointer) noexcept {
        return signed_pointer & kAddressMask;
    }

    // arm64e ptrauth_blend_discriminator replaces the high 16 bits of the
    // address discriminator with the 16-bit constant discriminator.
    [[nodiscard]] static constexpr std::uint64_t blend_discriminator(
        std::uint64_t address,
        std::uint16_t diversity) noexcept {
        return (address & kAddressMask) |
               (static_cast<std::uint64_t>(diversity) << kAddressBits);
    }

private:
    [[nodiscard]] const PointerAuthKeyMaterial* key_material(
        PointerAuthKey key) const noexcept;

    [[nodiscard]] static std::uint64_t signature(
        std::uint64_t pointer,
        std::uint64_t discriminator,
        const PointerAuthKeyMaterial& key) noexcept;

    PointerAuthKeySet keys_;
};

[[nodiscard]] std::string_view pointer_auth_error_name(
    PointerAuthError error) noexcept;

} // namespace macosarm
