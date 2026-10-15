#include "macosarm/pointer_auth.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int failures = 0;

void expect(bool condition, const std::string& label) {
    if (!condition) {
        std::cerr << "FAIL: " << label << '\n';
        ++failures;
    }
}

macosarm::PointerAuthKeySet test_keys() {
    return {{
        {0x0123456789abcdefULL, 0xfedcba9876543210ULL},
        {0x1111222233334444ULL, 0x5555666677778888ULL},
        {0x1020304050607080ULL, 0x90a0b0c0d0e0f000ULL},
        {0x0f1e2d3c4b5a6978ULL, 0x8796a5b4c3d2e1f0ULL},
    }};
}

} // namespace

int main() {
    using macosarm::PointerAuthError;
    using macosarm::PointerAuthKey;
    using macosarm::PointerAuthenticator;

    const PointerAuthenticator auth(test_keys());
    constexpr std::uint64_t pointer = 0x0000000100001234ULL;
    constexpr std::uint64_t discriminator = 0x0000000700000555ULL;

    const auto signed_ia = auth.sign(pointer, PointerAuthKey::instruction_a, discriminator);
    expect(static_cast<bool>(signed_ia), "IA signing succeeds");
    expect(
        signed_ia.pointer == 0x2d08000100001234ULL,
        "software PAC has stable deterministic test vector");
    expect(
        PointerAuthenticator::strip(signed_ia.pointer) == pointer,
        "strip removes software PAC bits");

    const auto authenticated = auth.authenticate(
        signed_ia.pointer,
        PointerAuthKey::instruction_a,
        discriminator);
    expect(static_cast<bool>(authenticated), "matching IA authentication succeeds");
    expect(authenticated.pointer == pointer, "authentication restores raw pointer");

    const auto wrong_key = auth.authenticate(
        signed_ia.pointer,
        PointerAuthKey::instruction_b,
        discriminator);
    expect(
        wrong_key.error == PointerAuthError::invalid_signature,
        "different key rejects signed pointer");

    const auto wrong_discriminator = auth.authenticate(
        signed_ia.pointer,
        PointerAuthKey::instruction_a,
        discriminator + 1);
    expect(
        wrong_discriminator.error == PointerAuthError::invalid_signature,
        "different discriminator rejects signed pointer");

    const auto tampered = auth.authenticate(
        signed_ia.pointer ^ 0x20U,
        PointerAuthKey::instruction_a,
        discriminator);
    expect(
        tampered.error == PointerAuthError::invalid_signature,
        "tampered pointer bits fail authentication");

    const auto signed_da = auth.sign(pointer, PointerAuthKey::data_a, discriminator);
    expect(static_cast<bool>(signed_da), "DA signing succeeds");
    expect(
        signed_da.pointer != signed_ia.pointer,
        "independent key material produces independent PAC");

    constexpr std::uint64_t storage_address = 0x0000000101234568ULL;
    constexpr std::uint16_t diversity = 0xbeefU;
    expect(
        PointerAuthenticator::blend_discriminator(storage_address, diversity) ==
            0xbeef000101234568ULL,
        "arm64e discriminator blend replaces the high 16 bits");

    const auto blended_signed = auth.sign(
        pointer,
        PointerAuthKey::data_b,
        PointerAuthenticator::blend_discriminator(storage_address, diversity));
    expect(static_cast<bool>(blended_signed), "address-diverse signing succeeds");
    expect(
        static_cast<bool>(auth.authenticate(
            blended_signed.pointer,
            PointerAuthKey::data_b,
            PointerAuthenticator::blend_discriminator(storage_address, diversity))),
        "matching address-diverse authentication succeeds");
    expect(
        auth.authenticate(
                blended_signed.pointer,
                PointerAuthKey::data_b,
                PointerAuthenticator::blend_discriminator(storage_address + 8, diversity))
                .error == PointerAuthError::invalid_signature,
        "moving an address-diverse pointer invalidates its PAC");

    const auto out_of_range = auth.sign(
        0x0001000000000000ULL,
        PointerAuthKey::instruction_a,
        0);
    expect(
        out_of_range.error == PointerAuthError::pointer_out_of_range,
        "signing rejects pointers outside the phase-22 48-bit guest policy");

    const auto invalid_key = auth.sign(
        pointer,
        static_cast<PointerAuthKey>(9),
        discriminator);
    expect(
        invalid_key.error == PointerAuthError::invalid_key,
        "invalid abstract key rejected");

    expect(
        macosarm::pointer_auth_error_name(PointerAuthError::invalid_signature) ==
            "invalid_signature",
        "pointer-auth errors have stable names");

    if (failures != 0) {
        std::cerr << failures << " pointer-auth test(s) failed\n";
        return EXIT_FAILURE;
    }

    std::cout << "software pointer-auth tests passed\n";
    return EXIT_SUCCESS;
}
