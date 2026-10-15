#include "macosarm/pointer_auth.hpp"

#include <cstddef>

namespace macosarm {
namespace {

[[nodiscard]] constexpr std::uint64_t rotate_left(
    std::uint64_t value,
    unsigned shift) noexcept {
    return (value << shift) | (value >> (64U - shift));
}

void sip_round(
    std::uint64_t& v0,
    std::uint64_t& v1,
    std::uint64_t& v2,
    std::uint64_t& v3) noexcept {
    v0 += v1;
    v1 = rotate_left(v1, 13) ^ v0;
    v0 = rotate_left(v0, 32);
    v2 += v3;
    v3 = rotate_left(v3, 16) ^ v2;
    v0 += v3;
    v3 = rotate_left(v3, 21) ^ v0;
    v2 += v1;
    v1 = rotate_left(v1, 17) ^ v2;
    v2 = rotate_left(v2, 32);
}

void sip_compress(
    std::uint64_t message,
    std::uint64_t& v0,
    std::uint64_t& v1,
    std::uint64_t& v2,
    std::uint64_t& v3) noexcept {
    v3 ^= message;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= message;
}

[[nodiscard]] std::uint64_t siphash24_two_words(
    std::uint64_t first,
    std::uint64_t second,
    const PointerAuthKeyMaterial& key) noexcept {
    std::uint64_t v0 = 0x736f6d6570736575ULL ^ key.low;
    std::uint64_t v1 = 0x646f72616e646f6dULL ^ key.high;
    std::uint64_t v2 = 0x6c7967656e657261ULL ^ key.low;
    std::uint64_t v3 = 0x7465646279746573ULL ^ key.high;

    sip_compress(first, v0, v1, v2, v3);
    sip_compress(second, v0, v1, v2, v3);
    sip_compress(std::uint64_t{16} << 56U, v0, v1, v2, v3);

    v2 ^= 0xffU;
    for (unsigned round = 0; round < 4; ++round) {
        sip_round(v0, v1, v2, v3);
    }
    return v0 ^ v1 ^ v2 ^ v3;
}

} // namespace

const PointerAuthKeyMaterial* PointerAuthenticator::key_material(
    PointerAuthKey key) const noexcept {
    const auto index = static_cast<std::size_t>(key);
    if (index >= keys_.values.size()) {
        return nullptr;
    }
    return &keys_.values[index];
}

std::uint64_t PointerAuthenticator::signature(
    std::uint64_t pointer,
    std::uint64_t discriminator,
    const PointerAuthKeyMaterial& key) noexcept {
    return siphash24_two_words(pointer, discriminator, key) & 0xffffU;
}

PointerAuthResult PointerAuthenticator::sign(
    std::uint64_t pointer,
    PointerAuthKey key,
    std::uint64_t discriminator) const noexcept {
    const PointerAuthKeyMaterial* material = key_material(key);
    if (material == nullptr) {
        return {0, PointerAuthError::invalid_key};
    }
    if ((pointer & kPacMask) != 0) {
        return {0, PointerAuthError::pointer_out_of_range};
    }

    const std::uint64_t pac = signature(pointer, discriminator, *material);
    return {
        pointer | (pac << kAddressBits),
        PointerAuthError::none,
    };
}

PointerAuthResult PointerAuthenticator::authenticate(
    std::uint64_t signed_pointer,
    PointerAuthKey key,
    std::uint64_t discriminator) const noexcept {
    const PointerAuthKeyMaterial* material = key_material(key);
    if (material == nullptr) {
        return {0, PointerAuthError::invalid_key};
    }

    const std::uint64_t pointer = strip(signed_pointer);
    const std::uint64_t pac = signature(pointer, discriminator, *material);
    const std::uint64_t expected = pointer | (pac << kAddressBits);
    if (expected != signed_pointer) {
        return {0, PointerAuthError::invalid_signature};
    }
    return {pointer, PointerAuthError::none};
}

std::string_view pointer_auth_error_name(PointerAuthError error) noexcept {
    switch (error) {
    case PointerAuthError::none: return "none";
    case PointerAuthError::invalid_key: return "invalid_key";
    case PointerAuthError::pointer_out_of_range: return "pointer_out_of_range";
    case PointerAuthError::invalid_signature: return "invalid_signature";
    }
    return "unknown";
}

} // namespace macosarm
