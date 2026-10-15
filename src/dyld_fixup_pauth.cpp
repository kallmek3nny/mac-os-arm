#include "macosarm/dyld_fixup_pauth.hpp"

#include <array>
#include <limits>
#include <vector>

namespace macosarm::dyld {
namespace {

constexpr std::uint64_t kTarget43Mask = (std::uint64_t{1} << 43) - 1;
constexpr std::uint64_t kHigh8Mask = 0xff;
constexpr std::uint64_t kOrdinal16Mask = (std::uint64_t{1} << 16) - 1;
constexpr std::uint64_t kOrdinal24Mask = (std::uint64_t{1} << 24) - 1;
constexpr std::uint64_t kZero16Mask = (std::uint64_t{1} << 16) - 1;
constexpr std::uint64_t kZero8Mask = (std::uint64_t{1} << 8) - 1;
constexpr std::uint64_t kAddend19Mask = (std::uint64_t{1} << 19) - 1;
constexpr std::uint64_t kAddend19Sign = std::uint64_t{1} << 18;
constexpr std::uint64_t kNextMask = (std::uint64_t{1} << 11) - 1;
constexpr std::uint64_t kBindBit = std::uint64_t{1} << 62;
constexpr std::uint64_t kAuthBit = std::uint64_t{1} << 63;
constexpr std::uint64_t kAuthTargetMask = 0xffffffffULL;

constexpr std::int32_t kBindSpecialDylibSelf = 0;
constexpr std::int32_t kBindSpecialDylibMainExecutable = -1;
constexpr std::int32_t kBindSpecialDylibFlatLookup = -2;
constexpr std::int32_t kBindSpecialDylibWeakLookup = -3;

[[nodiscard]] bool add_overflows(std::uint64_t left, std::uint64_t right) noexcept {
    return right > std::numeric_limits<std::uint64_t>::max() - left;
}

[[nodiscard]] bool multiply_overflows(std::uint64_t left, std::uint64_t right) noexcept {
    return left != 0 && right > std::numeric_limits<std::uint64_t>::max() / left;
}

[[nodiscard]] bool add_signed(
    std::uint64_t value,
    std::int64_t addend,
    std::uint64_t& output) noexcept {
    if (addend >= 0) {
        const auto positive = static_cast<std::uint64_t>(addend);
        if (add_overflows(value, positive)) {
            return false;
        }
        output = value + positive;
        return true;
    }

    const std::uint64_t magnitude =
        static_cast<std::uint64_t>(-(addend + 1)) + std::uint64_t{1};
    if (magnitude > value) {
        return false;
    }
    output = value - magnitude;
    return true;
}

[[nodiscard]] std::int64_t sign_extend_19(std::uint64_t value) noexcept {
    value &= kAddend19Mask;
    if ((value & kAddend19Sign) == 0) {
        return static_cast<std::int64_t>(value);
    }
    return static_cast<std::int64_t>(value) - (std::int64_t{1} << 19);
}

[[nodiscard]] bool supported_format(ChainedPointerFormat format) noexcept {
    return format == ChainedPointerFormat::arm64e ||
           format == ChainedPointerFormat::arm64e_userland ||
           format == ChainedPointerFormat::arm64e_userland24;
}

[[nodiscard]] bool uses_image_offset(ChainedPointerFormat format) noexcept {
    return format == ChainedPointerFormat::arm64e_userland ||
           format == ChainedPointerFormat::arm64e_userland24;
}

[[nodiscard]] bool uses_24bit_ordinal(ChainedPointerFormat format) noexcept {
    return format == ChainedPointerFormat::arm64e_userland24;
}

[[nodiscard]] std::uint64_t decode_u64(const std::array<std::byte, 8>& bytes) noexcept {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        value |= static_cast<std::uint64_t>(std::to_integer<unsigned char>(bytes[index]))
                 << (index * 8U);
    }
    return value;
}

[[nodiscard]] std::array<std::byte, 8> encode_u64(std::uint64_t value) noexcept {
    std::array<std::byte, 8> bytes{};
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
    return bytes;
}

struct Patch {
    std::uint64_t address{};
    std::uint64_t original{};
};

struct ImportResolution {
    bool success{};
    bool weak_null{};
    std::uint64_t address{};
    Arm64eFixupsApplyError error{Arm64eFixupsApplyError::none};
    SymbolResolutionError symbol_error{SymbolResolutionError::none};
};

struct DecodedPointer {
    std::uint64_t replacement{};
    std::uint64_t next{};
    std::size_t import_index{Arm64eFixupsApplyResult::kNoIndex};
};

class Applier {
public:
    Applier(
        const LoadedImageGraph& graph,
        std::size_t image_index,
        const ChainedFixupsMetadata& metadata,
        GuestAddressSpace& address_space,
        const Arm64eFixupsApplyConfig& config)
        : graph_(graph),
          image_index_(image_index),
          metadata_(metadata),
          address_space_(address_space),
          config_(config) {}

    [[nodiscard]] Arm64eFixupsApplyResult run() {
        if (image_index_ >= graph_.images.size()) {
            return fail(Arm64eFixupsApplyError::bad_image_index);
        }
        image_ = &graph_.images[image_index_];
        if (metadata_.segments.size() > image_->image.segments.size()) {
            return fail(Arm64eFixupsApplyError::metadata_segment_count_exceeds_image);
        }

        for (std::size_t segment_index = 0;
             segment_index < metadata_.segments.size();
             ++segment_index) {
            const ChainedSegmentStarts& starts = metadata_.segments[segment_index];
            if (!starts.present) {
                continue;
            }
            const auto segment_result = apply_segment(segment_index, starts);
            if (!segment_result) {
                return segment_result;
            }
        }
        return result_;
    }

private:
    [[nodiscard]] Arm64eFixupsApplyResult fail(
        Arm64eFixupsApplyError error,
        std::size_t segment_index = Arm64eFixupsApplyResult::kNoIndex,
        std::size_t page_index = Arm64eFixupsApplyResult::kNoIndex,
        std::size_t import_index = Arm64eFixupsApplyResult::kNoIndex,
        std::uint64_t address = 0,
        VmError vm_error = VmError::none,
        SymbolResolutionError symbol_error = SymbolResolutionError::none,
        PointerAuthError pointer_auth_error = PointerAuthError::none) {
        result_.error = error;
        result_.segment_index = segment_index;
        result_.page_index = page_index;
        result_.import_index = import_index;
        result_.address = address;
        result_.vm_error = vm_error;
        result_.symbol_error = symbol_error;
        result_.pointer_auth_error = pointer_auth_error;

        if (patches_.empty()) {
            return result_;
        }

        result_.rolled_back = true;
        for (auto it = patches_.rbegin(); it != patches_.rend(); ++it) {
            const auto bytes = encode_u64(it->original);
            const VmResult restored = address_space_.write(it->address, bytes);
            if (!restored) {
                result_.error = Arm64eFixupsApplyError::rollback_failure;
                result_.vm_error = restored.error;
                result_.address = it->address;
                return result_;
            }
        }
        return result_;
    }

    [[nodiscard]] Arm64eFixupsApplyResult apply_segment(
        std::size_t segment_index,
        const ChainedSegmentStarts& starts) {
        if (starts.page_size != 0x1000 && starts.page_size != 0x4000) {
            return fail(Arm64eFixupsApplyError::invalid_page_size, segment_index);
        }
        if (!supported_format(starts.pointer_format)) {
            return fail(Arm64eFixupsApplyError::unsupported_pointer_format, segment_index);
        }

        const macho::Segment& segment = image_->image.segments[segment_index];
        const std::uint64_t image_base = image_->mapping.preferred_load_address;
        if (segment.vm_address < image_base) {
            return fail(Arm64eFixupsApplyError::segment_offset_overflow, segment_index);
        }
        if (starts.segment_offset != segment.vm_address - image_base) {
            return fail(Arm64eFixupsApplyError::segment_offset_mismatch, segment_index);
        }
        if (segment.vm_size == 0) {
            if (!starts.pages.empty()) {
                return fail(Arm64eFixupsApplyError::page_count_exceeds_segment, segment_index);
            }
            return result_;
        }

        const std::uint64_t page_size = starts.page_size;
        const std::uint64_t page_count =
            segment.vm_size / page_size + ((segment.vm_size % page_size) != 0 ? 1 : 0);
        if (starts.pages.size() > page_count) {
            return fail(Arm64eFixupsApplyError::page_count_exceeds_segment, segment_index);
        }
        if (add_overflows(segment.vm_address, segment.vm_size)) {
            return fail(Arm64eFixupsApplyError::page_address_overflow, segment_index);
        }

        for (std::size_t page_index = 0; page_index < starts.pages.size(); ++page_index) {
            const ChainedPageStarts& page = starts.pages[page_index];
            if (page.offsets.empty()) {
                continue;
            }
            if (page.offsets.size() != 1) {
                return fail(
                    Arm64eFixupsApplyError::multiple_page_starts_unsupported,
                    segment_index,
                    page_index);
            }
            if (multiply_overflows(static_cast<std::uint64_t>(page_index), page_size)) {
                return fail(
                    Arm64eFixupsApplyError::page_address_overflow,
                    segment_index,
                    page_index);
            }
            const std::uint64_t page_segment_offset =
                static_cast<std::uint64_t>(page_index) * page_size;
            if (add_overflows(segment.vm_address, page_segment_offset)) {
                return fail(
                    Arm64eFixupsApplyError::page_address_overflow,
                    segment_index,
                    page_index);
            }
            const std::uint64_t page_address = segment.vm_address + page_segment_offset;
            const std::uint64_t start = page.offsets.front();
            if (start > page_size || page_size - start < 8) {
                return fail(
                    Arm64eFixupsApplyError::chain_start_out_of_page,
                    segment_index,
                    page_index,
                    Arm64eFixupsApplyResult::kNoIndex,
                    page_address);
            }
            if (page_segment_offset > segment.vm_size ||
                start > segment.vm_size - page_segment_offset ||
                segment.vm_size - page_segment_offset - start < 8) {
                return fail(
                    Arm64eFixupsApplyError::chain_start_out_of_segment,
                    segment_index,
                    page_index,
                    Arm64eFixupsApplyResult::kNoIndex,
                    page_address + start);
            }

            const auto page_result = apply_chain(
                segment_index,
                page_index,
                starts,
                segment,
                page_address + start);
            if (!page_result) {
                return page_result;
            }
        }
        return result_;
    }

    [[nodiscard]] Arm64eFixupsApplyResult sign_pointer(
        std::size_t segment_index,
        std::size_t page_index,
        std::size_t import_index,
        std::uint64_t address,
        std::uint64_t target,
        std::uint64_t raw,
        DecodedPointer& decoded) {
        if (config_.pointer_auth == nullptr) {
            return fail(
                Arm64eFixupsApplyError::pointer_auth_required,
                segment_index,
                page_index,
                import_index,
                address);
        }

        const std::uint16_t diversity = static_cast<std::uint16_t>((raw >> 32) & 0xffffU);
        const bool address_diversity = ((raw >> 48) & 1U) != 0;
        const auto key = static_cast<PointerAuthKey>((raw >> 49) & 0x3U);
        const std::uint64_t discriminator = address_diversity
            ? PointerAuthenticator::blend_discriminator(address, diversity)
            : static_cast<std::uint64_t>(diversity);
        const PointerAuthResult signed_pointer =
            config_.pointer_auth->sign(target, key, discriminator);
        if (!signed_pointer) {
            return fail(
                Arm64eFixupsApplyError::pointer_auth_failure,
                segment_index,
                page_index,
                import_index,
                address,
                VmError::none,
                SymbolResolutionError::none,
                signed_pointer.error);
        }
        decoded.replacement = signed_pointer.pointer;
        return result_;
    }

    [[nodiscard]] Arm64eFixupsApplyResult decode_pointer(
        std::size_t segment_index,
        std::size_t page_index,
        const ChainedSegmentStarts& starts,
        std::uint64_t address,
        std::uint64_t raw,
        DecodedPointer& decoded) {
        decoded.next = (raw >> 51) & kNextMask;
        const bool is_bind = (raw & kBindBit) != 0;
        const bool is_auth = (raw & kAuthBit) != 0;

        if (is_auth) {
            if (is_bind) {
                const bool ordinal24 = uses_24bit_ordinal(starts.pointer_format);
                const std::uint64_t zero = ordinal24
                    ? ((raw >> 24) & kZero8Mask)
                    : ((raw >> 16) & kZero16Mask);
                if (zero != 0) {
                    return fail(
                        Arm64eFixupsApplyError::pointer_reserved_bits,
                        segment_index,
                        page_index,
                        decoded.import_index,
                        address);
                }
                decoded.import_index = static_cast<std::size_t>(
                    raw & (ordinal24 ? kOrdinal24Mask : kOrdinal16Mask));
                if (decoded.import_index >= metadata_.imports.size()) {
                    return fail(
                        Arm64eFixupsApplyError::bind_ordinal_out_of_range,
                        segment_index,
                        page_index,
                        decoded.import_index,
                        address);
                }
                const ImportResolution resolution =
                    resolve_import(metadata_.imports[decoded.import_index]);
                if (!resolution.success) {
                    return fail(
                        resolution.error,
                        segment_index,
                        page_index,
                        decoded.import_index,
                        address,
                        VmError::none,
                        resolution.symbol_error);
                }
                if (resolution.weak_null) {
                    decoded.replacement = 0;
                    return result_;
                }

                std::uint64_t target = 0;
                if (!add_signed(
                        resolution.address,
                        metadata_.imports[decoded.import_index].addend,
                        target)) {
                    return fail(
                        Arm64eFixupsApplyError::addend_overflow,
                        segment_index,
                        page_index,
                        decoded.import_index,
                        address);
                }
                return sign_pointer(
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address,
                    target,
                    raw,
                    decoded);
            }

            const std::uint64_t target_offset = raw & kAuthTargetMask;
            if (add_overflows(image_->mapping.preferred_load_address, target_offset)) {
                return fail(
                    Arm64eFixupsApplyError::addend_overflow,
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address);
            }
            return sign_pointer(
                segment_index,
                page_index,
                decoded.import_index,
                address,
                image_->mapping.preferred_load_address + target_offset,
                raw,
                decoded);
        }

        if (is_bind) {
            const bool ordinal24 = uses_24bit_ordinal(starts.pointer_format);
            const std::uint64_t zero = ordinal24
                ? ((raw >> 24) & kZero8Mask)
                : ((raw >> 16) & kZero16Mask);
            if (zero != 0) {
                return fail(
                    Arm64eFixupsApplyError::pointer_reserved_bits,
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address);
            }
            decoded.import_index = static_cast<std::size_t>(
                raw & (ordinal24 ? kOrdinal24Mask : kOrdinal16Mask));
            if (decoded.import_index >= metadata_.imports.size()) {
                return fail(
                    Arm64eFixupsApplyError::bind_ordinal_out_of_range,
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address);
            }
            const ImportResolution resolution =
                resolve_import(metadata_.imports[decoded.import_index]);
            if (!resolution.success) {
                return fail(
                    resolution.error,
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address,
                    VmError::none,
                    resolution.symbol_error);
            }
            if (resolution.weak_null) {
                decoded.replacement = 0;
                return result_;
            }
            if (!add_signed(
                    resolution.address,
                    metadata_.imports[decoded.import_index].addend,
                    decoded.replacement)) {
                return fail(
                    Arm64eFixupsApplyError::addend_overflow,
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address);
            }
            std::uint64_t with_pointer_addend = 0;
            if (!add_signed(decoded.replacement, sign_extend_19(raw >> 32), with_pointer_addend)) {
                return fail(
                    Arm64eFixupsApplyError::addend_overflow,
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address);
            }
            decoded.replacement = with_pointer_addend;
            return result_;
        }

        const std::uint64_t target = raw & kTarget43Mask;
        const std::uint64_t high8 = (raw >> 43) & kHigh8Mask;
        const std::uint64_t unpacked_target = target | (high8 << 56);
        if (!uses_image_offset(starts.pointer_format)) {
            decoded.replacement = unpacked_target;
            return result_;
        }
        if (add_overflows(image_->mapping.preferred_load_address, unpacked_target)) {
            return fail(
                Arm64eFixupsApplyError::addend_overflow,
                segment_index,
                page_index,
                decoded.import_index,
                address);
        }
        decoded.replacement = image_->mapping.preferred_load_address + unpacked_target;
        return result_;
    }

    [[nodiscard]] Arm64eFixupsApplyResult apply_chain(
        std::size_t segment_index,
        std::size_t page_index,
        const ChainedSegmentStarts& starts,
        const macho::Segment& segment,
        std::uint64_t address) {
        const std::uint64_t page_size = starts.page_size;
        const std::uint64_t page_address =
            segment.vm_address + static_cast<std::uint64_t>(page_index) * page_size;

        while (true) {
            if (result_.fixups_processed >= config_.max_fixups) {
                return fail(
                    Arm64eFixupsApplyError::fixup_limit,
                    segment_index,
                    page_index,
                    Arm64eFixupsApplyResult::kNoIndex,
                    address);
            }

            std::array<std::byte, 8> bytes{};
            const VmResult read = address_space_.read(address, bytes);
            if (!read) {
                return fail(
                    Arm64eFixupsApplyError::read_failure,
                    segment_index,
                    page_index,
                    Arm64eFixupsApplyResult::kNoIndex,
                    address,
                    read.error);
            }
            const std::uint64_t raw = decode_u64(bytes);
            DecodedPointer decoded;
            const auto decoded_result =
                decode_pointer(segment_index, page_index, starts, address, raw, decoded);
            if (!decoded_result) {
                return decoded_result;
            }

            std::uint64_t next_address = 0;
            if (decoded.next != 0) {
                const std::uint64_t delta = decoded.next * 8U;
                const std::uint64_t offset_in_page = address - page_address;
                if (offset_in_page > page_size ||
                    delta > page_size - offset_in_page ||
                    page_size - offset_in_page - delta < 8) {
                    return fail(
                        Arm64eFixupsApplyError::chain_next_out_of_page,
                        segment_index,
                        page_index,
                        decoded.import_index,
                        address);
                }
                const std::uint64_t offset_in_segment = address - segment.vm_address;
                if (offset_in_segment > segment.vm_size ||
                    delta > segment.vm_size - offset_in_segment ||
                    segment.vm_size - offset_in_segment - delta < 8) {
                    return fail(
                        Arm64eFixupsApplyError::chain_next_out_of_segment,
                        segment_index,
                        page_index,
                        decoded.import_index,
                        address);
                }
                if (add_overflows(address, delta)) {
                    return fail(
                        Arm64eFixupsApplyError::page_address_overflow,
                        segment_index,
                        page_index,
                        decoded.import_index,
                        address);
                }
                next_address = address + delta;
            }

            const auto replacement = encode_u64(decoded.replacement);
            const VmResult written = address_space_.write(address, replacement);
            if (!written) {
                return fail(
                    Arm64eFixupsApplyError::write_failure,
                    segment_index,
                    page_index,
                    decoded.import_index,
                    address,
                    written.error);
            }
            patches_.push_back(Patch{address, raw});
            ++result_.fixups_processed;

            if (decoded.next == 0) {
                break;
            }
            address = next_address;
        }
        return result_;
    }

    [[nodiscard]] ImportResolution resolve_from_image(
        std::size_t target_image_index,
        const ChainedImportEntry& import,
        bool weak_lookup) const {
        const bool weak = import.weak_import || weak_lookup;
        const SymbolResolutionResult resolved = resolve_symbol(
            graph_, target_image_index, import.symbol_name, weak, config_.symbol_resolution);
        if (resolved.status == SymbolResolutionStatus::found) {
            return {true, false, resolved.symbol.address};
        }
        if (resolved.status == SymbolResolutionStatus::not_found) {
            if (weak) {
                return {true, true, 0};
            }
            ImportResolution result;
            result.error = Arm64eFixupsApplyError::symbol_not_found;
            return result;
        }
        ImportResolution result;
        result.error = Arm64eFixupsApplyError::symbol_resolution_failure;
        result.symbol_error = resolved.error;
        return result;
    }

    [[nodiscard]] ImportResolution resolve_flat(
        const ChainedImportEntry& import,
        bool weak_lookup) const {
        const bool weak = import.weak_import || weak_lookup;
        for (std::size_t index = 0; index < graph_.images.size(); ++index) {
            const SymbolResolutionResult resolved = resolve_symbol(
                graph_, index, import.symbol_name, weak, config_.symbol_resolution);
            if (resolved.status == SymbolResolutionStatus::found) {
                return {true, false, resolved.symbol.address};
            }
            if (resolved.status == SymbolResolutionStatus::error) {
                ImportResolution result;
                result.error = Arm64eFixupsApplyError::symbol_resolution_failure;
                result.symbol_error = resolved.error;
                return result;
            }
        }
        if (weak) {
            return {true, true, 0};
        }
        ImportResolution result;
        result.error = Arm64eFixupsApplyError::symbol_not_found;
        return result;
    }

    [[nodiscard]] ImportResolution resolve_import(const ChainedImportEntry& import) const {
        if (import.library_ordinal > 0) {
            const std::size_t dependency_index =
                static_cast<std::size_t>(import.library_ordinal - 1);
            if (dependency_index >= image_->dependencies.size()) {
                ImportResolution result;
                result.error = Arm64eFixupsApplyError::library_ordinal_out_of_range;
                return result;
            }
            const GraphDependency& dependency = image_->dependencies[dependency_index];
            if (dependency.state != GraphDependencyState::loaded ||
                dependency.image_index == GraphDependency::kNoImage ||
                dependency.image_index >= graph_.images.size()) {
                if (import.weak_import &&
                    dependency.state == GraphDependencyState::missing_weak) {
                    return {true, true, 0};
                }
                ImportResolution result;
                result.error = Arm64eFixupsApplyError::dependency_unavailable;
                return result;
            }
            return resolve_from_image(dependency.image_index, import, false);
        }

        switch (import.library_ordinal) {
        case kBindSpecialDylibSelf:
            return resolve_from_image(image_index_, import, false);
        case kBindSpecialDylibMainExecutable:
            if (graph_.images.empty()) {
                ImportResolution result;
                result.error = Arm64eFixupsApplyError::dependency_unavailable;
                return result;
            }
            return resolve_from_image(0, import, false);
        case kBindSpecialDylibFlatLookup:
            return resolve_flat(import, false);
        case kBindSpecialDylibWeakLookup:
            return resolve_flat(import, true);
        default: {
            ImportResolution result;
            result.error = Arm64eFixupsApplyError::unsupported_special_ordinal;
            return result;
        }
        }
    }

    const LoadedImageGraph& graph_;
    std::size_t image_index_{};
    const ChainedFixupsMetadata& metadata_;
    GuestAddressSpace& address_space_;
    const Arm64eFixupsApplyConfig& config_;
    const GraphImage* image_{};
    Arm64eFixupsApplyResult result_;
    std::vector<Patch> patches_;
};

} // namespace

Arm64eFixupsApplyResult apply_arm64e_chained_fixups(
    const LoadedImageGraph& graph,
    std::size_t image_index,
    const ChainedFixupsMetadata& metadata,
    GuestAddressSpace& address_space,
    const Arm64eFixupsApplyConfig& config) {
    return Applier(graph, image_index, metadata, address_space, config).run();
}

std::string_view arm64e_fixups_apply_error_name(Arm64eFixupsApplyError error) noexcept {
    switch (error) {
    case Arm64eFixupsApplyError::none: return "none";
    case Arm64eFixupsApplyError::bad_image_index: return "bad_image_index";
    case Arm64eFixupsApplyError::metadata_segment_count_exceeds_image:
        return "metadata_segment_count_exceeds_image";
    case Arm64eFixupsApplyError::invalid_page_size: return "invalid_page_size";
    case Arm64eFixupsApplyError::unsupported_pointer_format: return "unsupported_pointer_format";
    case Arm64eFixupsApplyError::pointer_auth_required: return "pointer_auth_required";
    case Arm64eFixupsApplyError::pointer_auth_failure: return "pointer_auth_failure";
    case Arm64eFixupsApplyError::segment_offset_overflow: return "segment_offset_overflow";
    case Arm64eFixupsApplyError::segment_offset_mismatch: return "segment_offset_mismatch";
    case Arm64eFixupsApplyError::page_count_exceeds_segment: return "page_count_exceeds_segment";
    case Arm64eFixupsApplyError::page_address_overflow: return "page_address_overflow";
    case Arm64eFixupsApplyError::multiple_page_starts_unsupported:
        return "multiple_page_starts_unsupported";
    case Arm64eFixupsApplyError::chain_start_out_of_page: return "chain_start_out_of_page";
    case Arm64eFixupsApplyError::chain_start_out_of_segment:
        return "chain_start_out_of_segment";
    case Arm64eFixupsApplyError::read_failure: return "read_failure";
    case Arm64eFixupsApplyError::write_failure: return "write_failure";
    case Arm64eFixupsApplyError::pointer_reserved_bits: return "pointer_reserved_bits";
    case Arm64eFixupsApplyError::bind_ordinal_out_of_range: return "bind_ordinal_out_of_range";
    case Arm64eFixupsApplyError::library_ordinal_out_of_range:
        return "library_ordinal_out_of_range";
    case Arm64eFixupsApplyError::dependency_unavailable: return "dependency_unavailable";
    case Arm64eFixupsApplyError::unsupported_special_ordinal:
        return "unsupported_special_ordinal";
    case Arm64eFixupsApplyError::symbol_not_found: return "symbol_not_found";
    case Arm64eFixupsApplyError::symbol_resolution_failure: return "symbol_resolution_failure";
    case Arm64eFixupsApplyError::addend_overflow: return "addend_overflow";
    case Arm64eFixupsApplyError::chain_next_out_of_page: return "chain_next_out_of_page";
    case Arm64eFixupsApplyError::chain_next_out_of_segment:
        return "chain_next_out_of_segment";
    case Arm64eFixupsApplyError::fixup_limit: return "fixup_limit";
    case Arm64eFixupsApplyError::rollback_failure: return "rollback_failure";
    }
    return "unknown";
}

} // namespace macosarm::dyld
