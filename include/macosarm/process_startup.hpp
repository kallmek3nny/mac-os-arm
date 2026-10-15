#pragma once

#include "macosarm/address_space.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

namespace macosarm {

struct ProcessStartupConfig {
    std::span<const std::string_view> arguments{};
    std::span<const std::string_view> environment{};
    std::span<const std::string_view> apple{};
    std::size_t max_entries{4096};
    std::uint64_t max_string_bytes{1024ULL * 1024ULL};
};

enum class ProcessStartupError {
    none,
    invalid_stack_range,
    entry_limit,
    string_bytes_limit,
    embedded_nul,
    address_overflow,
    insufficient_stack,
    stack_not_writable,
    memory_failure,
};

struct ProcessStartupLayout {
    std::uint64_t stack_base{};
    std::uint64_t stack_top{};
    std::uint64_t stack_pointer{};
    std::uint64_t argc{};
    std::uint64_t argv{};
    std::uint64_t envp{};
    std::uint64_t apple{};
    std::uint64_t string_bytes{};
    std::uint64_t bytes_used{};
};

struct ProcessStartupResult {
    ProcessStartupError error{ProcessStartupError::none};
    ProcessStartupLayout layout{};
    VmError vm_error{VmError::none};
    std::size_t failed_entry_index{std::numeric_limits<std::size_t>::max()};

    [[nodiscard]] explicit operator bool() const noexcept {
        return error == ProcessStartupError::none;
    }
};

namespace process_startup_detail {

[[nodiscard]] inline bool checked_add_u64(
    std::uint64_t lhs,
    std::uint64_t rhs,
    std::uint64_t& result) noexcept {
    if (rhs > std::numeric_limits<std::uint64_t>::max() - lhs) {
        return false;
    }
    result = lhs + rhs;
    return true;
}

[[nodiscard]] inline bool checked_add_size(
    std::size_t lhs,
    std::size_t rhs,
    std::size_t& result) noexcept {
    if (rhs > std::numeric_limits<std::size_t>::max() - lhs) {
        return false;
    }
    result = lhs + rhs;
    return true;
}

[[nodiscard]] inline bool writable_range(
    const GuestAddressSpace& address_space,
    std::uint64_t base,
    std::uint64_t size) {
    for (const Mapping& mapping : address_space.mappings()) {
        if (base < mapping.base || !has_protection(mapping.protection, Protection::write)) {
            continue;
        }
        const std::uint64_t offset = base - mapping.base;
        if (offset <= mapping.size && size <= mapping.size - offset) {
            return true;
        }
    }
    return false;
}

inline void encode_u64(
    std::vector<std::byte>& bytes,
    std::size_t offset,
    std::uint64_t value) {
    for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
        bytes.at(offset + index) =
            static_cast<std::byte>((value >> (index * 8U)) & 0xffU);
    }
}

} // namespace process_startup_detail

[[nodiscard]] inline ProcessStartupResult build_process_startup(
    GuestAddressSpace& address_space,
    std::uint64_t stack_base,
    std::uint64_t stack_size,
    const ProcessStartupConfig& config = {}) {
    ProcessStartupResult result;
    if (stack_size == 0) {
        result.error = ProcessStartupError::invalid_stack_range;
        return result;
    }

    std::uint64_t stack_top = 0;
    if (!process_startup_detail::checked_add_u64(stack_base, stack_size, stack_top)) {
        result.error = ProcessStartupError::address_overflow;
        return result;
    }

    std::size_t total_entries = 0;
    if (!process_startup_detail::checked_add_size(
            config.arguments.size(), config.environment.size(), total_entries) ||
        !process_startup_detail::checked_add_size(
            total_entries, config.apple.size(), total_entries)) {
        result.error = ProcessStartupError::entry_limit;
        return result;
    }
    if (total_entries > config.max_entries) {
        result.error = ProcessStartupError::entry_limit;
        return result;
    }

    std::uint64_t string_bytes = 0;
    std::size_t global_entry_index = 0;
    const auto account_strings = [&](std::span<const std::string_view> values) -> bool {
        for (const std::string_view value : values) {
            if (value.find('\0') != std::string_view::npos) {
                result.error = ProcessStartupError::embedded_nul;
                result.failed_entry_index = global_entry_index;
                return false;
            }
            const std::uint64_t length = static_cast<std::uint64_t>(value.size());
            std::uint64_t with_nul = 0;
            if (!process_startup_detail::checked_add_u64(length, 1, with_nul) ||
                !process_startup_detail::checked_add_u64(
                    string_bytes, with_nul, string_bytes)) {
                result.error = ProcessStartupError::address_overflow;
                result.failed_entry_index = global_entry_index;
                return false;
            }
            if (string_bytes > config.max_string_bytes) {
                result.error = ProcessStartupError::string_bytes_limit;
                result.failed_entry_index = global_entry_index;
                return false;
            }
            ++global_entry_index;
        }
        return true;
    };
    if (!account_strings(config.arguments) ||
        !account_strings(config.environment) ||
        !account_strings(config.apple)) {
        return result;
    }

    std::size_t table_words = 0;
    if (!process_startup_detail::checked_add_size(total_entries, 4, table_words) ||
        table_words > std::numeric_limits<std::size_t>::max() / sizeof(std::uint64_t)) {
        result.error = ProcessStartupError::entry_limit;
        return result;
    }
    const std::size_t table_bytes_size = table_words * sizeof(std::uint64_t);
    const std::uint64_t table_bytes = static_cast<std::uint64_t>(table_bytes_size);

    if (string_bytes > stack_size) {
        result.error = ProcessStartupError::insufficient_stack;
        return result;
    }
    const std::uint64_t strings_start = stack_top - string_bytes;
    if (table_bytes > strings_start - stack_base) {
        result.error = ProcessStartupError::insufficient_stack;
        return result;
    }

    const std::uint64_t unaligned_stack_pointer = strings_start - table_bytes;
    const std::uint64_t stack_pointer = unaligned_stack_pointer & ~std::uint64_t{0xf};
    if (stack_pointer < stack_base) {
        result.error = ProcessStartupError::insufficient_stack;
        return result;
    }
    const std::uint64_t bytes_used = stack_top - stack_pointer;
    if (bytes_used > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        result.error = ProcessStartupError::address_overflow;
        return result;
    }

    if (!process_startup_detail::writable_range(
            address_space, stack_pointer, bytes_used)) {
        result.error = ProcessStartupError::stack_not_writable;
        result.vm_error = VmError::protection;
        return result;
    }

    result.layout.stack_base = stack_base;
    result.layout.stack_top = stack_top;
    result.layout.stack_pointer = stack_pointer;
    result.layout.argc = static_cast<std::uint64_t>(config.arguments.size());
    result.layout.argv = stack_pointer + sizeof(std::uint64_t);
    result.layout.envp = result.layout.argv +
        static_cast<std::uint64_t>(config.arguments.size() + 1) * sizeof(std::uint64_t);
    result.layout.apple = result.layout.envp +
        static_cast<std::uint64_t>(config.environment.size() + 1) * sizeof(std::uint64_t);
    result.layout.string_bytes = string_bytes;
    result.layout.bytes_used = bytes_used;

    std::vector<std::byte> image(static_cast<std::size_t>(bytes_used), std::byte{0});
    std::size_t table_offset = 0;
    process_startup_detail::encode_u64(image, table_offset, result.layout.argc);
    table_offset += sizeof(std::uint64_t);

    std::uint64_t string_address = strings_start;
    const std::size_t string_image_base = static_cast<std::size_t>(strings_start - stack_pointer);
    std::size_t string_image_offset = string_image_base;
    const auto append_vector = [&](std::span<const std::string_view> values) {
        for (const std::string_view value : values) {
            process_startup_detail::encode_u64(image, table_offset, string_address);
            table_offset += sizeof(std::uint64_t);
            for (char character : value) {
                image.at(string_image_offset++) =
                    static_cast<std::byte>(static_cast<unsigned char>(character));
            }
            image.at(string_image_offset++) = std::byte{0};
            string_address += static_cast<std::uint64_t>(value.size()) + 1;
        }
        process_startup_detail::encode_u64(image, table_offset, 0);
        table_offset += sizeof(std::uint64_t);
    };

    append_vector(config.arguments);
    append_vector(config.environment);
    append_vector(config.apple);

    const VmResult written = address_space.write(stack_pointer, image);
    if (!written) {
        result.error = ProcessStartupError::memory_failure;
        result.vm_error = written.error;
        result.layout = {};
        return result;
    }
    return result;
}

[[nodiscard]] inline std::string_view process_startup_error_name(
    ProcessStartupError error) noexcept {
    switch (error) {
    case ProcessStartupError::none: return "none";
    case ProcessStartupError::invalid_stack_range: return "invalid_stack_range";
    case ProcessStartupError::entry_limit: return "entry_limit";
    case ProcessStartupError::string_bytes_limit: return "string_bytes_limit";
    case ProcessStartupError::embedded_nul: return "embedded_nul";
    case ProcessStartupError::address_overflow: return "address_overflow";
    case ProcessStartupError::insufficient_stack: return "insufficient_stack";
    case ProcessStartupError::stack_not_writable: return "stack_not_writable";
    case ProcessStartupError::memory_failure: return "memory_failure";
    }
    return "unknown";
}

} // namespace macosarm
