#pragma once

// tiny assert harness: one macro, fails loud with file:line, counts checks

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rbxtest {

// capture the corpus tests read, one hex UDP payload per line. not shipped, so
// point it at your own, or pass a path as argv[1]:
//   build/test_frame.exe path/to/capture.hex
inline constexpr const char* default_capture = "capture.hex";

inline int& check_count() {
    static int count = 0;
    return count;
}

// whitespace off both ends
inline std::string trim(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return s.substr(b, e - b);
}

inline void require(bool condition, std::string_view expr, const char* file, int line) {
    ++check_count();
    if (!condition) {
        std::cerr << "FAIL " << file << ':' << line << "  " << expr << '\n';
        std::exit(1);
    }
}

// hex to bytes. nullopt on odd length or a bad digit, so a mangled capture line
// fails loud instead of parsing to junk
inline std::optional<std::vector<std::byte>> from_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<std::byte>((hi << 4) | lo));
    }
    return out;
}

}  // namespace rbxtest

#define REQUIRE(cond) ::rbxtest::require((cond), #cond, __FILE__, __LINE__)
