// the outer-framing codec has to be lossless: serialize(parse(payload)) must
// come back byte-identical for every captured payload, which is what proves the
// framing model drops no field.
// run: test_roundtrip [optional_capture.hex]

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "rbxraknet/datagram.hpp"
#include "support.hpp"

using namespace rbxraknet;

namespace {

// on mismatch, name the payload and the first bad offsets so it points at the
// dropped field
void report_diff(std::size_t index, const std::vector<std::byte>& want,
                 const std::vector<std::byte>& got) {
    std::cerr << "round-trip MISMATCH at payload #" << index << ": original "
              << want.size() << " B, serialize " << got.size() << " B\n";
    const std::size_t n = std::min(want.size(), got.size());
    int shown = 0;
    for (std::size_t i = 0; i < n && shown < 8; ++i) {
        if (want[i] != got[i]) {
            std::cerr << "  offset " << i << ": original 0x" << std::hex
                      << static_cast<int>(want[i]) << " != serialize 0x"
                      << static_cast<int>(got[i]) << std::dec << '\n';
            ++shown;
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : rbxtest::default_capture;
    std::ifstream in(path);
    if (!in) {
        std::cerr << "capture not found: " << path << '\n'
                  << "pass the path as argv[1]; this test needs the real capture.\n";
        return 2;
    }

    std::size_t checked = 0;
    std::string line;
    while (std::getline(in, line)) {
        const std::string h = rbxtest::trim(line);
        if (h.empty()) continue;

        auto bytes = rbxtest::from_hex(h);
        REQUIRE(bytes.has_value());

        auto dg = Datagram::parse(*bytes);
        REQUIRE(dg.has_value());

        const std::vector<std::byte> wire = dg->serialize();
        if (wire != *bytes) {
            report_diff(checked, *bytes, wire);  // print before failing
        }
        REQUIRE(wire == *bytes);
        ++checked;
    }

    // pinned so an empty loop cannot pass as success
    REQUIRE(checked == 16797);

    std::cout << "test_roundtrip: " << rbxtest::check_count() << " checks passed\n"
              << "  payloads round-tripped byte-identical : " << checked << " / 16797\n";
    return 0;
}
