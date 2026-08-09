// parses the real 16,797-datagram capture and asserts every invariant in
// PROVENANCE.md. run: test_frame [optional_capture.hex], defaults to the
// live_game.hex the framing came from

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

#include "rbxraknet/datagram.hpp"
#include "rbxraknet/session.hpp"
#include "support.hpp"

using namespace rbxraknet;

namespace {

void unit_checks() {
    // junk in has to give a typed error, never a half-built Datagram
    const std::byte one{0x01};
    std::vector<std::byte> empty;
    REQUIRE(Datagram::parse(empty).error() == FrameError::too_short);

    std::vector<std::byte> bad_flag = {std::byte{0x02}, std::byte{0}, std::byte{0}, std::byte{0x1f}};
    bad_flag.resize(40);
    REQUIRE(Datagram::parse(bad_flag).error() == FrameError::not_rupp_flag);

    std::vector<std::byte> huge_len = {one, std::byte{0}, std::byte{0}, std::byte{0xff}};
    huge_len.resize(10);
    REQUIRE(Datagram::parse(huge_len).error() == FrameError::implausible_header_len);
}

}  // namespace

int main(int argc, char** argv) {
    unit_checks();

    const std::string path = argc > 1 ? argv[1] : rbxtest::default_capture;
    std::ifstream in(path);
    if (!in) {
        std::cerr << "capture not found: " << path << '\n'
                  << "pass the path as argv[1]; this test needs the real capture.\n";
        return 2;
    }

    std::size_t parsed = 0;
    std::size_t dir_1f = 0, dir_17 = 0;
    std::set<std::string> epoch_tags;

    // per-direction wire counter monotonicity (matches the raknet_frame.py metric)
    std::uint16_t prev_hint[2] = {0, 0};
    bool have_prev[2] = {false, false};
    long inorder[2] = {0, 0}, other[2] = {0, 0};
    auto slot = [](Direction d) { return d == Direction::d1f ? 0 : 1; };

    // session reconstruction: same-epoch steps should be nearly all +/-1
    Session session;
    long same_epoch_pm1[2] = {0, 0}, same_epoch_other[2] = {0, 0};
    long boundaries[2] = {0, 0};

    std::string line;
    bool checked_first = false;
    while (std::getline(in, line)) {
        const std::string h = rbxtest::trim(line);
        if (h.empty()) continue;

        auto bytes = rbxtest::from_hex(h);
        REQUIRE(bytes.has_value());

        auto dg = Datagram::parse(*bytes);
        REQUIRE(dg.has_value());
        const Datagram& d = *dg;
        ++parsed;

        REQUIRE(d.flag() == std::byte{0x01});
        REQUIRE(d.direction() == Direction::d1f || d.direction() == Direction::d17);
        // byte[3] is also header_len, so the header describes itself
        REQUIRE(d.header_len() == static_cast<std::uint32_t>(d.direction()));

        // sub-flags are always 01 11 02
        const auto& raw = *bytes;
        REQUIRE(raw[4] == std::byte{0x01} && raw[5] == std::byte{0x11} && raw[6] == std::byte{0x02});

        // AEAD body self-consistency: body == ciphertext || counter(2) || tag(16)
        REQUIRE(d.aead_body().size() == d.ciphertext().size() + Datagram::aead_trailer);
        REQUIRE(d.tag().size() == 16);

        epoch_tags.insert(std::string(reinterpret_cast<const char*>(d.epoch_tag().data()), 16));

        if (d.direction() == Direction::d1f) {
            ++dir_1f;
            // 8 bytes of mux-extra, first 6 are the stable prefix
            REQUIRE(d.mux_extra().size() == 8);
            const std::byte prefix[6] = {std::byte{0x02}, std::byte{0x06}, std::byte{0x0a},
                                         std::byte{0xdd}, std::byte{0x2c}, std::byte{0xd2}};
            for (int i = 0; i < 6; ++i) REQUIRE(d.mux_extra()[i] == prefix[i]);
        } else {
            ++dir_17;
            REQUIRE(d.mux_extra().empty());
        }

        // golden vector from raknet_frame.py
        if (!checked_first) {
            checked_first = true;
            REQUIRE(d.direction() == Direction::d1f);
            REQUIRE(d.header_len() == 31);
            REQUIRE(d.counter_hint() == 50476);
        }

        const int s = slot(d.direction());
        if (have_prev[s]) {
            const std::uint16_t delta = static_cast<std::uint16_t>(d.counter_hint() - prev_hint[s]);
            if (delta == 0 || delta == 1 || delta == 0xFFFF) ++inorder[s];
            else ++other[s];
        }
        prev_hint[s] = d.counter_hint();
        have_prev[s] = true;

        const Observation obs = session.observe(d);
        if (obs.epoch_boundary) {
            ++boundaries[s];
        } else {
            // delta 0 is a retransmit, still in-order, same as the wire metric
            if (obs.counter_delta >= -1 && obs.counter_delta <= 1) ++same_epoch_pm1[s];
            else ++same_epoch_other[s];
        }
    }

    REQUIRE(parsed == 16797);
    REQUIRE(dir_1f == 8904);
    REQUIRE(dir_17 == 7893);
    REQUIRE(epoch_tags.size() == 25);

    for (int s = 0; s < 2; ++s) {
        const long tot = inorder[s] + other[s];
        REQUIRE(tot > 0);
        const double frac = static_cast<double>(inorder[s]) / static_cast<double>(tot);
        REQUIRE(frac >= 0.97);

        // inside an epoch the counter steps +/-1 more often than on the raw wire
        // (0x17: 99.18% vs 98.52%). the residual ~64 same-epoch 0x17 jumps are
        // capture retransmission: blocks re-sent ~9x, and the loop wrap steps the
        // counter back. see PROVENANCE.md and analyze_0x17_counter.py
        REQUIRE(boundaries[s] > 0);
        const long se_tot = same_epoch_pm1[s] + same_epoch_other[s];
        REQUIRE(se_tot > 0);
        const double se_frac = static_cast<double>(same_epoch_pm1[s]) / static_cast<double>(se_tot);
        REQUIRE(se_frac >= 0.99);
    }

    std::cout << "test_frame: " << rbxtest::check_count() << " checks passed\n"
              << "  datagrams parsed : " << parsed << " (0x1f=" << dir_1f << ", 0x17=" << dir_17 << ")\n"
              << "  distinct epochs  : " << epoch_tags.size() << '\n'
              << "  wire counter |d|<=1 : 0x1f=" << (100.0 * inorder[0] / (inorder[0] + other[0]))
              << "%, 0x17=" << (100.0 * inorder[1] / (inorder[1] + other[1])) << "%\n"
              << "  epoch boundaries : 0x1f=" << boundaries[0] << ", 0x17=" << boundaries[1] << '\n';
    return 0;
}
