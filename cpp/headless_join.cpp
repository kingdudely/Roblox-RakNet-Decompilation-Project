// roblox headless game-join plus raknet transport, all in one file.
//
// the wire side of roblox's udp game protocol, taken apart from scratch: the
// udmux framing, the aead (aes-256-gcm or chacha20-poly1305), the "UniqueNumbeR"
// nonce, the x25519 handshake and the https join flow. run it and it walks from
// cookie to auth ticket to joinScript to ecdh, then it stops.
//
// two pieces aren't done, both marked TODO below. one is the kdf that turns the
// ecdh secret into the real aead key, plus the per-epoch rekey. the other is the
// per-packet security token the server checks. both live in the client and
// aren't pulled out yet. finish those two and everything below is a working
// client.
//
// build: g++ -std=c++17 roblox_headless_join.cpp -lcurl -lcrypto -o rblxjoin
// deps:  openssl, libcurl, nlohmann/json.hpp

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <cctype>
#include <stdexcept>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>

using bytes = std::vector<uint8_t>;
using json  = nlohmann::json;

// ---------------------------------------------------------------- framing --
// layout of every udp payload:
//   01 00 00 <hlen> 01 11 02 <epoch:16> [<mux:8> if 0x1f]
// after that the body is ciphertext || counter_hint(2,le) || tag(16).
// hlen pulls double duty as the direction id. 0x17 is one way, 0x1f the other.
struct Datagram {
    uint8_t direction;
    std::array<uint8_t,16> epoch;
    bytes mux;                       // 8 bytes on 0x1f, empty on 0x17
    bytes ciphertext;
    uint16_t counter_hint;           // low 16 bits of the nonce counter
    std::array<uint8_t,16> tag;
};

Datagram parse_frame(const bytes& p) {
    if (p.size() < 4 || p[0] != 0x01 || p[1] || p[2]) throw std::runtime_error("not udmux");
    uint8_t hlen = p[3];
    if (hlen != 0x17 && hlen != 0x1f)                  throw std::runtime_error("bad direction");
    if (p[4] != 0x01 || p[5] != 0x11 || p[6] != 0x02)  throw std::runtime_error("bad subflags");
    if (p.size() < size_t(hlen) + 18)                  throw std::runtime_error("short body");
    Datagram d;
    d.direction = hlen;
    std::memcpy(d.epoch.data(), &p[7], 16);
    d.mux.assign(p.begin() + 23, p.begin() + hlen);    // empty when hlen==0x17
    size_t end = p.size();
    d.ciphertext.assign(p.begin() + hlen, p.begin() + end - 18);
    d.counter_hint = uint16_t(p[end - 18]) | (uint16_t(p[end - 17]) << 8);
    std::memcpy(d.tag.data(), &p[end - 16], 16);
    return d;
}

// ------------------------------------------------------------------ nonce --
// the nonce is le64(counter) || "mbeR". the counter starts at le64("UniqueNu")
// and goes up by one per packet, counted separately for each direction. the
// wire only carries the low 16 bits, so you rebuild the full counter from the
// last one you saw on that side. at the base counter the nonce spells out
// "UniqueNumbeR", used below as a cheap sanity check.
static const uint64_t COUNTER_BASE = 0x754E657571696E55ULL; // le64("UniqueNu")

std::array<uint8_t,12> nonce_of(uint64_t counter) {
    std::array<uint8_t,12> n;
    for (int i = 0; i < 8; i++) n[i] = uint8_t(counter >> (8 * i));
    std::memcpy(&n[8], "mbeR", 4);
    return n;
}

uint64_t counter_from_hint(uint16_t hint, uint64_t last) {
    uint64_t c = (last & ~0xFFFFULL) | hint;
    if (c + 0x8000 < last)      c += 0x10000;           // hint wrapped forward
    else if (last + 0x8000 < c) c -= 0x10000;
    return c;
}

// ---------------------------------------------------------------- aead ----
enum Cipher { AES_256_GCM, CHACHA20_POLY1305 };         // roblox picks aes when format&2 is set

bytes aead_decrypt(const bytes& key, Cipher c, const Datagram& d, uint64_t counter) {
    auto nonce = nonce_of(counter);
    const EVP_CIPHER* alg = (c == AES_256_GCM) ? EVP_aes_256_gcm() : EVP_chacha20_poly1305();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    bytes out(d.ciphertext.size());
    int len = 0;
    EVP_DecryptInit_ex(ctx, alg, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    EVP_DecryptUpdate(ctx, out.data(), &len, d.ciphertext.data(), int(d.ciphertext.size()));
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)d.tag.data());
    int ok = EVP_DecryptFinal_ex(ctx, out.data() + len, &len);   // 1 only when the tag verifies, and there's no aad
    EVP_CIPHER_CTX_free(ctx);
    if (ok != 1) throw std::runtime_error("aead auth failed: wrong key or epoch");
    return out;
}

// ------------------------------------------------------------- x25519 -----
// the join handout gives you both public halves and a seed, but never a private
// key. so you make your own pair, hand roblox your public half in the join
// request and hang onto the private half here.
struct KeyPair { EVP_PKEY* pkey; bytes pub; };          // pub = 32-byte RakNetEarlyPublicKey

KeyPair gen_x25519() {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY_keygen_init(c);
    EVP_PKEY* k = nullptr;
    EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    bytes pub(32); size_t n = 32;
    EVP_PKEY_get_raw_public_key(k, pub.data(), &n);
    return { k, pub };
}

bytes ecdh(EVP_PKEY* mine, const bytes& peer_pub) {
    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                 peer_pub.data(), peer_pub.size());
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(mine, nullptr);
    EVP_PKEY_derive_init(c);
    EVP_PKEY_derive_set_peer(c, peer);
    size_t n = 0; EVP_PKEY_derive(c, nullptr, &n);
    bytes secret(n); EVP_PKEY_derive(c, secret.data(), &n);
    EVP_PKEY_CTX_free(c); EVP_PKEY_free(peer);
    return secret;                                       // 32-byte shared secret
}

// -------------------------------------------------- the two unfinished bits --
//
// #1. the shared secret is not the aead key by itself. the client runs it
// through a kdf along with RandomSeed1, and then it rekeys on every epoch
// (that's the rotating 16-byte epoch tag). the kdf isn't pulled out yet, so the
// labels, how the seed gets folded in, and how the per-epoch ratchet steps are
// all still unknown. once it's done, this returns {tx_key, rx_key} for a given
// epoch.
std::vector<bytes> derive_aead_keys(const bytes& shared, const bytes& random_seed1,
                                    const std::array<uint8_t,16>& epoch) {
    (void)shared; (void)random_seed1; (void)epoch;
    throw std::runtime_error("derive_aead_keys: KDF not reversed yet");
}

// #2, the anti-tamper token the server wants inline on every packet. the pieces
// it's built from (TokenValue, TokenGenAlgorithm, PepperId) come down in the
// joinScript. the generator that turns them into the actual packet token lives
// in the client and isn't reversed yet. without it the server drops you even if
// your crypto is perfect.
bytes gen_security_token(const json& join_script) {
    (void)join_script;
    throw std::runtime_error("gen_security_token: not reversed yet");
}

// --------------------------------------------------------------- http -----
struct Resp { long status = 0; std::map<std::string,std::string> hdr; std::string body; };

static size_t on_body(char* p, size_t s, size_t n, void* u) {
    ((std::string*)u)->append(p, s * n); return s * n;
}
static size_t on_hdr(char* p, size_t s, size_t n, void* u) {
    std::string line(p, s * n);
    auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string k = line.substr(0, colon), v = line.substr(colon + 1);
        for (auto& ch : k) ch = char(tolower(ch));
        size_t a = v.find_first_not_of(" \t"), b = v.find_last_not_of(" \r\n");
        if (a != std::string::npos) (*(std::map<std::string,std::string>*)u)[k] = v.substr(a, b - a + 1);
    }
    return s * n;
}

Resp http(const std::string& url, const std::vector<std::string>& headers, const std::string& post) {
    CURL* h = curl_easy_init();
    Resp r;
    curl_slist* hl = nullptr;
    for (auto& x : headers) hl = curl_slist_append(hl, x.c_str());
    curl_easy_setopt(h, CURLOPT_URL, url.c_str());
    curl_easy_setopt(h, CURLOPT_POST, 1L);
    curl_easy_setopt(h, CURLOPT_POSTFIELDS, post.c_str());
    curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, long(post.size()));
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &r.body);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, on_hdr);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &r.hdr);
    curl_easy_perform(h);
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &r.status);
    curl_slist_free_all(hl);
    curl_easy_cleanup(h);
    return r;
}

// -------------------------------------------------------------- base64 ----
std::string b64enc(const bytes& b) {
    std::string out(4 * ((b.size() + 2) / 3), '\0');
    int n = EVP_EncodeBlock((unsigned char*)out.data(), b.data(), int(b.size()));
    out.resize(n); return out;
}
bytes b64dec(const std::string& s) {
    bytes out(s.size() / 4 * 3);
    int n = EVP_DecodeBlock(out.data(), (const unsigned char*)s.data(), int(s.size()));
    if (n < 0) throw std::runtime_error("bad base64");
    int pad = (!s.empty() && s.back() == '=') + (s.size() > 1 && s[s.size() - 2] == '=');
    out.resize(n - pad); return out;
}

// --------------------------------------------- cookie -> ticket -> join ----
// any state-changing post needs an x-csrf-token. fire an empty-body post, it
// 403s and hands the token back in a header. grab it there and reuse it.
std::string csrf(const std::string& cookie) {
    Resp r = http("https://auth.roblox.com/v1/authentication-ticket/",
                  { "Cookie: .ROBLOSECURITY=" + cookie }, "");
    return r.hdr.count("x-csrf-token") ? r.hdr["x-csrf-token"] : "";
}

// this grabs a one-time redemption ticket. it comes back in a response header
// and the body is empty.
std::string auth_ticket(const std::string& cookie, const std::string& tok) {
    Resp r = http("https://auth.roblox.com/v1/authentication-ticket/",
                  { "Cookie: .ROBLOSECURITY=" + cookie, "X-CSRF-TOKEN: " + tok,
                    "RBXAuthenticationNegotiation: 1", "Referer: https://www.roblox.com/" }, "");
    if (!r.hdr.count("rbx-authentication-ticket")) throw std::runtime_error("no auth ticket");
    return r.hdr["rbx-authentication-ticket"];
}

// wraps the public half the same way the real client sends it up.
std::string client_pub_data(const std::string& pub_b64) {
    json app = { {"versions", { {{"id",2},{"value",pub_b64},{"allowed",true}} }},
                 {"send",2}, {"revert",2} };
    return json{ {"applications", {{"RakNetEarlyPublicKey", app}}} }.dump();
}

// the actual join call. the response carries the joinScript to connect with,
// which has UdmuxEndpoints, ClientTicket, EphemeralEarlyPubKey, RandomSeed1 and
// the token fields. the request body here is bare bones; a real teleport sends
// more than this.
json join_game(const std::string& cookie, const std::string& tok,
               const std::string& ticket, long placeId, const std::string& pub_b64) {
    json body = { {"placeId", placeId}, {"isTeleport", false},
                  {"ClientPublicKeyData", client_pub_data(pub_b64)} };
    Resp r = http("https://gamejoin.roblox.com/v1/join-game",
                  { "Cookie: .ROBLOSECURITY=" + cookie, "X-CSRF-TOKEN: " + tok,
                    "RBX-Authentication-Ticket: " + ticket, "Content-Type: application/json" },
                  body.dump());
    json j = json::parse(r.body);
    return j.contains("joinScript") ? j["joinScript"] : j;
}

// ---------------------------------------------------------------- main ----
void selftest() {
    auto n = nonce_of(COUNTER_BASE);
    if (std::memcmp(n.data(), "UniqueNumbeR", 12) != 0)
        throw std::runtime_error("nonce selftest failed");
}

int main(int argc, char** argv) {
    selftest();
    const char* cookie = getenv("ROBLOSECURITY");
    if (!cookie) { fprintf(stderr, "set ROBLOSECURITY env var\n"); return 2; }
    long placeId = argc > 1 ? atol(argv[1]) : 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    KeyPair kp = gen_x25519();
    std::string tok    = csrf(cookie);
    std::string ticket = auth_ticket(cookie, tok);
    json js = join_game(cookie, tok, ticket, placeId, b64enc(kp.pub));

    bytes peer   = b64dec(js.at("EphemeralEarlyPubKey").get<std::string>());
    bytes shared = ecdh(kp.pkey, peer);
    bytes seed   = b64dec(js.at("RandomSeed1").get<std::string>());
    printf("ecdh ok, %zu-byte shared secret. udmux endpoint: %s\n",
           shared.size(), js["UdmuxEndpoints"][0].dump().c_str());

    // everything above this works. the next line is the first of the two TODOs.
    std::array<uint8_t,16> epoch{};                      // the real epoch comes off the first datagram you see
    auto keys = derive_aead_keys(shared, seed, epoch);   // throws until the kdf is reversed

    // if those two TODOs were done, the rest would go like this. you udp-connect
    // to one of the UdmuxEndpoints, run the raknet offline handshake, then submit
    // js["ClientTicket"] via ID_SUBMIT_TICKET(0x8a) together with the token from
    // gen_security_token(js). after that every packet that comes in is just
    //   aead_decrypt(keys[dir], AES_256_GCM, parse_frame(pkt), counter)
    // and you track counter per direction with counter_from_hint.
    (void)keys;
    return 0;
}
