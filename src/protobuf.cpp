#include "wraith.h"
#include <stdexcept>
#include <cstring>

namespace wraith::pb {

// ==== Encoder ====
void Enc::varint(uint64_t v) {
    while (v >= 0x80) { d_.push_back(uint8_t(v | 0x80)); v >>= 7; }
    d_.push_back(uint8_t(v));
}
void Enc::tag(uint32_t fn, Wire w)  { varint((uint64_t(fn) << 3) | w); }
void Enc::str(uint32_t fn, const std::string& s) {
    if (s.empty()) return;
    tag(fn, W_LEN); varint(s.size());
    d_.insert(d_.end(), s.begin(), s.end());
}
void Enc::bytes(uint32_t fn, const uint8_t* p, size_t n) {
    if (!n) return;
    tag(fn, W_LEN); varint(n);
    d_.insert(d_.end(), p, p + n);
}
void Enc::bytes(uint32_t fn, const std::vector<uint8_t>& v) { bytes(fn, v.data(), v.size()); }
void Enc::u32(uint32_t fn, uint32_t v) { if (!v) return; tag(fn, W_VARINT); varint(v); }
void Enc::u64(uint32_t fn, uint64_t v) { if (!v) return; tag(fn, W_VARINT); varint(v); }
void Enc::b(uint32_t fn, bool v) { if (!v) return; tag(fn, W_VARINT); d_.push_back(1); }
void Enc::sub(uint32_t fn, const Enc& e) {
    if (!e.size()) return;
    tag(fn, W_LEN); varint(e.size());
    d_.insert(d_.end(), e.buf().begin(), e.buf().end());
}
void Enc::packed_u32(uint32_t fn, const std::vector<uint32_t>& vs) {
    if (vs.empty()) return;
    Enc tmp; for (auto v : vs) tmp.varint(v);
    tag(fn, W_LEN); varint(tmp.size());
    d_.insert(d_.end(), tmp.buf().begin(), tmp.buf().end());
}
void Enc::map_ss(uint32_t fn, const std::string& k, const std::string& v) {
    Enc e; e.str(1, k); e.str(2, v); sub(fn, e);
}

// ==== Decoder ====
bool Dec::next(uint32_t& fn, Wire& w) {
    if (!more()) return false;
    auto t = varint();
    w = Wire(t & 7); fn = uint32_t(t >> 3);
    return true;
}
uint64_t Dec::varint() {
    uint64_t r = 0; int s = 0;
    while (o_ < n_) {
        uint8_t c = p_[o_++];
        r |= uint64_t(c & 0x7F) << s;
        if (!(c & 0x80)) return r;
        s += 7;
    }
    return r;
}
std::string Dec::str() {
    auto len = varint();
    if (o_ + len > n_) throw std::runtime_error("trunc str");
    std::string r((const char*)p_ + o_, len);
    o_ += len; return r;
}
std::vector<uint8_t> Dec::bytes() {
    auto len = varint();
    if (o_ + len > n_) throw std::runtime_error("trunc bytes");
    std::vector<uint8_t> r(p_ + o_, p_ + o_ + len);
    o_ += len; return r;
}
Dec Dec::submsg() {
    auto len = varint();
    if (o_ + len > n_) throw std::runtime_error("trunc sub");
    Dec d(p_ + o_, len); o_ += len; return d;
}
void Dec::skip(Wire w) {
    switch (w) {
        case W_VARINT: varint(); break;
        case W_64: o_ += 8; break;
        case W_LEN: { auto l = varint(); o_ += l; } break;
        case W_32: o_ += 4; break;
    }
}

// ==== High-level builders ====
static Enc enc_app(const AppInfo& a) {
    Enc e; e.str(F::App::id, a.id); e.str(F::App::version_name, a.version); return e;
}
static Enc enc_os(const OSInfo& o) {
    // vanguard.OSInfo (serializer @ sub_5647DBD20):
    //   field 1: varint (os_type, only if non-zero)
    //   field 2: varint (os_build, only if non-zero)
    //   field 3: string (variant)
    //   field 4: string (version)
    Enc e;
    if (o.os_type) e.u32(F::OS::field1_varint, o.os_type);
    if (o.os_build) e.u32(F::OS::field2_varint, o.os_build);
    e.str(F::OS::variant, o.variant);
    e.str(F::OS::version, o.version);
    return e;
}
static Enc enc_ver(const VersionInfo& v) {
    // vanguard.Version (serializer @ sub_5647E0570): only write non-zero fields (proto3)
    Enc e;
    if (v.major) e.u32(1, v.major);
    if (v.minor) e.u32(2, v.minor);
    if (v.patch) e.u32(3, v.patch);
    if (v.build) e.u32(4, v.build);
    return e;
}
static Enc enc_dev(const DevInfo& d) {
    // vanguard.DeviceInfo (parser @ sub_5647E9D00): ONLY map<string,string> at field 1
    Enc e;
    for (auto& [k, v] : d.info) e.map_ss(F::Dev::info_map, k, v);
    return e;
}

std::vector<uint8_t> auth_request(const AuthParams& p)
{
    Enc e;
    // Field 1: machine_id
    e.str(F::Auth::machine_id, p.machine_id);
    // Field 2: os_info (vanguard.OSInfo submessage)
    auto osi = enc_os(p.os); e.sub(F::Auth::os_info, osi);
    // Field 3: platform (varint, 1=Windows)
    e.u32(F::Auth::platform, p.platform);
    // Field 4: game_token (RSO access token)
    e.str(F::Auth::game_token, p.game_token);
    // Field 5: client_rsa_public_key
    e.str(F::Auth::client_rsa_pub, p.client_rsa_pub);
    // Field 6: client_version (vanguard.Version)
    auto cv = enc_ver(p.client_ver); e.sub(F::Auth::client_version, cv);
    // Field 7: game_version (vanguard.Version)
    auto gv = enc_ver(p.game_ver); e.sub(F::Auth::game_version, gv);
    // Field 8: game_id
    e.str(F::Auth::game_id, p.game_id);
    // Field 9: request type / capability flags (real client always sets non-zero)
    e.u32(F::Auth::field9, p.field9);
    // Field 10: ephemeral_identifiers (repeated string — NOT attestation)
    // Real VGC iterates a string list; send individual strings if provided
    for (auto& eid : p.ephemeral_ids) e.str(F::Auth::ephemeral_ids, eid);
    // Field 11: app_info (vanguard.AppInfo)
    auto ai = enc_app(p.app); e.sub(F::Auth::app_info, ai);
    // Field 12: device_info
    auto di = enc_dev(p.dev); e.sub(F::Auth::device_info, di);
    // Field 13: external_sid
    if (!p.session_id.empty()) e.str(F::Auth::session_id, p.session_id);
    // Field 14: flags map<string, string>
    for (auto& [k, v] : p.flags) e.map_ss(F::Auth::flags, k, v);
    // Field 15: metadata map<string, string>
    for (auto& [k, v] : p.metadata) e.map_ss(F::Auth::metadata, k, v);
    return {e.buf().begin(), e.buf().end()};
}

std::vector<uint8_t> wrap_envelope(const std::vector<uint8_t>& body,
    EnvMsgType type, uint32_t version)
{
    Enc e;
    // Field 1: msg_type (varint) — envelope message type
    e.u32(F::Env::msg_type, (uint32_t)type);
    // Field 2: body (LEN) — serialized inner message
    e.bytes(F::Env::body, body);
    // Field 3: version (varint) — protocol version
    e.u32(F::Env::version, version);
    return {e.buf().begin(), e.buf().end()};
}

std::vector<uint8_t> heartbeat_request(const std::string& tok, uint64_t ts,
    const std::vector<uint32_t>& tasks)
{
    Enc e;
    e.str(F::HBReq::access_token, tok);
    e.u64(F::HBReq::timestamp, ts);
    e.packed_u32(F::HBReq::active_tasks, tasks);
    return {e.buf().begin(), e.buf().end()};
}

std::vector<uint8_t> disconnect_request(const std::string& tok, const std::string& reason) {
    Enc e; e.str(1, tok); if (!reason.empty()) e.str(2, reason);
    return {e.buf().begin(), e.buf().end()};
}

// ==== Parsers ====
static void parse_map(Dec& d, std::map<std::string,std::string>& m) {
    auto s = d.submsg();
    std::string k, v;
    while (s.more()) {
        uint32_t fn; Wire w;
        if (!s.next(fn, w)) break;
        if (fn == 1) k = s.str(); else if (fn == 2) v = s.str(); else s.skip(w);
    }
    if (!k.empty()) m[k] = v;
}

std::optional<TokenResp> parse_token(const std::vector<uint8_t>& data) {
    try {
        Dec d(data); TokenResp r;
        while (d.more()) {
            uint32_t fn; Wire w;
            if (!d.next(fn, w)) break;
            switch (fn) {
                case F::TokResp::token:       r.token = d.str(); break;
                case F::TokResp::exp:         r.exp = d.varint(); break;
                case F::TokResp::server_rsa_pub: r.server_rsa = d.str(); break;
                case F::TokResp::session_id:  r.session_id = d.str(); break;
                case F::TokResp::feature_flags: parse_map(d, r.flags); break;
                case F::TokResp::config:      parse_map(d, r.config); break;
                default: d.skip(w); break;
            }
        }
        if (r.token.empty()) return std::nullopt;
        return r;
    } catch (...) { return std::nullopt; }
}

std::optional<HBResp> parse_hb(const std::vector<uint8_t>& data) {
    try {
        Dec d(data); HBResp r;
        while (d.more()) {
            uint32_t fn; Wire w;
            if (!d.next(fn, w)) break;
            switch (fn) {
                case 1: r.interval = (uint32_t)d.varint(); break;
                case 2: {
                    if (w == W_LEN) {
                        auto s = d.submsg();
                        while (s.more()) r.tasks.push_back((uint32_t)s.varint());
                    } else r.tasks.push_back((uint32_t)d.varint());
                    break;
                }
                default: d.skip(w); break;
            }
        }
        return r;
    } catch (...) { return std::nullopt; }
}

} // namespace wraith::pb
