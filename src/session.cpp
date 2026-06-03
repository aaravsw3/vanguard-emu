#include "wraith.h"
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

namespace wraith {

// ============================================================================
// Session orchestrator — the full VGC lifecycle
// ============================================================================

class SessionImpl {
public:
    SessionImpl(Config cfg, DevInfo dev, AppInfo app)
        : cfg_(std::move(cfg)), dev_(std::move(dev)), app_(std::move(app))
    {
        // machine_id is in the DevInfo map but also needed standalone
        machine_id_ = fp::machine_id();
        // OSInfo is a separate top-level field in AuthenticationRequest
        os_ = {};
        os_.variant = "Windows";
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            using Fn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
            auto fn = (Fn)GetProcAddress(ntdll, "RtlGetVersion");
            if (fn) {
                RTL_OSVERSIONINFOW v{}; v.dwOSVersionInfoSize = sizeof(v);
                if (fn(&v) == 0) {
                    os_.version = std::to_string(v.dwMajorVersion) + "." +
                                  std::to_string(v.dwMinorVersion) + "." +
                                  std::to_string(v.dwBuildNumber);
                    os_.os_type = v.dwMajorVersion;
                    os_.os_build = v.dwBuildNumber;
                }
            }
        }
    }

    bool run() {
        // Phase 0: Silence real VGC
        LINF(" Phase 0: Silence ");
        stealth::kill_vgc();

        // Phase 1: Manifest
        LINF(" Phase 1: Manifest ");
        stealth::spoof_process_name(L"C:\\Program Files\\Riot Vanguard\\vgc.exe");
        stealth::hide_console_window();

        if (cfg_.pipe_name.empty())
            cfg_.pipe_name = stealth::generate_pipe_name();
        LINF("Pipe name: %s", cfg_.pipe_name.c_str());

        // Start pipe server
        pipe_ = std::make_unique<pipe::Server>(cfg_.pipe_name);
        pipe_->on_msg([this](uint32_t cid, const pipe::Msg& m) { on_pipe(cid, m); });
        pipe_->start();

        // Init gateway
        gw_ = std::make_unique<gw::Client>(cfg_);

        // Phase 2: Authenticate
        LINF(" Phase 2: Authenticate ");
        if (!authenticate()) {
            LERR("Authentication failed. Cannot proceed.");
            return false;
        }

        // Phase 3: Launch game
        if (!cfg_.no_launch) {
            LINF(" Phase 3: Launch ");
            auto paths = launch::detect_paths();
            if (!launch::start_valorant(paths)) {
                LWRN("Could not launch Valorant. Continuing in headless mode.");
                LWRN("You can launch Valorant manually — the pipe server is running.");
            }
        } else {
            LINF(" Phase 3: Skipped (--no-launch) ");
        }

        // Phase 4: Session loop
        LINF(" Phase 4: Session Active ");
        LINF("Heartbeat every %u ms. Press Ctrl+C to stop.", cfg_.heartbeat_ms);

        hb_thread_ = std::thread(&SessionImpl::heartbeat_loop, this);

        // Wait for shutdown signal or game exit
        if (!cfg_.no_launch) {
            // Monitor game process in background
            std::thread game_mon([this]() {
                launch::wait_for_game_exit(0);
                LINF("Game exited — shutting down session");
                sess_.alive = false;
            });
            game_mon.detach();
        }

        // Block until session ends
        while (sess_.alive) Sleep(500);

        // Phase 5: Vanish
        LINF(" Phase 5: Vanish ");
        shutdown();
        return true;
    }

    void signal_stop() { sess_.alive = false; }

private:
    // Build ASN.1 DER length encoding
    static void der_len(std::vector<uint8_t>& out, size_t len) {
        if (len < 0x80) { out.push_back((uint8_t)len); }
        else if (len < 0x100) { out.push_back(0x81); out.push_back((uint8_t)len); }
        else { out.push_back(0x82); out.push_back((uint8_t)(len >> 8)); out.push_back((uint8_t)len); }
    }
    // Build ASN.1 DER INTEGER from unsigned big-endian bytes
    static std::vector<uint8_t> der_uint(const uint8_t* data, size_t len) {
        std::vector<uint8_t> r;
        bool need_pad = (data[0] & 0x80) != 0;
        size_t total = len + (need_pad ? 1 : 0);
        r.push_back(0x02); // INTEGER tag
        der_len(r, total);
        if (need_pad) r.push_back(0x00);
        r.insert(r.end(), data, data + len);
        return r;
    }

    std::string generate_rsa_pubkey() {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_KEY_HANDLE key = nullptr;

        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0) != 0) {
            LWRN("BCrypt RSA open failed");
            return "";
        }
        if (BCryptGenerateKeyPair(alg, &key, 2048, 0) != 0 ||
            BCryptFinalizeKeyPair(key, 0) != 0) {
            LWRN("BCrypt RSA keygen failed");
            BCryptCloseAlgorithmProvider(alg, 0);
            return "";
        }

        // Export as BCRYPT_RSAPUBLIC_BLOB (Microsoft format)
        ULONG sz = 0;
        BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &sz, 0);
        std::vector<uint8_t> blob(sz);
        BCryptExportKey(key, nullptr, BCRYPT_RSAPUBLIC_BLOB, blob.data(), sz, &sz, 0);

        // Parse BCRYPT_RSAKEY_BLOB: Magic(4) BitLen(4) cbPubExp(4) cbMod(4) cbP1(4) cbP2(4)
        // followed by: PublicExponent(cbPubExp) Modulus(cbMod)
        auto* hdr = (BCRYPT_RSAKEY_BLOB*)blob.data();
        uint32_t exp_len = hdr->cbPublicExp;
        uint32_t mod_len = hdr->cbModulus;
        const uint8_t* exp_data = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
        const uint8_t* mod_data = exp_data + exp_len;

        // Build PKCS#1 RSAPublicKey: SEQUENCE { INTEGER(modulus), INTEGER(exponent) }
        auto mod_int = der_uint(mod_data, mod_len);
        auto exp_int = der_uint(exp_data, exp_len);

        std::vector<uint8_t> rsa_key_seq;
        rsa_key_seq.push_back(0x30); // SEQUENCE
        der_len(rsa_key_seq, mod_int.size() + exp_int.size());
        rsa_key_seq.insert(rsa_key_seq.end(), mod_int.begin(), mod_int.end());
        rsa_key_seq.insert(rsa_key_seq.end(), exp_int.begin(), exp_int.end());

        // Build SubjectPublicKeyInfo (SPKI):
        // SEQUENCE { SEQUENCE { OID(rsaEncryption), NULL }, BIT STRING { rsa_key_seq } }
        static const uint8_t algo_seq[] = {
            0x30, 0x0D, 0x06, 0x09,
            0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, // OID 1.2.840.113549.1.1.1
            0x05, 0x00 // NULL
        };

        // BIT STRING wrapping: 03 <len> 00 <rsa_key_seq>
        std::vector<uint8_t> bit_str;
        bit_str.push_back(0x03); // BIT STRING tag
        der_len(bit_str, 1 + rsa_key_seq.size());
        bit_str.push_back(0x00); // no unused bits
        bit_str.insert(bit_str.end(), rsa_key_seq.begin(), rsa_key_seq.end());

        // Outer SEQUENCE
        size_t spki_content = sizeof(algo_seq) + bit_str.size();
        std::vector<uint8_t> spki;
        spki.push_back(0x30); // SEQUENCE
        der_len(spki, spki_content);
        spki.insert(spki.end(), algo_seq, algo_seq + sizeof(algo_seq));
        spki.insert(spki.end(), bit_str.begin(), bit_str.end());

        // Base64 encode DER → PEM with 64-char line wrapping (matching OpenSSL)
        DWORD b64_sz = 0;
        CryptBinaryToStringA(spki.data(), (DWORD)spki.size(),
            CRYPT_STRING_BASE64, nullptr, &b64_sz);
        std::string b64(b64_sz, '\0');
        CryptBinaryToStringA(spki.data(), (DWORD)spki.size(),
            CRYPT_STRING_BASE64, b64.data(), &b64_sz);
        // Trim null terminator and trailing whitespace
        while (!b64.empty() && (b64.back() == '\0' || b64.back() == '\r' || b64.back() == '\n'))
            b64.pop_back();
        // Convert CRLF → LF to match OpenSSL output
        std::string b64_lf;
        for (char c : b64) { if (c != '\r') b64_lf += c; }

        // Wrap in PEM (matching OpenSSL PEM_write_bio_PUBKEY format)
        std::string pem = "-----BEGIN PUBLIC KEY-----\n" + b64_lf + "\n-----END PUBLIC KEY-----\n";

        // Store private key handle for later session key decryption
        rsa_key_ = key;
        BCryptCloseAlgorithmProvider(alg, 0);
        LDBG("RSA: generated 2048-bit SPKI public key (%zu bytes DER, %zu chars PEM)",
             spki.size(), pem.size());
        return pem;
    }

    VersionInfo parse_vgc_version() {
        // Parse VANGUARD_VERSION "1.18.2-25+..." into Version{major,minor,patch,build}
        VersionInfo v;
        sscanf(VANGUARD_VERSION, "%u.%u.%u-%u", &v.major, &v.minor, &v.patch, &v.build);
        return v;
    }

    VersionInfo detect_game_version() {
        // Try to read VALORANT.exe file version
        VersionInfo v;
        const char* paths[] = {
            "C:\\Riot Games\\VALORANT\\live\\ShooterGame\\Binaries\\Win64\\VALORANT-Win64-Shipping.exe",
            "D:\\Riot Games\\VALORANT\\live\\ShooterGame\\Binaries\\Win64\\VALORANT-Win64-Shipping.exe",
        };
        for (auto p : paths) {
            DWORD dummy = 0;
            DWORD sz = GetFileVersionInfoSizeA(p, &dummy);
            if (!sz) continue;
            std::vector<uint8_t> buf(sz);
            if (!GetFileVersionInfoA(p, 0, sz, buf.data())) continue;
            VS_FIXEDFILEINFO* fi = nullptr; UINT fi_len = 0;
            if (!VerQueryValueA(buf.data(), "\\", (void**)&fi, &fi_len) || !fi) continue;
            v.major = HIWORD(fi->dwFileVersionMS);
            v.minor = LOWORD(fi->dwFileVersionMS);
            v.patch = HIWORD(fi->dwFileVersionLS);
            v.build = LOWORD(fi->dwFileVersionLS);
            LDBG("Game version: %u.%u.%u.%u (from %s)", v.major, v.minor, v.patch, v.build, p);
            return v;
        }
        // Fallback: use client version (better than empty)
        v = parse_vgc_version();
        LDBG("Game version: falling back to VGC version %u.%u.%u.%u", v.major, v.minor, v.patch, v.build);
        return v;
    }

    bool authenticate() {
        // Generate RSA keypair for session key exchange
        std::string rsa_pub = generate_rsa_pubkey();
        if (rsa_pub.empty()) LWRN("No RSA pubkey — session key exchange will fail");

        // Build AuthParams with all required fields
        pb::AuthParams params;
        params.machine_id = machine_id_;
        params.game_id = cfg_.game_id;
        params.game_token = cfg_.game_token;
        params.client_rsa_pub = rsa_pub;
        params.session_id = cfg_.puuid;  // external SID = player UUID
        params.platform = 1;  // Windows

        // OS info (separate top-level field, not in DeviceInfo)
        params.os = os_;

        // VGC version
        params.client_ver = parse_vgc_version();

        // Game version (detect from VALORANT exe, fallback to VGC ver)
        params.game_ver = detect_game_version();

        // App and device info
        params.app = app_;
        params.dev = dev_;
        // ephemeral_ids left empty — populated from server response after first auth

        // Debug: log key field details
        LDBG("Auth fields: machine_id=%zu game_token=%zu rsa_pub=%zu game_id=%s",
             params.machine_id.size(), params.game_token.size(),
             params.client_rsa_pub.size(), params.game_id.c_str());
        LDBG("RSA key starts: %.40s", params.client_rsa_pub.c_str());
        LDBG("Versions: client=%u.%u.%u.%u game=%u.%u.%u.%u",
             params.client_ver.major, params.client_ver.minor,
             params.client_ver.patch, params.client_ver.build,
             params.game_ver.major, params.game_ver.minor,
             params.game_ver.patch, params.game_ver.build);

        // Serialize AuthenticationRequest
        auto inner = pb::auth_request(params);
        LINF("AuthRequest: %zu bytes", inner.size());

        // Wrap in Envelope
        auto payload = pb::wrap_envelope(inner, ENV_AUTH_REQUEST);
        LINF("Envelope: %zu bytes (type=AUTH_REQUEST)", payload.size());
        // Debug: hex dump first 32 bytes of envelope for protobuf verification
        {
            size_t n = (std::min)(payload.size(), (size_t)32);
            std::string hex;
            for (size_t i = 0; i < n; ++i) {
                char tmp[4]; snprintf(tmp, sizeof(tmp), "%02x ", payload[i]);
                hex += tmp;
            }
            LDBG("Envelope hex[0..%zu]: %s", n, hex.c_str());
        }

        if (cfg_.dry_run) {
            dry_run_dump(inner);
            LINF("Dry run complete — no request sent.");
            sess_.alive = false;
            return true;
        }

        // Send to gateway
        auto resp = gw_->post(payload, ENV_AUTH_REQUEST, machine_id_);
        if (resp.code != 200) {
            LERR("Auth failed: HTTP %d (%s)", resp.code, resp.err.c_str());
            if (!resp.body.empty()) {
                // Hex dump first 64 bytes of response for debugging
                size_t dump_len = (std::min)(resp.body.size(), (size_t)64);
                std::string hex;
                for (size_t i = 0; i < dump_len; ++i) {
                    char tmp[4]; snprintf(tmp, sizeof(tmp), "%02x ", resp.body[i]);
                    hex += tmp;
                }
                LERR("Response hex (%zu bytes): %s", resp.body.size(), hex.c_str());
                // Try to decode as protobuf Envelope error
                auto tok = pb::parse_token(resp.body);
                if (tok) LERR("Server error token: %s", tok->token.c_str());
            }
            return false;
        }

        // The response is also wrapped in Envelope — unwrap it
        auto tok = pb::parse_token(resp.body);
        if (!tok) { LERR("Failed to parse TokenResponse"); return false; }

        sess_.token = tok->token;
        sess_.session_id = tok->session_id;
        sess_.server_rsa = tok->server_rsa;
        sess_.expires = tok->exp;
        sess_.config = tok->config;
        sess_.flags = tok->flags;
        sess_.authed = true;

        LINF("Authenticated! session=%s expires=%llu",
             sess_.session_id.c_str(), sess_.expires);
        for (auto& [k,v] : sess_.config)
            LDBG("  config[%s] = %s", k.c_str(), v.c_str());

        return true;
    }

    void heartbeat_loop() {
        std::vector<uint32_t> active;
        while (sess_.alive && sess_.authed) {
            // Timing jitter (stealth)
            stealth::add_timing_jitter(cfg_.heartbeat_ms);
            Sleep(cfg_.heartbeat_ms);
            if (!sess_.alive) break;

            auto now = (uint64_t)time(nullptr);
            auto payload = pb::heartbeat_request(sess_.token, now, active);
            auto resp = gw_->post(payload);

            if (resp.code == 200) {
                auto hb = pb::parse_hb(resp.body);
                if (hb) {
                    if (hb->interval > 0 && hb->interval != cfg_.heartbeat_ms) {
                        LINF("Heartbeat interval: %u -> %u ms", cfg_.heartbeat_ms, hb->interval);
                        cfg_.heartbeat_ms = hb->interval;
                    }
                    for (auto tid : hb->tasks) {
                        LINF("Task assigned: %u (returning clean)", tid);
                        active.push_back(tid);
                        // Execute task — return clean result
                        pb::Enc result;
                        result.u32(1, tid);
                        result.u32(2, 0); // clean
                        result.str(3, "ok");
                        auto task_resp_payload = pb::disconnect_request(sess_.token, "");
                        // In practice we'd use a task_result builder;
                        // for now reuse disconnect shape
                        gw_->post(task_resp_payload);
                        active.erase(std::remove(active.begin(), active.end(), tid), active.end());
                    }
                }
                LDBG("Heartbeat OK");
            } else if (resp.code == 401 || resp.code == 403) {
                LWRN("Token expired/rejected — re-authenticating...");
                sess_.authed = false;
                if (!authenticate()) {
                    LERR("Re-auth failed — stopping");
                    sess_.alive = false;
                }
            } else {
                LWRN("Heartbeat: HTTP %d", resp.code);
            }
        }
    }

    void on_pipe(uint32_t cid, const pipe::Msg& m) {
        switch (m.id) {
            case PIPE_CONNECT:     on_connect(cid);     break;
            case PIPE_LOGIN:       on_login(cid, m);    break;
            case PIPE_MATCH_START: on_match(cid);       break;
            case PIPE_DISCONNECT:  on_disconnect(cid);  break;
            default:
                LWRN("Pipe: unknown msg_id=%u from cid=%u", m.id, cid);
                send_health(cid);
                break;
        }
    }

    void on_connect(uint32_t cid) {
        LINF("Pipe: CONNECT from %u", cid);
        send_health(cid);
    }

    void on_login(uint32_t cid, const pipe::Msg& m) {
        LINF("Pipe: LOGIN from %u (%zu bytes)", cid, m.payload.size());
        send_health(cid);
    }

    void on_match(uint32_t cid) {
        LINF("Pipe: MATCH_START from %u", cid);
        send_health(cid);
    }

    void on_disconnect(uint32_t cid) {
        LINF("Pipe: DISCONNECT from %u", cid);
    }

    void send_health(uint32_t cid) {
        pipe::Msg resp;
        resp.id = PIPE_HEALTH_RESP;
        pb::Enc e;
        e.u32(1, PIPE_HEALTH_RESP);
        e.b(2, sess_.authed.load());
        resp.payload = {e.buf().begin(), e.buf().end()};
        pipe_->send(cid, resp);
    }

    void shutdown() {
        if (sess_.authed && gw_) {
            auto dc = pb::disconnect_request(sess_.token, "session_end");
            gw_->post(dc);
        }
        sess_.alive = false;
        sess_.authed = false;
        if (hb_thread_.joinable()) hb_thread_.join();
        if (pipe_) pipe_->stop();
        stealth::cleanup();
        LINF("Session terminated cleanly.");
    }

    void dry_run_dump(const std::vector<uint8_t>& payload) {
        LINF("═══ DRY RUN ═══");
        LINF("AuthRequest: %zu bytes", payload.size());
        LINF("machine_id: %s", machine_id_.c_str());
        LINF("region:     %s -> %s.vg.ac.pvp.net:%d", cfg_.region.c_str(), cfg_.region.c_str(), GATEWAY_PORT);
        LINF("puuid:      %s", cfg_.puuid.c_str());
        LINF("game_id:    %s", cfg_.game_id.c_str());
        LINF("app:        %s %s", app_.id.c_str(), app_.version.c_str());
        auto it_cpu = dev_.info.find("cpu_brand");
        auto it_gpu = dev_.info.find("gpu_model");
        LINF("cpu:        %s", it_cpu != dev_.info.end() ? it_cpu->second.c_str() : "?");
        LINF("gpu:        %s", it_gpu != dev_.info.end() ? it_gpu->second.c_str() : "?");
        LINF("pipe:       %s", cfg_.pipe_name.c_str());
        LINF("Hex (first 128B):");
        for (size_t i = 0; i < std::min(payload.size(), (size_t)128); i += 16) {
            char hex[64] = {}, ascii[20] = {};
            for (size_t j = 0; j < 16 && i+j < payload.size(); j++) {
                sprintf(hex + j*3, "%02x ", payload[i+j]);
                ascii[j] = (payload[i+j] >= 32 && payload[i+j] < 127) ? (char)payload[i+j] : '.';
            }
            LINF("  %04zx: %-48s %s", i, hex, ascii);
        }
    }

    Config cfg_;
    DevInfo dev_;
    AppInfo app_;
    std::string machine_id_;
    OSInfo os_;
    Session sess_;
    std::unique_ptr<gw::Client> gw_;
    std::unique_ptr<pipe::Server> pipe_;
    std::thread hb_thread_;
    BCRYPT_KEY_HANDLE rsa_key_ = nullptr;
};

// ============================================================================
// Public C-style interface for main.cpp
// ============================================================================
static std::unique_ptr<SessionImpl> g_session;

bool session_start(Config cfg, DevInfo dev, AppInfo app) {
    g_session = std::make_unique<SessionImpl>(std::move(cfg), std::move(dev), std::move(app));
    return g_session->run();
}

void session_stop() {
    if (g_session) g_session->signal_stop();
}

} // namespace wraith
