#pragma once
// ============================================================================
// Wraith — VGC Full Emulator (PATH B)
//
// "Temporal Process Substitution" architecture:
//   Phase 0: Silence real VGC/VGK
//   Phase 1: Manifest as VGC (pipe, service identity)
//   Phase 2: Authenticate with gateway
//   Phase 3: Launch Valorant
//   Phase 4: Maintain session (heartbeat, tasks, pipe)
//   Phase 5: Vanish on exit (cleanup, optional restore)
//
// Creative stealth: "Entropy-Matched Temporal Cloaking"
//   - Binary exists on disk only during execution (self-deleting)
//   - Process metadata spoofed to match real vgc.exe
//   - Attestation blob uses real hardware data with entropy-matched signatures
//   - Timing jitter matches real VGC's statistical profile
//   - No persistent artifacts (registry, files, services)
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <optional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <userenv.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

namespace wraith {

// ============================================================================
// Version constants (from RE @ 0x564bd131b etc.)
// ============================================================================
inline constexpr const char* VANGUARD_VERSION   = "1.18.2-25+20260501.225940";
inline constexpr const char* GATEWAY_PATH       = "/vanguard/v1/gateway";
inline constexpr const char* GATEWAY_DOMAIN_FMT = "%s.vg.ac.pvp.net";
inline constexpr uint16_t    GATEWAY_PORT       = 8443;
inline constexpr const char* CONTENT_TYPE       = "application/x-protobuf";
inline constexpr const char* XVG1_VALUE         = "3";
inline constexpr const char* XVG3_VALUE         = "1";

// Pipe name — VGC uses a session-specific pipe
// Discovered pattern: \\.\pipe\riot-vgc-{machine-guid}
inline constexpr const char* PIPE_PREFIX        = "riot-vgc-";

// ============================================================================
// Protobuf wire types & field tags (from RE @ sub_5647DD700 etc.)
// ============================================================================
enum Wire : uint8_t { W_VARINT = 0, W_64 = 1, W_LEN = 2, W_32 = 5 };

namespace F {
    // AuthenticationRequest (serializer @ 0x5647DD700)
    namespace Auth {
        enum : uint32_t {
            machine_id = 1, os_info = 2, platform = 3,
            game_token = 4, client_rsa_pub = 5,
            client_version = 6, game_version = 7,
            game_id = 8, field9 = 9, ephemeral_ids = 10,
            app_info = 11, device_info = 12, session_id = 13,
            flags = 14, metadata = 15
        };
    }
    // Envelope (parser @ 0x564824500: field1=varint→+32, field2=LEN→+16, field3=varint→+36, field4=LEN→+24)
    namespace Env {
        enum : uint32_t { msg_type = 1, body = 2, version = 3, aux = 4 };
    }
    // TokenResponse (deserializer @ 0x564D83C42)
    namespace TokResp {
        enum : uint32_t {
            token = 1, exp = 2, server_rsa_pub = 3,
            ephemeral_ids = 4, feature_flags = 5,
            config = 6, session_id = 7
        };
    }
    // HeartbeatRequest (serializer @ 0x56482C770)
    namespace HBReq {
        enum : uint32_t { access_token = 1, timestamp = 2, active_tasks = 3 };
    }
    // AppInfo (serializer @ 0x5647E6AE0)
    namespace App { enum : uint32_t { id = 1, version_name = 2 }; }
    // DeviceInfo (parser @ sub_5647E9D00: ONLY has map<string,string> at field 1)
    namespace Dev {
        enum : uint32_t { info_map = 1 };
    }
    // OSInfo (serializer @ sub_5647DBD20)
    namespace OS {
        enum : uint32_t {
            field1_varint = 1,  // varint (OS type? 0=default)
            field2_varint = 2,  // varint (build? 0=default)
            variant = 3,        // string: OS variant name
            version = 4         // string: OS version string
        };
    }
}

// ============================================================================
// Pipe message IDs (from RE @ 0x5647F9440 etc.)
// ============================================================================
enum MsgId : uint32_t {
    PIPE_DISCONNECT      = 2,
    PIPE_CONNECT         = 100,
    PIPE_LOGIN           = 101,
    PIPE_MATCH_START     = 103,
    PIPE_HEALTH_RESP     = 1003,
};

// ============================================================================
// Data structures
// ============================================================================
struct AppInfo   { std::string id, version; };
struct VersionInfo { uint32_t major = 0, minor = 0, patch = 0, build = 0; };
struct OSInfo    { std::string variant, version; uint32_t os_type = 0, os_build = 0; };
struct CpuInfo   { std::string brand, model; };
struct GpuInfo   { std::string brand, model; };
struct MemInfo   { uint64_t total = 0, avail = 0; };
struct DevInfo   {
    std::map<std::string,std::string> info;  // DeviceInfo is just map<string,string>
};

// Envelope message types (enum from .rdata @ 0x564bcc380)
enum EnvMsgType : uint32_t {
    ENV_ERROR_RESPONSE       = 0,
    ENV_EMPTY                = 1,
    ENV_TOKEN_RESPONSE       = 2,
    ENV_AUTH_REQUEST         = 3,
    ENV_DISCONNECT_REQUEST   = 4,
    ENV_INVALID              = 5,
    ENV_MODULES_RESPONSE     = 6,
    ENV_ACCESS_REQUEST       = 7,
    ENV_HEARTBEAT_RESPONSE   = 8,
    ENV_TASK_RESULT_REQUEST  = 9,
    ENV_HEARTBEAT_REQUEST    = 10,
};

struct Config {
    std::string region   = "na";
    std::string game_id  = "valorant";
    std::string puuid;
    std::string game_token;      // RSO access token (from Riot Client API)
    std::string entitlements;    // entitlements token
    std::string pipe_name;       // auto-generated if empty
    std::string valorant_path;   // auto-detected if empty
    std::string riot_client_path;
    uint32_t    heartbeat_ms = 30000;
    bool        dry_run    = false;
    bool        debug      = false;
    bool        no_launch  = false;  // don't launch game, just emulate
    bool        stealth    = true;
};

struct Session {
    std::string token;
    std::string session_id;
    std::string server_rsa;
    uint64_t    expires = 0;
    std::map<std::string,std::string> config;
    std::map<std::string,std::string> flags;
    std::atomic<bool> authed{false};
    std::atomic<bool> alive{true};
};

// ============================================================================
// Forward declarations — each module
// ============================================================================
namespace log {
    enum Lvl { DBG, INF, WRN, ERR };
    void init(bool debug);
    void print(Lvl l, const char* fmt, ...);
}
#define LDBG(...) wraith::log::print(wraith::log::DBG, __VA_ARGS__)
#define LINF(...) wraith::log::print(wraith::log::INF, __VA_ARGS__)
#define LWRN(...) wraith::log::print(wraith::log::WRN, __VA_ARGS__)
#define LERR(...) wraith::log::print(wraith::log::ERR, __VA_ARGS__)

// protobuf.cpp
namespace pb {
    class Enc {
    public:
        void varint(uint64_t v);
        void tag(uint32_t fn, Wire w);
        void str(uint32_t fn, const std::string& s);
        void bytes(uint32_t fn, const std::vector<uint8_t>& d);
        void bytes(uint32_t fn, const uint8_t* d, size_t n);
        void u32(uint32_t fn, uint32_t v);
        void u64(uint32_t fn, uint64_t v);
        void b(uint32_t fn, bool v);
        void sub(uint32_t fn, const Enc& e);
        void packed_u32(uint32_t fn, const std::vector<uint32_t>& vs);
        void map_ss(uint32_t fn, const std::string& k, const std::string& v);
        const std::vector<uint8_t>& buf() const { return d_; }
        size_t size() const { return d_.size(); }
    private:
        std::vector<uint8_t> d_;
    };
    class Dec {
    public:
        Dec(const uint8_t* p, size_t n) : p_(p), n_(n) {}
        Dec(const std::vector<uint8_t>& v) : p_(v.data()), n_(v.size()) {}
        bool more() const { return o_ < n_; }
        bool next(uint32_t& fn, Wire& w);
        uint64_t varint();
        std::string str();
        std::vector<uint8_t> bytes();
        Dec submsg();
        void skip(Wire w);
    private:
        const uint8_t* p_; size_t n_, o_ = 0;
    };

    struct AuthParams {
        std::string machine_id;
        std::string game_id;
        std::string game_token;           // RSO access token
        std::string client_rsa_pub;       // PEM-encoded RSA public key
        std::string session_id;           // external SID
        OSInfo os;
        VersionInfo client_ver;
        VersionInfo game_ver;
        AppInfo app;
        DevInfo dev;
        std::vector<std::string> ephemeral_ids; // repeated string field 10
        uint32_t platform = 1;            // 1 = Windows
        uint32_t field9 = 1;               // auth request type / capability flags (real client always sets non-zero)
        std::map<std::string,std::string> flags;
        std::map<std::string,std::string> metadata;
    };
    std::vector<uint8_t> auth_request(const AuthParams& p);
    std::vector<uint8_t> wrap_envelope(const std::vector<uint8_t>& body,
        EnvMsgType type, uint32_t version = 1);
    std::vector<uint8_t> heartbeat_request(const std::string& tok, uint64_t ts,
        const std::vector<uint32_t>& tasks);
    std::vector<uint8_t> disconnect_request(const std::string& tok, const std::string& reason);

    struct TokenResp {
        std::string token, session_id, server_rsa;
        uint64_t exp = 0;
        std::map<std::string,std::string> config, flags;
    };
    struct HBResp { uint32_t interval = 0; std::vector<uint32_t> tasks; };

    std::optional<TokenResp> parse_token(const std::vector<uint8_t>& d);
    std::optional<HBResp>    parse_hb(const std::vector<uint8_t>& d);
}

// gateway.cpp
namespace gw {
    struct Resp { int code = 0; std::vector<uint8_t> body; std::string err; };
    class Client {
    public:
        Client(const Config& c);
        ~Client();
        Resp post(const std::vector<uint8_t>& payload,
                  EnvMsgType msg_type = ENV_AUTH_REQUEST,
                  const std::string& machine_id = "");
    private:
        Config cfg_;
        HINTERNET session_ = nullptr, connect_ = nullptr;
    };
}

// pipe_server.cpp
namespace pipe {
    struct Msg { uint32_t id; std::vector<uint8_t> payload; };
    using Handler = std::function<void(uint32_t cid, const Msg& m)>;
    class Server {
    public:
        Server(const std::string& name);
        ~Server();
        void on_msg(Handler h) { h_ = std::move(h); }
        void start();
        void stop();
        bool send(uint32_t cid, const Msg& m);
    private:
        void accept_loop();
        void client_loop(HANDLE p, uint32_t cid);
        bool read_msg(HANDLE p, Msg& m);
        bool write_msg(HANDLE p, const Msg& m);
        std::string name_;
        Handler h_;
        std::atomic<bool> run_{false};
        std::atomic<uint32_t> next_cid_{1};
        std::thread accept_t_;
        struct Conn { HANDLE h = INVALID_HANDLE_VALUE; std::thread t; std::atomic<bool> up{true}; };
        std::mutex mu_;
        std::map<uint32_t, std::unique_ptr<Conn>> conns_;
    };
}

// fingerprint.cpp
namespace fp {
    DevInfo collect();
    AppInfo app_info(const std::string& gid, const std::string& ver);
    std::string machine_id();
}

// attestation.cpp
namespace att {
    std::vector<uint8_t> build(const DevInfo& dev, const std::string& kver);
}

// stealth.cpp
namespace stealth {
    bool kill_vgc();
    bool spoof_process_name(const wchar_t* name);
    bool hide_console_window();
    std::string get_machine_guid();
    std::string generate_pipe_name();
    void add_timing_jitter(uint32_t base_ms);
    void cleanup();
}

// puuid.cpp — auto-detect player UUID from Riot Client
namespace puuid {
    struct Result { std::string uuid; std::string source; std::string region; };
    // Method 1: Query Riot Client local API (lockfile -> /chat/v1/session)
    std::optional<Result> from_riot_api();
    // Method 2: Parse RiotGamesPrivateSettings.yaml (sub cookie)
    std::optional<Result> from_private_settings();
    // Method 3: Decode JWT from ssid cookie
    std::optional<Result> from_ssid_jwt();
    // Try all methods in order, return first success
    std::optional<Result> resolve();
    // Fetch RSO access token from Riot Client API
    std::string fetch_access_token();
    // Fetch entitlements token from Riot Client API
    std::string fetch_entitlements_token();
}

// launcher.cpp
namespace launch {
    struct Paths {
        std::wstring riot_client;
        std::wstring valorant_exe;
        std::wstring vanguard_dir;
    };
    Paths detect_paths();
    bool start_valorant(const Paths& p);
    bool wait_for_game_exit(uint32_t timeout_sec = 0);
}

} // namespace wraith
