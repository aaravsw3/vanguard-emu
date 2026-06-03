#include "wraith.h"
#include <cstdio>
#include <csignal>

// Forward declarations from session.cpp
namespace wraith {
    bool session_start(Config cfg, DevInfo dev, AppInfo app);
    void session_stop();
}

static void on_signal(int) {
    LINF("Interrupt received — vanishing...");
    wraith::session_stop();
}

static void banner() {
    fprintf(stderr,
        "\n"
        "\x1b[35m"
        "  __      ___ __ __ _ (_) |_| |__  \n"
        "  \\ \\ /\\ / / '__/ _` | | __| '_ \\ \n"
        "   \\ V  V /| | | (_| | | |_| | | |\n"
        "    \\_/\\_/ |_|  \\__,_|_|\\__|_| |_|\n"
        "\x1b[0m"
        "  wraith.cx\n"
        "\n"
    );
}

static void usage() {
    fprintf(stderr,
        "Usage: wraith [options]\n\n"
        "Options:\n"
        "  -p, --puuid <uuid>   Player UUID (auto-detected if omitted)\n"
        "  -r, --region <r>     Gateway region: na|eu|ap|kr|latam (default: auto)\n"
        "  -g, --game <id>      Game ID (default: valorant)\n"
        "      --pipe <name>    Pipe name (default: auto from MachineGuid)\n"
        "  -n, --no-launch      Don't launch Valorant, just emulate VGC\n"
        "  -d, --dry-run        Build & dump auth payload, don't send\n"
        "  -v, --debug          Verbose logging\n"
        "  -h, --help           This message\n\n"
        "PUUID auto-detection (when -p is omitted):\n"
        "  1. Riot Client local API  (requires Riot Client running)\n"
        "  2. RiotGamesPrivateSettings.yaml  (offline, prior login)\n"
        "  3. SSID JWT decode  (offline, prior login)\n"
    );
}

static bool is_flag(const std::string& a, const char* s, const char* l) {
    return a == s || a == l;
}
static bool is_opt(const std::string& a, const char* s, const char* l, int i, int argc) {
    return (a == s || a == l) && i + 1 < argc;
}

int main(int argc, char* argv[]) {
    // Ensure stderr is available (even if launched as WIN32 subsystem)
    if (!GetConsoleWindow()) {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }

    banner();

    wraith::Config cfg;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if      (is_opt(a, "-p", "--puuid",  i, argc)) cfg.puuid     = argv[++i];
        else if (is_opt(a, "-r", "--region", i, argc)) cfg.region    = argv[++i];
        else if (is_opt(a, "-g", "--game",   i, argc)) cfg.game_id   = argv[++i];
        else if (is_opt(a, "",   "--pipe",   i, argc)) cfg.pipe_name = argv[++i];
        else if (is_flag(a, "-n", "--no-launch")) cfg.no_launch = true;
        else if (is_flag(a, "-d", "--dry-run"))   cfg.dry_run   = true;
        else if (is_flag(a, "-v", "--debug"))      cfg.debug     = true;
        else if (is_flag(a, "-h", "--help")) { usage(); return 0; }
        else {
            fprintf(stderr, "Unknown option: %s\n\n", a.c_str());
            usage();
            return 1;
        }
    }

    wraith::log::init(cfg.debug);

    // Auto-detect PUUID if not provided
    if (cfg.puuid.empty()) {
        LINF("No --puuid given, auto-detecting...");
        auto result = wraith::puuid::resolve();
        if (result) {
            cfg.puuid = result->uuid;
            // Map Riot account shard to valid Vanguard gateway prefix.
            // DNS-verified gateways: na, eu, ap, kr, latam
            // Account shards: na1, br1, la1, la2, euw1, eun1, tr1, ru1, kr, jp1, oce1, ph2, sg2, th2, tw2, vn2
            if (!result->region.empty() && cfg.region == "na") {
                std::string rr = result->region;
                std::transform(rr.begin(), rr.end(), rr.begin(), ::tolower);
                if      (rr.find("br") == 0 || rr.find("la") == 0)
                    cfg.region = "latam";
                else if (rr.find("eu") == 0 || rr.find("tr") == 0 || rr.find("ru") == 0)
                    cfg.region = "eu";
                else if (rr.find("kr") == 0)
                    cfg.region = "kr";
                else if (rr.find("jp") == 0 || rr.find("oce") == 0 || rr.find("ap") == 0 ||
                         rr.find("ph") == 0 || rr.find("sg") == 0 || rr.find("th") == 0 ||
                         rr.find("tw") == 0 || rr.find("vn") == 0)
                    cfg.region = "ap";
                else
                    cfg.region = "na";
                LINF("Auto-detected gateway: %s.vg.ac.pvp.net (account shard: %s)",
                     cfg.region.c_str(), result->region.c_str());
            }
        } else {
            LERR("PUUID auto-detection failed. Provide --puuid manually.");
            LERR("  Make sure Riot Client is running, or you've logged in before.");
            usage();
            return 1;
        }
    }

    // Fetch RSO access token and entitlements (requires Riot Client running)
    if (cfg.game_token.empty()) {
        LINF("Fetching RSO access token from Riot Client...");
        cfg.game_token = wraith::puuid::fetch_access_token();
        if (cfg.game_token.empty())
            LWRN("No RSO token — auth will likely fail. Is Riot Client logged in?");
    }
    if (cfg.entitlements.empty()) {
        cfg.entitlements = wraith::puuid::fetch_entitlements_token();
    }

    // Collect real device fingerprint
    auto dev = wraith::fp::collect();
    auto app = wraith::fp::app_info(cfg.game_id, wraith::VANGUARD_VERSION);

    // Install Ctrl+C handler
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    // Run full pipeline
    bool ok = wraith::session_start(std::move(cfg), std::move(dev), std::move(app));
    return ok ? 0 : 1;
}
