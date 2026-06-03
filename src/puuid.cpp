#include "wraith.h"
#include <fstream>
#include <regex>

namespace wraith::puuid {

// ============================================================================
// Lockfile parser: %LOCALAPPDATA%\Riot Games\Riot Client\Config\lockfile
// Format: name:pid:port:password:protocol
// ============================================================================
struct Lockfile { std::string name; int port; std::string pass; std::string proto; };

static std::optional<Lockfile> read_lockfile() {
    char appdata[MAX_PATH];
    if (!GetEnvironmentVariableA("LOCALAPPDATA", appdata, MAX_PATH)) return std::nullopt;
    std::string path = std::string(appdata) + "\\Riot Games\\Riot Client\\Config\\lockfile";
    std::ifstream f(path);
    if (!f.is_open()) { LDBG("PUUID: lockfile not found at %s", path.c_str()); return std::nullopt; }
    std::string line;
    std::getline(f, line);
    // Parse: name:pid:port:password:protocol
    size_t p1 = line.find(':');
    if (p1 == std::string::npos) return std::nullopt;
    size_t p2 = line.find(':', p1 + 1);
    if (p2 == std::string::npos) return std::nullopt;
    size_t p3 = line.find(':', p2 + 1);
    if (p3 == std::string::npos) return std::nullopt;
    size_t p4 = line.find(':', p3 + 1);
    if (p4 == std::string::npos) return std::nullopt;

    Lockfile lf;
    lf.name  = line.substr(0, p1);
    lf.port  = std::stoi(line.substr(p2 + 1, p3 - p2 - 1));
    lf.pass  = line.substr(p3 + 1, p4 - p3 - 1);
    lf.proto = line.substr(p4 + 1);
    // Trim trailing whitespace/newline
    while (!lf.proto.empty() && (lf.proto.back() == '\r' || lf.proto.back() == '\n' || lf.proto.back() == ' '))
        lf.proto.pop_back();
    LDBG("PUUID: lockfile found — port=%d proto=%s", lf.port, lf.proto.c_str());
    return lf;
}

// Base64 decode (for JWT)
static std::string b64_decode(const std::string& in) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Handle URL-safe base64
    std::string s = in;
    for (auto& c : s) { if (c == '-') c = '+'; if (c == '_') c = '/'; }
    while (s.size() % 4) s += '=';
    std::string out;
    uint32_t val = 0; int bits = -8;
    for (auto c : s) {
        auto p = strchr(t, c);
        if (!p) continue;
        val = (val << 6) + (uint32_t)(p - t);
        bits += 6;
        if (bits >= 0) { out += char((val >> bits) & 0xFF); bits -= 8; }
    }
    return out;
}

// ============================================================================
// Method 1: Riot Client local API
// GET https://127.0.0.1:{port}/chat/v1/session
// Auth: Basic riot:{password}
// Response JSON: {"puuid":"...","region":"..."}
// ============================================================================
std::optional<Result> from_riot_api() {
    LINF("PUUID: trying Riot Client local API...");
    auto lf = read_lockfile();
    if (!lf) return std::nullopt;

    HINTERNET session = WinHttpOpen(L"wraith/puuid", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return std::nullopt;

    HINTERNET connect = WinHttpConnect(session, L"127.0.0.1", (INTERNET_PORT)lf->port, 0);
    if (!connect) { WinHttpCloseHandle(session); return std::nullopt; }

    HINTERNET req = WinHttpOpenRequest(connect, L"GET", L"/chat/v1/session",
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        (lf->proto == "https") ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return std::nullopt; }

    // Disable cert validation (Riot Client uses self-signed cert)
    DWORD sec = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));

    // Basic auth: riot:{password}
    std::string cred_raw = "riot:" + lf->pass;
    // Manual Base64 encode
    static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    for (size_t i = 0; i < cred_raw.size(); i += 3) {
        uint32_t n = (uint8_t)cred_raw[i] << 16;
        if (i+1 < cred_raw.size()) n |= (uint8_t)cred_raw[i+1] << 8;
        if (i+2 < cred_raw.size()) n |= (uint8_t)cred_raw[i+2];
        b64 += b64t[(n >> 18) & 63]; b64 += b64t[(n >> 12) & 63];
        b64 += (i+1 < cred_raw.size()) ? b64t[(n >> 6) & 63] : '=';
        b64 += (i+2 < cred_raw.size()) ? b64t[n & 63] : '=';
    }
    std::string auth_hdr = "Authorization: Basic " + b64;
    std::wstring wauth(auth_hdr.begin(), auth_hdr.end());

    BOOL ok = WinHttpSendRequest(req, wauth.c_str(), (DWORD)wauth.size(),
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok || !WinHttpReceiveResponse(req, nullptr)) {
        LDBG("PUUID: API request failed: %u", GetLastError());
        WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return std::nullopt;
    }

    // Read response body
    std::string body;
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
        std::vector<char> buf(avail);
        DWORD rd = 0;
        WinHttpReadData(req, buf.data(), avail, &rd);
        body.append(buf.data(), rd);
        avail = 0;
    }
    WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);

    // Parse JSON (simple regex — no JSON library dependency)
    std::regex puuid_re("\"puuid\"\\s*:\\s*\"([0-9a-f\\-]+)\"");
    std::regex region_re("\"region\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch m;
    Result r;
    if (std::regex_search(body, m, puuid_re)) r.uuid = m[1];
    if (std::regex_search(body, m, region_re)) r.region = m[1];
    r.source = "riot_api";

    if (r.uuid.empty()) { LDBG("PUUID: API response had no puuid"); return std::nullopt; }
    LINF("PUUID: [riot_api] %s (region=%s)", r.uuid.c_str(), r.region.c_str());
    return r;
}

// ============================================================================
// Method 2: RiotGamesPrivateSettings.yaml — parse 'sub' cookie
// ============================================================================
std::optional<Result> from_private_settings() {
    LINF("PUUID: trying RiotGamesPrivateSettings.yaml...");
    char appdata[MAX_PATH];
    if (!GetEnvironmentVariableA("LOCALAPPDATA", appdata, MAX_PATH)) return std::nullopt;

    // Try both Riot Client and VALORANT paths
    std::string paths[] = {
        std::string(appdata) + "\\Riot Games\\Riot Client\\Data\\RiotGamesPrivateSettings.yaml",
        std::string(appdata) + "\\Riot Games\\VALORANT\\Data\\RiotGamesPrivateSettings.yaml",
    };

    for (auto& path : paths) {
        std::ifstream f(path);
        if (!f.is_open()) continue;
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        f.close();

        // Find the 'sub' cookie value — it's the PUUID
        // Look for: name: "sub" followed by value: "uuid"
        // The YAML structure has name/value pairs for each cookie
        std::regex sub_re("name:\\s*\"sub\"[\\s\\S]*?value:\\s*\"([0-9a-f\\-]+)\"");
        std::smatch m;
        if (std::regex_search(content, m, sub_re)) {
            Result r;
            r.uuid = m[1];
            r.source = "private_settings";

            // Also try to get region from 'region' field
            std::regex region_re("region:\\s*\"([^\"]+)\"");
            std::smatch rm;
            if (std::regex_search(content, rm, region_re))
                r.region = rm[1];

            LINF("PUUID: [yaml] %s (region=%s) from %s", r.uuid.c_str(), r.region.c_str(), path.c_str());
            return r;
        }
    }
    LDBG("PUUID: no sub cookie found in settings");
    return std::nullopt;
}

// ============================================================================
// Method 3: Decode JWT from 'ssid' cookie — extract 'sub' claim
// ============================================================================
std::optional<Result> from_ssid_jwt() {
    LINF("PUUID: trying SSID JWT decode...");
    char appdata[MAX_PATH];
    if (!GetEnvironmentVariableA("LOCALAPPDATA", appdata, MAX_PATH)) return std::nullopt;

    std::string paths[] = {
        std::string(appdata) + "\\Riot Games\\Riot Client\\Data\\RiotGamesPrivateSettings.yaml",
        std::string(appdata) + "\\Riot Games\\VALORANT\\Data\\RiotGamesPrivateSettings.yaml",
    };

    for (auto& path : paths) {
        std::ifstream f(path);
        if (!f.is_open()) continue;
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        f.close();

        // Find ssid cookie value (JWT)
        std::regex ssid_re("name:\\s*\"ssid\"[\\s\\S]*?value:\\s*\"(eyJ[^\"]+)\"");
        std::smatch m;
        if (!std::regex_search(content, m, ssid_re)) continue;

        std::string jwt = m[1];
        // JWT = header.payload.signature
        auto dot1 = jwt.find('.');
        auto dot2 = jwt.find('.', dot1 + 1);
        if (dot1 == std::string::npos || dot2 == std::string::npos) continue;

        std::string payload_b64 = jwt.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string payload = b64_decode(payload_b64);

        // Extract "sub" from JSON payload
        std::regex sub_re("\"sub\"\\s*:\\s*\"([0-9a-f\\-]+)\"");
        std::smatch sm;
        if (std::regex_search(payload, sm, sub_re)) {
            Result r;
            r.uuid = sm[1];
            r.source = "ssid_jwt";
            LINF("PUUID: [jwt] %s", r.uuid.c_str());
            return r;
        }
    }
    LDBG("PUUID: no SSID JWT found");
    return std::nullopt;
}

// ============================================================================
// resolve() — try all methods in priority order
// ============================================================================
std::optional<Result> resolve() {
    // Method 1: Live API (most reliable, requires Riot Client running)
    if (auto r = from_riot_api()) return r;
    // Method 2: YAML config (works offline, requires prior login)
    if (auto r = from_private_settings()) return r;
    // Method 3: JWT decode (fallback)
    if (auto r = from_ssid_jwt()) return r;
    LERR("PUUID: all auto-detection methods failed");
    return std::nullopt;
}

// ============================================================================
// Riot Client API helpers for tokens
// ============================================================================
static std::string riot_api_get(const Lockfile& lf, const wchar_t* path) {
    HINTERNET session = WinHttpOpen(L"wraith/token", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return "";

    HINTERNET connect = WinHttpConnect(session, L"127.0.0.1", (INTERNET_PORT)lf.port, 0);
    if (!connect) { WinHttpCloseHandle(session); return ""; }

    HINTERNET req = WinHttpOpenRequest(connect, L"GET", path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        (lf.proto == "https") ? WINHTTP_FLAG_SECURE : 0);
    if (!req) { WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return ""; }

    DWORD sec = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));

    // Basic auth
    std::string cred_raw = "riot:" + lf.pass;
    static const char b64t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    for (size_t i = 0; i < cred_raw.size(); i += 3) {
        uint32_t n = (uint8_t)cred_raw[i] << 16;
        if (i+1 < cred_raw.size()) n |= (uint8_t)cred_raw[i+1] << 8;
        if (i+2 < cred_raw.size()) n |= (uint8_t)cred_raw[i+2];
        b64 += b64t[(n >> 18) & 63]; b64 += b64t[(n >> 12) & 63];
        b64 += (i+1 < cred_raw.size()) ? b64t[(n >> 6) & 63] : '=';
        b64 += (i+2 < cred_raw.size()) ? b64t[n & 63] : '=';
    }
    std::string auth_hdr = "Authorization: Basic " + b64;
    std::wstring wauth(auth_hdr.begin(), auth_hdr.end());

    BOOL ok = WinHttpSendRequest(req, wauth.c_str(), (DWORD)wauth.size(),
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return "";
    }

    std::string body;
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
        std::vector<char> buf(avail);
        DWORD rd = 0;
        WinHttpReadData(req, buf.data(), avail, &rd);
        body.append(buf.data(), rd);
        avail = 0;
    }
    WinHttpCloseHandle(req); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
    return body;
}

std::string fetch_access_token() {
    auto lf = read_lockfile();
    if (!lf) { LDBG("Token: lockfile not found"); return ""; }

    auto body = riot_api_get(*lf, L"/rso-auth/v1/authorization/access-token");
    if (body.empty()) { LDBG("Token: access-token endpoint failed"); return ""; }

    // Parse {"token":"eyJ..."} from JSON
    std::regex tok_re("\"token\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch m;
    if (std::regex_search(body, m, tok_re)) {
        LINF("Token: RSO access token acquired (%zu chars)", m[1].str().size());
        return m[1];
    }
    LDBG("Token: no token in response");
    return "";
}

std::string fetch_entitlements_token() {
    auto lf = read_lockfile();
    if (!lf) return "";

    auto body = riot_api_get(*lf, L"/entitlements/v1/token");
    if (body.empty()) return "";

    // Parse {"accessToken":"...","entitlements":[...],"token":"..."}
    // The entitlements JWT is in the "token" field
    std::regex tok_re("\"token\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch m;
    if (std::regex_search(body, m, tok_re)) {
        LINF("Token: entitlements token acquired (%zu chars)", m[1].str().size());
        return m[1];
    }
    return "";
}

} // namespace wraith::puuid
