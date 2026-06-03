#include "wraith.h"

namespace wraith::gw {

Client::Client(const Config& c) : cfg_(c) {
    // User-Agent matching real VGC (from .rdata @ 0x564bd1358)
    std::string ua = "vanguard/" + std::string(VANGUARD_VERSION);
    std::wstring wua(ua.begin(), ua.end());

    session_ = WinHttpOpen(wua.c_str(),
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session_) { LERR("WinHttpOpen failed: %u", GetLastError()); return; }

    // Enable TLS 1.2/1.3 — real VGC uses TLS 1.3 with OpenSSL
    DWORD opts = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    WinHttpSetOption(session_, WINHTTP_OPTION_SECURE_PROTOCOLS, &opts, sizeof(opts));

    // Disable redirects (real VGC doesn't follow redirects)
    DWORD noRedirect = WINHTTP_DISABLE_REDIRECTS;
    WinHttpSetOption(session_, WINHTTP_OPTION_DISABLE_FEATURE, &noRedirect, sizeof(noRedirect));

    // Connect to gateway
    char domain[256];
    snprintf(domain, sizeof(domain), GATEWAY_DOMAIN_FMT, cfg_.region.c_str());
    std::wstring wdomain(domain, domain + strlen(domain));

    connect_ = WinHttpConnect(session_, wdomain.c_str(), GATEWAY_PORT, 0);
    if (!connect_) { LERR("WinHttpConnect failed: %u", GetLastError()); }
    else { LINF("Gateway: connected to %s:%d", domain, GATEWAY_PORT); }
}

Client::~Client() {
    if (connect_) WinHttpCloseHandle(connect_);
    if (session_) WinHttpCloseHandle(session_);
}

Resp Client::post(const std::vector<uint8_t>& payload,
    EnvMsgType msg_type, const std::string& machine_id) {
    Resp resp;
    if (!connect_) { resp.err = "not connected"; return resp; }

    std::wstring wpath(GATEWAY_PATH, GATEWAY_PATH + strlen(GATEWAY_PATH));

    HINTERNET req = WinHttpOpenRequest(connect_, L"POST", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!req) { resp.err = "OpenRequest failed"; return resp; }

    // Disable certificate validation (real VGC does SPKI pinning, we skip)
    DWORD sec = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));

    // Build headers matching real VGC (RE @ 0x564bd1678..0x564bd1698)
    std::wstring headers;
    headers += L"Content-Type: application/x-protobuf\r\n";
    headers += L"User-Agent: vanguard/1.18.2-25+20260501.225940\r\n";
    // X-VG-0: machine identifier
    if (!machine_id.empty()) {
        std::wstring mid_w(machine_id.begin(), machine_id.end());
        headers += L"X-VG-0: " + mid_w + L"\r\n";
    }
    // X-VG-1: envelope message type
    headers += L"X-VG-1: " + std::to_wstring((uint32_t)msg_type) + L"\r\n";
    // X-VG-2: player UUID
    if (!cfg_.puuid.empty()) {
        std::wstring puuid_w(cfg_.puuid.begin(), cfg_.puuid.end());
        headers += L"X-VG-2: " + puuid_w + L"\r\n";
    }
    // X-VG-3: protocol version
    headers += L"X-VG-3: 1\r\n";
    // X-VG-4: entitlements token
    if (!cfg_.entitlements.empty()) {
        std::wstring ent_w(cfg_.entitlements.begin(), cfg_.entitlements.end());
        headers += L"X-VG-4: " + ent_w + L"\r\n";
    }

    BOOL ok = WinHttpSendRequest(req, headers.c_str(), (DWORD)headers.size(),
        (LPVOID)payload.data(), (DWORD)payload.size(), (DWORD)payload.size(), 0);
    if (!ok) {
        resp.err = "SendRequest failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(req);
        return resp;
    }

    ok = WinHttpReceiveResponse(req, nullptr);
    if (!ok) {
        resp.err = "ReceiveResponse failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(req);
        return resp;
    }

    // Read status code
    DWORD code = 0, sz = sizeof(code);
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
    resp.code = (int)code;

    // Read body
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
        std::vector<uint8_t> chunk(avail);
        DWORD read = 0;
        if (WinHttpReadData(req, chunk.data(), avail, &read)) {
            resp.body.insert(resp.body.end(), chunk.begin(), chunk.begin() + read);
        }
        avail = 0;
    }

    // Log response headers for debugging
    if (resp.code != 200) {
        DWORD hdr_sz = 0;
        WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
            WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &hdr_sz, WINHTTP_NO_HEADER_INDEX);
        if (hdr_sz > 0) {
            std::wstring rh(hdr_sz / sizeof(wchar_t), L'\0');
            WinHttpQueryHeaders(req, WINHTTP_QUERY_RAW_HEADERS_CRLF,
                WINHTTP_HEADER_NAME_BY_INDEX, rh.data(), &hdr_sz, WINHTTP_NO_HEADER_INDEX);
            std::string rh_a(rh.begin(), rh.end());
            LDBG("Response headers:\n%s", rh_a.c_str());
        }
    }

    LDBG("Gateway: POST %s -> HTTP %d (%zu bytes)",
         GATEWAY_PATH, resp.code, resp.body.size());

    WinHttpCloseHandle(req);
    return resp;
}

} // namespace wraith::gw
