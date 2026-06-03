#include "wraith.h"
#include <cstring>

namespace wraith::pipe {

// Wire format (from RE of VanguardSDK::Message @ sub_56480DEF0):
//   [4B length LE][4B msg_id LE][payload...]
// length includes the 8-byte header.

static constexpr DWORD BUF_SZ = 65536;

Server::Server(const std::string& name) : name_(name) {}

Server::~Server() { stop(); }

void Server::start() {
    if (run_.exchange(true)) return;
    LINF("Pipe: starting \\\\.\\pipe\\%s", name_.c_str());
    accept_t_ = std::thread(&Server::accept_loop, this);
}

void Server::stop() {
    if (!run_.exchange(false)) return;
    // Wake accept_loop by connecting as dummy client
    std::string full = "\\\\.\\pipe\\" + name_;
    HANDLE dummy = CreateFileA(full.c_str(), GENERIC_READ|GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (dummy != INVALID_HANDLE_VALUE) CloseHandle(dummy);
    if (accept_t_.joinable()) accept_t_.join();
    std::lock_guard lk(mu_);
    for (auto& [id, c] : conns_) {
        c->up = false;
        if (c->h != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(c->h); CloseHandle(c->h); }
        if (c->t.joinable()) c->t.join();
    }
    conns_.clear();
}

bool Server::send(uint32_t cid, const Msg& m) {
    std::lock_guard lk(mu_);
    auto it = conns_.find(cid);
    if (it == conns_.end() || !it->second->up) return false;
    return write_msg(it->second->h, m);
}

void Server::accept_loop() {
    while (run_) {
        std::string full = "\\\\.\\pipe\\" + name_;
        HANDLE h = CreateNamedPipeA(full.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, BUF_SZ, BUF_SZ, 5000, nullptr);
        if (h == INVALID_HANDLE_VALUE) { Sleep(500); continue; }

        BOOL ok = ConnectNamedPipe(h, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!run_) { CloseHandle(h); break; }
        if (ok) {
            uint32_t cid = next_cid_++;
            LINF("Pipe: client %u connected", cid);
            auto c = std::make_unique<Conn>();
            c->h = h;
            c->t = std::thread(&Server::client_loop, this, h, cid);
            std::lock_guard lk(mu_);
            conns_[cid] = std::move(c);
        } else CloseHandle(h);
    }
}

void Server::client_loop(HANDLE h, uint32_t cid) {
    while (run_) {
        Msg m;
        if (!read_msg(h, m)) break;
        LDBG("Pipe: recv cid=%u msg_id=%u %zu bytes", cid, m.id, m.payload.size());
        if (h_) h_(cid, m);
    }
    LINF("Pipe: client %u disconnected", cid);
    std::lock_guard lk(mu_);
    auto it = conns_.find(cid);
    if (it != conns_.end()) { it->second->up = false; DisconnectNamedPipe(h); CloseHandle(h); }
}

bool Server::read_msg(HANDLE h, Msg& m) {
    uint8_t hdr[8];
    DWORD rd = 0;
    if (!ReadFile(h, hdr, 8, &rd, nullptr) || rd != 8) return false;
    uint32_t len = *(uint32_t*)&hdr[0];
    m.id = *(uint32_t*)&hdr[4];
    if (len < 8 || len > 1048576) return false;
    uint32_t plen = len - 8;
    m.payload.resize(plen);
    DWORD off = 0;
    while (off < plen) {
        DWORD chunk = 0;
        if (!ReadFile(h, m.payload.data() + off, plen - off, &chunk, nullptr) || !chunk) return false;
        off += chunk;
    }
    return true;
}

bool Server::write_msg(HANDLE h, const Msg& m) {
    uint32_t len = 8 + (uint32_t)m.payload.size();
    std::vector<uint8_t> wire(len);
    *(uint32_t*)&wire[0] = len;
    *(uint32_t*)&wire[4] = m.id;
    if (!m.payload.empty()) memcpy(&wire[8], m.payload.data(), m.payload.size());
    DWORD w = 0;
    return WriteFile(h, wire.data(), len, &w, nullptr) && w == len;
}

} // namespace wraith::pipe
