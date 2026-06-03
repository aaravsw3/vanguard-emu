#include "wraith.h"

namespace wraith::launch {

// ============================================================================
// Auto-detect Riot/Valorant installation paths
// ============================================================================

static std::wstring reg_wstr(HKEY root, const wchar_t* sub, const wchar_t* val) {
    HKEY k;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return L"";
    wchar_t buf[MAX_PATH] = {}; DWORD sz = sizeof(buf), type = 0;
    RegQueryValueExW(k, val, nullptr, &type, (LPBYTE)buf, &sz);
    RegCloseKey(k);
    return (type == REG_SZ) ? std::wstring(buf) : L"";
}

static bool file_exists(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

Paths detect_paths() {
    Paths p;

    // Riot Client — check common locations
    auto rc_path = reg_wstr(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Riot Game valorant.live",
        L"UninstallString");
    if (!rc_path.empty()) {
        // UninstallString usually points to "C:\Riot Games\Riot Client\RiotClientServices.exe" --uninstall-...
        auto pos = rc_path.find(L"RiotClientServices.exe");
        if (pos != std::wstring::npos) {
            // Extract just the directory
            p.riot_client = rc_path.substr(0, pos + wcslen(L"RiotClientServices.exe"));
            // Remove quotes if present
            if (!p.riot_client.empty() && p.riot_client[0] == L'"')
                p.riot_client = p.riot_client.substr(1);
        }
    }

    // Try standard locations
    std::wstring standard_paths[] = {
        L"C:\\Riot Games\\Riot Client\\RiotClientServices.exe",
        L"D:\\Riot Games\\Riot Client\\RiotClientServices.exe",
        L"C:\\Program Files\\Riot Games\\Riot Client\\RiotClientServices.exe",
    };
    if (p.riot_client.empty() || !file_exists(p.riot_client)) {
        for (auto& sp : standard_paths) {
            if (file_exists(sp)) { p.riot_client = sp; break; }
        }
    }

    // Valorant executable
    auto val_path = reg_wstr(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Riot Game valorant.live",
        L"InstallLocation");
    if (!val_path.empty()) {
        p.valorant_exe = val_path + L"\\VALORANT\\live\\ShooterGame\\Binaries\\Win64\\VALORANT-Win64-Shipping.exe";
    }
    if (p.valorant_exe.empty() || !file_exists(p.valorant_exe)) {
        std::wstring val_standards[] = {
            L"C:\\Riot Games\\VALORANT\\live\\ShooterGame\\Binaries\\Win64\\VALORANT-Win64-Shipping.exe",
            L"D:\\Riot Games\\VALORANT\\live\\ShooterGame\\Binaries\\Win64\\VALORANT-Win64-Shipping.exe",
        };
        for (auto& sp : val_standards) {
            if (file_exists(sp)) { p.valorant_exe = sp; break; }
        }
    }

    // Vanguard directory
    p.vanguard_dir = L"C:\\Program Files\\Riot Vanguard";
    if (!file_exists(p.vanguard_dir))
        p.vanguard_dir = L"";

    LINF("Launcher: riot_client = %ls", p.riot_client.empty() ? L"(not found)" : p.riot_client.c_str());
    LINF("Launcher: valorant    = %ls", p.valorant_exe.empty() ? L"(not found)" : p.valorant_exe.c_str());
    LINF("Launcher: vanguard    = %ls", p.vanguard_dir.empty() ? L"(not found)" : p.vanguard_dir.c_str());

    return p;
}

bool start_valorant(const Paths& p) {
    // Launch via Riot Client (proper way — handles login, patching, etc.)
    // If Riot Client not found, try launching Valorant directly
    std::wstring exe, args;

    if (!p.riot_client.empty() && file_exists(p.riot_client)) {
        exe = p.riot_client;
        // --launch-product=valorant --launch-patchline=live
        args = L"--launch-product=valorant --launch-patchline=live";
        LINF("Launcher: starting via Riot Client");
    } else if (!p.valorant_exe.empty() && file_exists(p.valorant_exe)) {
        exe = p.valorant_exe;
        args = L"";
        LINF("Launcher: starting Valorant directly (no Riot Client)");
    } else {
        LERR("Launcher: no Valorant installation found");
        return false;
    }

    STARTUPINFOW si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    std::wstring cmdline = L"\"" + exe + L"\" " + args;
    std::vector<wchar_t> cmdline_buf(cmdline.begin(), cmdline.end());
    cmdline_buf.push_back(0);

    BOOL ok = CreateProcessW(
        nullptr,
        cmdline_buf.data(),
        nullptr, nullptr, FALSE,
        0, nullptr, nullptr,
        &si, &pi);

    if (!ok) {
        LERR("Launcher: CreateProcess failed: %u", GetLastError());
        return false;
    }

    LINF("Launcher: started PID %u", pi.dwProcessId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool wait_for_game_exit(uint32_t timeout_sec) {
    // Monitor for VALORANT-Win64-Shipping.exe process
    LINF("Launcher: waiting for game process...");

    DWORD start = GetTickCount();
    DWORD game_pid = 0;

    // First, wait for the game to appear
    for (int attempt = 0; attempt < 300; attempt++) {  // 5 min max wait
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) {
                        game_pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        if (game_pid) break;
        Sleep(1000);
    }

    if (!game_pid) {
        LWRN("Launcher: game process not detected within timeout");
        return false;
    }

    LINF("Launcher: game running (PID %u)", game_pid);

    // Now wait for it to exit
    HANDLE proc = OpenProcess(SYNCHRONIZE, FALSE, game_pid);
    if (proc) {
        DWORD wait_ms = timeout_sec ? (timeout_sec * 1000) : INFINITE;
        WaitForSingleObject(proc, wait_ms);
        CloseHandle(proc);
    } else {
        // Fallback: poll for process existence
        while (true) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            bool alive = false;
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        if (pe.th32ProcessID == game_pid) { alive = true; break; }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
            if (!alive) break;
            Sleep(2000);
        }
    }

    LINF("Launcher: game exited");
    return true;
}

} // namespace wraith::launch
