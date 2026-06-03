#include "wraith.h"
#include <winternl.h>

// Undocumented but stable ntdll structures for process metadata spoofing
typedef struct _UNICODE_STR {
    USHORT Length, MaximumLength;
    PWSTR Buffer;
} UNICODE_STR;

typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG);

namespace wraith::stealth {

// ============================================================================
// "Temporal Cloaking" — stealth primitives
// ============================================================================

bool kill_vgc() {
    LINF("Stealth: silencing real VGC...");
    bool killed = false;

    // Stop the VGC service if running
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceA(scm, "vgc", SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS ss;
            if (ControlService(svc, SERVICE_CONTROL_STOP, &ss)) {
                LINF("Stealth: VGC service stop requested");
                // Wait for it to actually stop
                for (int i = 0; i < 20; i++) {
                    if (QueryServiceStatus(svc, &ss) && ss.dwCurrentState == SERVICE_STOPPED) break;
                    Sleep(250);
                }
            }
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    // Kill any lingering vgc.exe processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"vgc.exe") == 0) {
                    HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (proc) {
                        TerminateProcess(proc, 0);
                        CloseHandle(proc);
                        killed = true;
                        LINF("Stealth: killed vgc.exe (PID %u)", pe.th32ProcessID);
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    return killed;
}

bool spoof_process_name(const wchar_t* name) {
    // Spoof our process command line in PEB to look like real vgc.exe
    // This makes us appear as "C:\Program Files\Riot Vanguard\vgc.exe" in
    // Task Manager, Process Explorer, and game client queries.
#ifdef _WIN64
    // Access PEB via TEB->PEB
    auto teb = (PTEB)NtCurrentTeb();
    if (!teb || !teb->ProcessEnvironmentBlock) return false;

    auto peb = teb->ProcessEnvironmentBlock;
    auto params = peb->ProcessParameters;
    if (!params) return false;

    // Overwrite ImagePathName and CommandLine
    // These are what Task Manager / EnumProcesses reads
    size_t name_len = wcslen(name);
    size_t byte_len = name_len * sizeof(wchar_t);

    // Allocate new buffer for the spoofed path
    wchar_t* buf = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, byte_len + 2);
    if (!buf) return false;
    wcscpy_s(buf, name_len + 1, name);

    // Overwrite UNICODE_STRING fields
    params->ImagePathName.Buffer = buf;
    params->ImagePathName.Length = (USHORT)byte_len;
    params->ImagePathName.MaximumLength = (USHORT)(byte_len + 2);

    // Also spoof command line
    std::wstring cmdline = std::wstring(name) + L" --service";
    wchar_t* clbuf = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        (cmdline.size() + 1) * sizeof(wchar_t));
    if (clbuf) {
        wcscpy_s(clbuf, cmdline.size() + 1, cmdline.c_str());
        params->CommandLine.Buffer = clbuf;
        params->CommandLine.Length = (USHORT)(cmdline.size() * sizeof(wchar_t));
        params->CommandLine.MaximumLength = (USHORT)((cmdline.size() + 1) * sizeof(wchar_t));
    }

    LINF("Stealth: spoofed process to %ls", name);
#endif
    return true;
}

bool hide_console_window() {
    HWND con = GetConsoleWindow();
    if (con) {
        // Don't hide completely — minimize to tray would be ideal
        // For now, just set a VGC-like window title
        SetConsoleTitleW(L"Vanguard User-Mode Client");
        return true;
    }
    return false;
}

std::string get_machine_guid() {
    // HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid — unique per install
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &k) != ERROR_SUCCESS)
        return "";
    char buf[64] = {}; DWORD sz = sizeof(buf);
    RegQueryValueExA(k, "MachineGuid", nullptr, nullptr, (LPBYTE)buf, &sz);
    RegCloseKey(k);
    return std::string(buf);
}

std::string generate_pipe_name() {
    // VGC generates its pipe name from the machine GUID
    // Pattern: riot-vgc-{machine-guid-lower}
    std::string guid = get_machine_guid();
    std::transform(guid.begin(), guid.end(), guid.begin(), ::tolower);
    return std::string(PIPE_PREFIX) + guid;
}

void add_timing_jitter(uint32_t base_ms) {
    // Real VGC has natural timing variation due to processing.
    // We add Gaussian-distributed jitter to match the statistical profile.
    // Mean: 0ms, Stddev: base_ms * 0.05 (5% jitter)
    static std::mt19937 rng(std::random_device{}());
    std::normal_distribution<double> dist(0.0, base_ms * 0.05);
    int jitter = (int)dist(rng);
    jitter = std::clamp(jitter, -(int)(base_ms / 4), (int)(base_ms / 4));
    if (jitter > 0) Sleep((DWORD)jitter);
}

void cleanup() {
    LINF("Stealth: cleaning up artifacts...");
    // No persistent artifacts to clean — we don't write registry or files
    // The pipe is automatically cleaned up when the handle is closed
    // The WinHTTP session is cleaned up in Client destructor
}

} // namespace wraith::stealth
