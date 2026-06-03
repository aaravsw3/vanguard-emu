#include "wraith.h"
#include <intrin.h>

namespace wraith::fp {

static std::string reg_str(const char* sub, const char* val) {
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ, &k) != ERROR_SUCCESS)
        return "";
    char buf[256] = {}; DWORD sz = sizeof(buf), type = 0;
    RegQueryValueExA(k, val, nullptr, &type, (LPBYTE)buf, &sz);
    RegCloseKey(k);
    return (type == REG_SZ && sz > 0) ? std::string(buf, sz - 1) : "";
}

static std::string cpu_brand() {
    int ci[4]; char s[49] = {};
    __cpuid(ci, 0x80000002); memcpy(s,      ci, 16);
    __cpuid(ci, 0x80000003); memcpy(s + 16, ci, 16);
    __cpuid(ci, 0x80000004); memcpy(s + 32, ci, 16);
    std::string r(s);
    while (!r.empty() && r.back() == ' ') r.pop_back();
    return r;
}

static void fill_os(OSInfo& o) {
    // vanguard.OSInfo (serializer @ sub_5647DBD20):
    //   field 1: varint (os_type) — 0 = default (skip)
    //   field 2: varint (os_build) — 0 = default (skip)
    //   field 3: string (variant)
    //   field 4: string (version)
    o.variant = "Windows";
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    using Fn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto fn = (Fn)GetProcAddress(ntdll, "RtlGetVersion");
    if (!fn) return;
    RTL_OSVERSIONINFOW v{}; v.dwOSVersionInfoSize = sizeof(v);
    if (fn(&v) == 0) {
        o.version = std::to_string(v.dwMajorVersion) + "." +
                    std::to_string(v.dwMinorVersion) + "." +
                    std::to_string(v.dwBuildNumber);
        // These varints are conditionally serialized only if non-zero
        // Real VGC likely sets os_type to major version and os_build to build number
        o.os_type = v.dwMajorVersion;
        o.os_build = v.dwBuildNumber;
    }
}

static std::string gpu_brand() {
    std::string desc = reg_str("SYSTEM\\CurrentControlSet\\Control\\Class\\"
                      "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc");
    if (desc.empty()) return "Unknown";
    // Extract brand from description (e.g. "NVIDIA GeForce RTX 3080" -> "NVIDIA")
    if (desc.find("NVIDIA") != std::string::npos) return "NVIDIA";
    if (desc.find("AMD") != std::string::npos || desc.find("Radeon") != std::string::npos) return "AMD";
    if (desc.find("Intel") != std::string::npos) return "Intel";
    return desc.substr(0, desc.find(' '));
}

static std::string gpu_model() {
    return reg_str("SYSTEM\\CurrentControlSet\\Control\\Class\\"
                   "{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc");
}

DevInfo collect() {
    LINF("Fingerprint: collecting device info...");
    DevInfo d;
    // DeviceInfo is just map<string,string> (parser @ sub_5647E9D00)
    std::string mid = machine_id();
    std::string brand = cpu_brand();
    std::string gmodel = gpu_model();
    std::string gbrand = gpu_brand();
    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    d.info["machine_id"] = mid;
    d.info["cpu_brand"] = brand;
    d.info["cpu_cores"] = std::to_string(si.dwNumberOfProcessors);
    d.info["gpu_brand"] = gbrand;
    d.info["gpu_model"] = gmodel;
    d.info["mem_total"] = std::to_string(ms.ullTotalPhys);
    // OS fingerprint for attestation blob
    {
        OSInfo tmp_os;
        fill_os(tmp_os);
        d.info["os_fp"] = tmp_os.variant + " " + tmp_os.version;
    }
    d.info["boot_mode"] = "normal";
    d.info["uefi"] = "true";

    LINF("  cpu=%s gpu=%s ram=%lluMB",
         brand.c_str(), gmodel.c_str(), ms.ullTotalPhys/(1024*1024));
    return d;
}

AppInfo app_info(const std::string& gid, const std::string& ver) {
    return {gid, ver};
}

std::string machine_id() {
    // SHA-256 of SMBIOS serials — matches VGK's HWID derivation
    auto bios = reg_str("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemSerialNumber");
    auto mobo = reg_str("HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardSerialNumber");
    auto disk = reg_str("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\"
                         "Target Id 0\\Logical Unit Id 0", "SerialNumber");

    std::string combined = bios + "|" + mobo + "|" + disk;

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hh = nullptr;
    uint8_t hash[32] = {};
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        if (BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0) == 0) {
            BCryptHashData(hh, (PUCHAR)combined.data(), (ULONG)combined.size(), 0);
            BCryptFinishHash(hh, hash, 32, 0);
            BCryptDestroyHash(hh);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }

    std::ostringstream oss;
    for (auto b : hash) oss << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return oss.str();
}

} // namespace wraith::fp
