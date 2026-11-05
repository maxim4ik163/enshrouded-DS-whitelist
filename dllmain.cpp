// =====================================================================
//  Enshrouded dedicated-server admin whitelist  (proxy steam_api64.dll)
//
//  What it does
//  ------------
//  This DLL replaces steam_api64.dll next to enshrouded_server.exe.
//  * Every Steam export is forwarded, unchanged, to the renamed original
//    DLL (steam_api64_org.dll) via steam_api64.def.
//  * The ONE function we intercept is
//        SteamInternal_FindOrCreateGameServerInterface(...)
//    When the server asks Steam for its "SteamGameServer015" interface,
//    we patch a single slot of that interface's v-table:
//        ISteamGameServer::BeginAuthSession  (vtable offset +0xD0)
//  * Our BeginAuthSession runs on every incoming player. If the player's
//    SteamID64 is in enshrouded_whitelist.txt we let the real function
//    run (normal join); otherwise we return k_EBeginAuthSessionResultInvalidTicket
//    and the server cleanly rejects the connection.
//
//  Combined with an enshrouded_server.json that has a single, password-less
//  "Admin" group, the result is: only the listed SteamID64 accounts can
//  join, and they all join as Admin with no password.
//
//  Nothing here depends on any internal offset of enshrouded_server.exe,
//  so it survives game updates. The only Steam-side coupling is the
//  vtable layout of interface version "SteamGameServer015" (see VTBL_OFFSET
//  below), which is frozen by Steam's interface-versioning contract.
// =====================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_set>
#include <mutex>

// ---- ISteamGameServer::BeginAuthSession vtable byte offset -----------
// Verified by disassembling SteamAPI_ISteamGameServer_BeginAuthSession in
// the shipped steam_api64.dll:  mov rax,[rcx]; jmp [rax+0xD0]
// If a future Steam SDK bumps the interface past SteamGameServer015 and the
// server starts requesting the new version, re-derive this one number.
static const unsigned VTBL_OFFSET_BeginAuthSession = 0xD0;

// k_EBeginAuthSessionResultInvalidTicket (Steamworks enum value)
static const int kInvalidTicket = 1;

// ---------------------------------------------------------------------
//  Globals
// ---------------------------------------------------------------------
static std::once_flag             g_initOnce;
static HMODULE                    g_realSteam     = nullptr;
static char                       g_moduleDir[MAX_PATH] = {0};
static char                       g_wlPath[MAX_PATH]    = {0};
static char                       g_logPath[MAX_PATH]   = {0};

static std::mutex                 g_wlMutex;
static std::unordered_set<uint64_t> g_whitelist;
static FILETIME                   g_wlStamp = {0,0};

// real SteamInternal_FindOrCreateGameServerInterface
typedef void* (__cdecl *FindOrCreate_t)(int32_t hSteamUser, const char* pszVersion);
static FindOrCreate_t             g_realFindOrCreate = nullptr;

// original ISteamGameServer::BeginAuthSession
typedef int (__fastcall *BeginAuth_t)(void* self, const void* ticket,
                                      int cbTicket, uint64_t steamID);
static BeginAuth_t                g_origBeginAuth = nullptr;
static void**                     g_patchedVtbl   = nullptr;

// ---------------------------------------------------------------------
//  Logging (best-effort, never fatal)
// ---------------------------------------------------------------------
static void LogLine(const char* fmt, ...)
{
    FILE* f = nullptr;
    if (fopen_s(&f, g_logPath, "a") != 0 || !f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// ---------------------------------------------------------------------
//  Whitelist loading  (hot-reloads when the file's timestamp changes)
// ---------------------------------------------------------------------
static void LoadWhitelistLocked()
{
    FILE* f = nullptr;
    if (fopen_s(&f, g_wlPath, "rb") != 0 || !f) {
        LogLine("WARN  cannot open whitelist '%s' - ALL joins will be denied", g_wlPath);
        g_whitelist.clear();
        return;
    }
    std::unordered_set<uint64_t> fresh;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        // skip leading whitespace
        char* p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
        if (*p == '#' || *p == ';' || *p == '\0') continue;   // comment / blank
        // read the leading run of digits as the SteamID64
        uint64_t id = 0; bool any = false;
        while (*p >= '0' && *p <= '9') { id = id * 10 + (uint64_t)(*p - '0'); ++p; any = true; }
        if (any && id != 0) fresh.insert(id);
    }
    fclose(f);
    g_whitelist.swap(fresh);
    LogLine("INFO  whitelist loaded: %zu SteamID64 entries", g_whitelist.size());
}

static void EnsureWhitelistFresh()
{
    WIN32_FILE_ATTRIBUTE_DATA fad;
    std::lock_guard<std::mutex> lk(g_wlMutex);
    if (GetFileAttributesExA(g_wlPath, GetFileExInfoStandard, &fad)) {
        if (CompareFileTime(&fad.ftLastWriteTime, &g_wlStamp) != 0) {
            g_wlStamp = fad.ftLastWriteTime;
            LoadWhitelistLocked();
        }
    } else if (g_whitelist.empty() == false) {
        // file vanished - keep the last good list rather than lock everyone out
        LogLine("WARN  whitelist file missing; keeping last loaded list");
    } else {
        LoadWhitelistLocked();   // first attempt, file not there yet
    }
}

static bool IsAllowed(uint64_t steamID)
{
    EnsureWhitelistFresh();
    std::lock_guard<std::mutex> lk(g_wlMutex);
    return g_whitelist.find(steamID) != g_whitelist.end();
}

// ---------------------------------------------------------------------
//  Our BeginAuthSession detour
// ---------------------------------------------------------------------
static int __fastcall My_BeginAuthSession(void* self, const void* ticket,
                                          int cbTicket, uint64_t steamID)
{
    if (IsAllowed(steamID)) {
        LogLine("ALLOW SteamID64=%llu", (unsigned long long)steamID);
        return g_origBeginAuth(self, ticket, cbTicket, steamID);
    }
    LogLine("DENY  SteamID64=%llu (not whitelisted)", (unsigned long long)steamID);
    return kInvalidTicket;     // server drops the connection as a bad ticket
}

// ---------------------------------------------------------------------
//  Patch one slot of the ISteamGameServer vtable
// ---------------------------------------------------------------------
static void PatchGameServerVtbl(void* iface)
{
    void** vtbl = *reinterpret_cast<void***>(iface);
    if (!vtbl) return;

    void** slot = reinterpret_cast<void**>(
        reinterpret_cast<uint8_t*>(vtbl) + VTBL_OFFSET_BeginAuthSession);

    // already patched (same server object / shared vtable)?
    if (*slot == reinterpret_cast<void*>(&My_BeginAuthSession)) return;

    DWORD oldProt = 0;
    if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProt)) {
        LogLine("ERROR VirtualProtect failed (%lu) - whitelist NOT armed", GetLastError());
        return;
    }
    g_origBeginAuth = reinterpret_cast<BeginAuth_t>(*slot);
    *slot = reinterpret_cast<void*>(&My_BeginAuthSession);
    VirtualProtect(slot, sizeof(void*), oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(void*));

    g_patchedVtbl = vtbl;
    LogLine("INFO  BeginAuthSession hooked (vtbl=%p, orig=%p)", (void*)vtbl, (void*)g_origBeginAuth);
}

// ---------------------------------------------------------------------
//  Lazy init (runs on first interface request, i.e. outside loader lock)
// ---------------------------------------------------------------------
static void InitOnce()
{
    // locate our own directory
    HMODULE self = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCSTR>(&InitOnce), &self);
    GetModuleFileNameA(self, g_moduleDir, MAX_PATH);
    char* slash = strrchr(g_moduleDir, '\\');
    if (slash) *slash = '\0'; else g_moduleDir[0] = '\0';

    _snprintf_s(g_wlPath,  MAX_PATH, _TRUNCATE, "%s\\enshrouded_whitelist.txt", g_moduleDir);
    _snprintf_s(g_logPath, MAX_PATH, _TRUNCATE, "%s\\enshrouded_whitelist.log", g_moduleDir);

    LogLine("==== Enshrouded admin whitelist proxy loaded ====");

    // load the renamed original and resolve the real factory
    char realPath[MAX_PATH];
    _snprintf_s(realPath, MAX_PATH, _TRUNCATE, "%s\\steam_api64_org.dll", g_moduleDir);
    g_realSteam = LoadLibraryA(realPath);
    if (!g_realSteam) g_realSteam = LoadLibraryA("steam_api64_org.dll");
    if (!g_realSteam) {
        LogLine("FATAL cannot load steam_api64_org.dll (%lu)", GetLastError());
        return;
    }
    g_realFindOrCreate = reinterpret_cast<FindOrCreate_t>(
        GetProcAddress(g_realSteam, "SteamInternal_FindOrCreateGameServerInterface"));
    if (!g_realFindOrCreate)
        LogLine("FATAL cannot resolve real SteamInternal_FindOrCreateGameServerInterface");

    EnsureWhitelistFresh();     // prime the list + timestamp
}

// ---------------------------------------------------------------------
//  Exported, hooked factory (named in steam_api64.def)
// ---------------------------------------------------------------------
extern "C" __declspec(dllexport)
void* My_FindOrCreateGameServerInterface(int32_t hSteamUser, const char* pszVersion)
{
    std::call_once(g_initOnce, InitOnce);

    void* iface = g_realFindOrCreate ? g_realFindOrCreate(hSteamUser, pszVersion) : nullptr;

    // Only the game-server interface carries BeginAuthSession.
    if (iface && pszVersion && strncmp(pszVersion, "SteamGameServer", 15) == 0)
        PatchGameServerVtbl(iface);

    return iface;
}

// ---------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // Keep DllMain tiny: no LoadLibrary here (loader lock). Real init is
        // deferred to the first SteamInternal_FindOrCreateGameServerInterface call.
    }
    return TRUE;
}
