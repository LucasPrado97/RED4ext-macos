// iOS hook backend for RED4ext (CyPort). iOS forbids writing code at run time, so hooks cannot be installed by
// patching the game's text the way Platform/NativeHook.cpp does on macOS. Instead CyPort's build
// (tools/ios_retarget.py, patch_baked_hooks) rewrites the entry of every function that may be hooked into
//     adrp x16, slot ; ldr x16, [x16] ; br x16
// before the app is signed, and the CyPort shim (libMacShim) owns the slots and a pass-through trampoline per site.
// Attaching a hook here is then a pointer write in __DATA, done through the shim's C API:
//     int MSBakedHookAttach(void* target, void* detour, void** original);   // 0 = ok, -1 = not a baked site
//     int MSBakedHookDetach(void* target, void* detour);                    // 0 = ok
// Only functions listed in CyPort's baked-hook table can be hooked; anything else fails like an unsupported site.

#include "Platform/NativeHook.hpp"
#include "Detail/AddressHashes.hpp"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <spdlog/spdlog.h>

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace
{
using AttachFn = int (*)(void*, void*, void**);
using DetachFn = int (*)(void*, void*);

struct Op
{
    void** ppPointer;
    void* detour;
    bool attach;
};

// Function-local statics: RED4ext's constructor (Main.cpp) can run before this file's globals are constructed.
std::mutex& Lock()
{
    static std::mutex m;
    return m;
}
std::vector<Op>& Pending()
{
    static std::vector<Op> v;
    return v;
}
std::unordered_map<uintptr_t, std::string>& Names()
{
    static std::unordered_map<uintptr_t, std::string> m;
    return m;
}

AttachFn ShimAttach()
{
    static auto fn = reinterpret_cast<AttachFn>(dlsym(RTLD_DEFAULT, "MSBakedHookAttach"));
    return fn;
}

DetachFn ShimDetach()
{
    static auto fn = reinterpret_cast<DetachFn>(dlsym(RTLD_DEFAULT, "MSBakedHookDetach"));
    return fn;
}

const char* NameOf(void* target)
{
    auto it = Names().find(reinterpret_cast<uintptr_t>(target));
    return it != Names().end() ? it->second.c_str() : "?";
}

const mach_header_64* MainHeader()
{
    return reinterpret_cast<const mach_header_64*>(_dyld_get_image_header(0));
}
} // namespace

namespace NativeHook
{
void Begin()
{
    std::lock_guard _(Lock());
    Pending().clear();
}

int32_t Attach(void** ppPointer, void* detour)
{
    if (ppPointer == nullptr || *ppPointer == nullptr || detour == nullptr)
    {
        return -1;
    }

    if (ShimAttach() == nullptr)
    {
        spdlog::error("[BakedHook] the CyPort shim has no MSBakedHookAttach: this app was built without baked hooks");
        return -1;
    }

    std::lock_guard _(Lock());
    Pending().push_back({ppPointer, detour, true});
    return 0;
}

int32_t Detach(void** ppPointer, void* detour)
{
    if (ppPointer == nullptr || *ppPointer == nullptr || ShimDetach() == nullptr)
    {
        return -1;
    }

    std::lock_guard _(Lock());
    Pending().push_back({ppPointer, detour, false});
    return 0;
}

int32_t Commit()
{
    std::lock_guard _(Lock());
    int32_t result = 0;
    for (auto& op : Pending())
    {
        void* target = *op.ppPointer;
        if (op.attach)
        {
            void* original = nullptr;
            const int rc = ShimAttach()(target, op.detour, &original);
            if (rc != 0 || original == nullptr)
            {
                spdlog::error("[BakedHook] {} at {}: not a baked site in this build (add it to CyPort's table)",
                              NameOf(target), fmt::ptr(target));
                result = -1;
                continue;
            }

            Names().emplace(reinterpret_cast<uintptr_t>(original), NameOf(target));
            *op.ppPointer = original;
            spdlog::info("[BakedHook] {} hooked at {}", NameOf(target), fmt::ptr(target));
        }
        else
        {
            // *ppPointer is the original we handed out; the shim finds the site by detour.
            if (ShimDetach()(target, op.detour) != 0)
            {
                result = -1;
            }
        }
    }

    Pending().clear();
    return result;
}

int32_t Abort()
{
    std::lock_guard _(Lock());
    Pending().clear();
    return 0;
}

void SetIdentity(void* target, const char* name, const char* owner)
{
    std::lock_guard _(Lock());
    Names()[reinterpret_cast<uintptr_t>(target)] =
        std::string(name ? name : "?") + " (" + (owner ? owner : "?") + ")";
}

const char* CoreHookName(uint32_t hash)
{
    switch (hash)
    {
    case Hashes::WinMain:
        return "Main";
    case Hashes::CGameApplication_AddState:
        return "CGameApplication_AddState";
    case Hashes::Global_ExecuteProcess:
        return "Global_ExecuteProcess";
    case Hashes::CBaseEngine_InitScripts:
        return "CBaseEngine_InitScripts";
    case Hashes::CBaseEngine_LoadScripts:
        return "CBaseEngine_LoadScripts";
    case Hashes::ScriptValidator_Validate:
        return "ScriptValidator_Validate";
    case Hashes::AssertionFailed:
        return "AssertionFailed";
    case Hashes::GameInstance_CollectSaveableSystems:
        return "GameInstance_CollectSaveableSystems";
    case Hashes::GsmState_SessionActive_ReportErrorCode:
        return "GsmState_SessionActive_ReportErrorCode";
    default:
        return nullptr;
    }
}

bool AllowWrites(const char* dbVersion, const char* dbUuid, const char* imageVersion, const char* imageUuid,
                 bool strict, char* logLine, size_t logCap)
{
    // No code is written on iOS; the baked sites were checked against the game build when the app was made.
    // Still refuse a database for another game build when strict, as on macOS.
    const bool mismatch = (dbUuid && imageUuid && dbUuid[0] && std::strcmp(dbUuid, imageUuid) != 0) ||
                          (dbVersion && imageVersion && dbVersion[0] && std::strcmp(dbVersion, imageVersion) != 0);
    if (strict && mismatch)
    {
        if (logLine && logCap)
        {
            std::snprintf(logLine, logCap, kRefuseCodeWritesFormat, dbVersion ? dbVersion : "",
                          imageVersion ? imageVersion : "", dbUuid ? dbUuid : "", imageUuid ? imageUuid : "");
        }
        return false;
    }
    return true;
}

bool WritesAllowed()
{
    return true;
}

uint32_t CopyProtectLog(ProtectOp*, uint32_t)
{
    return 0;
}

uint32_t CopyHookStats(HookInfo*, uint32_t)
{
    return 0;
}

bool WriteHookStats(const char*, int, const char*)
{
    return false;
}

void StartStatsThread(const char*, const char*)
{
}

void StopStatsThread()
{
}

RelocOut Relocate(uint32_t, uint64_t, uint64_t)
{
    return {};
}

void MainImageUuid(char* out, size_t cap)
{
    if (out == nullptr || cap == 0)
    {
        return;
    }

    out[0] = '\0';
    const mach_header_64* header = MainHeader();
    if (header == nullptr)
    {
        return;
    }

    const auto* command = reinterpret_cast<const load_command*>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i)
    {
        if (command->cmd == LC_UUID)
        {
            const auto* uuid = reinterpret_cast<const uuid_command*>(command);
            std::snprintf(out, cap, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                          uuid->uuid[0], uuid->uuid[1], uuid->uuid[2], uuid->uuid[3], uuid->uuid[4], uuid->uuid[5],
                          uuid->uuid[6], uuid->uuid[7], uuid->uuid[8], uuid->uuid[9], uuid->uuid[10], uuid->uuid[11],
                          uuid->uuid[12], uuid->uuid[13], uuid->uuid[14], uuid->uuid[15]);
            return;
        }

        command = reinterpret_cast<const load_command*>(reinterpret_cast<const uint8_t*>(command) + command->cmdsize);
    }
}

uint64_t MainImageBase()
{
    return reinterpret_cast<uint64_t>(MainHeader());
}
} // namespace NativeHook
