#include "entity.h"
#include <windows.h>
#include <iostream>

Memory* mem = new Memory(L"cs2.exe");
uintptr_t client = mem->GetModuleBaseAddress(L"client.dll");
uintptr_t server = mem->GetModuleBaseAddress(L"server.dll");
uintptr_t engine = mem->GetModuleBaseAddress(L"engine2.dll");
view_matrix_t vm;
int playercount = 0;

std::vector<player_t> cache;
std::vector<CacheEntry> entityCache;
const uint64_t CACHE_UPDATE_INTERVAL = 1;

namespace localplayer {
    uintptr_t base = 0;
    int health = 0, team = 0;

    void update() {
        while (true) {
            uintptr_t pawn = mem->ReadMemory<uintptr_t>(client + cs2_dumper::offsets::client_dll::dwLocalPlayerPawn);
            if (pawn) {
                base = pawn;
                health = mem->ReadMemory<int>(base + cs2_dumper::schemas::client_dll::C_BaseEntity::m_iHealth);
                team = mem->ReadMemory<int>(base + cs2_dumper::schemas::client_dll::C_BaseEntity::m_iTeamNum);
            }
            Sleep(5);
        }
    }
}

void loop() {
    entityCache.resize(64);

    while (true) {
        std::vector<player_t> tempcache;

        uintptr_t entitylist = mem->ReadMemory<uintptr_t>(client + cs2_dumper::offsets::client_dll::dwEntityList);
        if (!entitylist) { Sleep(100); continue; }

        uintptr_t listentry = mem->ReadMemory<uintptr_t>(entitylist + 0x10);
        if (!listentry) { Sleep(100); continue; }

        uint64_t curTime = GetTickCount64();

        for (int i = 0; i < 64; ++i) {
            uintptr_t controller = mem->ReadMemory<uintptr_t>(listentry + i * 0x70);
            if (!controller) continue;

            int pawnHandle = mem->ReadMemory<int>(controller + cs2_dumper::schemas::client_dll::CCSPlayerController::m_hPlayerPawn);
            if (!pawnHandle) continue;

            uintptr_t listEntry2 = mem->ReadMemory<uintptr_t>(entitylist + 0x8 * ((pawnHandle & 0x7FFF) >> 9) + 0x10);
            if (!listEntry2) continue;

            uintptr_t entityPawn = mem->ReadMemory<uintptr_t>(listEntry2 + 0x70 * (pawnHandle & 0x1FF));
            if (!entityPawn || entityPawn == localplayer::base) continue;

            int health = mem->ReadMemory<int>(entityPawn + cs2_dumper::schemas::client_dll::C_BaseEntity::m_iHealth);
            int team = mem->ReadMemory<int>(entityPawn + cs2_dumper::schemas::client_dll::C_BaseEntity::m_iTeamNum);

            if (health <= 0 || health > 100 || team == localplayer::team) continue;

            player_t p;
            p.base = entityPawn;
            p.health = health;
            p.team = team;
            p.pos = mem->ReadMemory<vec3>(entityPawn + cs2_dumper::schemas::client_dll::C_BasePlayerPawn::m_vOldOrigin);

            // Cache check
            if (entityCache[i].playerData.base == entityPawn && (curTime - entityCache[i].lastUpdate) < CACHE_UPDATE_INTERVAL) {
                tempcache.push_back(entityCache[i].playerData);
                continue;
            }

            entityCache[i].playerData = p;
            entityCache[i].lastUpdate = curTime;
            tempcache.push_back(p);
        }

        cache = tempcache;
        playercount = (int)cache.size();
        // Optional: log
        // std::cout << "Player count: " << playercount << std::endl;

        Sleep(5);
    }
}

void init() {
    std::thread(loop).detach();
    std::thread(localplayer::update).detach();
}
