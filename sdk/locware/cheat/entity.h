#pragma once
#include <lib/memory/memory.h>
#include <lib/vector.h>
#include <a2x/client_dll.hpp>
#include <a2x/offsets.hpp>
#include <vector>
#include <thread>

extern Memory* mem;
extern uintptr_t client;
extern uintptr_t server;
extern uintptr_t engine;
extern view_matrix_t vm;
extern int playercount;

namespace localplayer {
    extern uintptr_t base;
    extern int health, team;
    void update();
}

struct player_t {
    vec3 pos;
    int health;
    int team;
    uintptr_t base;

    bool IsValid() const {
        return health > 0 && health <= 100;
    }
};

struct CacheEntry {
    player_t playerData;
    uint64_t lastUpdate;
};

extern std::vector<player_t> cache;
extern std::vector<CacheEntry> entityCache;
extern const uint64_t CACHE_UPDATE_INTERVAL;

void loop();
void init();
