#include <windows.h>
#include <string.h>
#include "bearssl.h"

static int
wince_seed(const br_prng_class **ctx)
{
    br_hmac_drbg_context *rc;
    unsigned char seed[64];
    SYSTEMTIME st;
    FILETIME ft;
    DWORD tc;
    DWORD pid;
    DWORD tid;
    int i;

    if (ctx == NULL || *ctx == NULL) {
        return 0;
    }

    rc = (br_hmac_drbg_context *)(void *)ctx;

    memset(seed, 0, sizeof(seed));

    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    tc = GetTickCount();
    pid = GetCurrentProcessId();
    tid = GetCurrentThreadId();

    memcpy(seed + 0, &ft.dwLowDateTime, sizeof(ft.dwLowDateTime));
    memcpy(seed + 4, &ft.dwHighDateTime, sizeof(ft.dwHighDateTime));
    memcpy(seed + 8, &tc, sizeof(tc));
    memcpy(seed + 12, &pid, sizeof(pid));
    memcpy(seed + 16, &tid, sizeof(tid));
    memcpy(seed + 20, &st, sizeof(st) < 32 ? sizeof(st) : 32);

    for (i = 32; i < 64; i++) {
        seed[i] = (unsigned char)(tc + i * 37 + (ft.dwLowDateTime >> (i & 7)));
    }

    br_hmac_drbg_update(rc, seed, sizeof(seed));
    return 1;
}

br_prng_seeder
br_prng_seeder_system(const char **name)
{
    if (name != 0) {
        *name = "wince-basic";
    }
    return &wince_seed;
}