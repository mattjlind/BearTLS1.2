# BearTLS

Windows Mobile / WinCE TLS helper DLL built on BearSSL.

This project builds `wm_https.dll`, which exposes a small C API for:
- HTTPS GET requests
- Generic HTTPS requests (custom method/headers/body)
- Raw TLS text exchange (for simple protocol scripting)
- Streaming TLS reads/writes for binary protocols and large transfers

## Projects in Solution

- `BearTLS` (DLL): builds `wm_https.dll` + `wm_https.lib`
- `BearTLS_example` (EXE): direct HTTPS sample client using the static API
- `dll_smoketest` (EXE): `LoadLibrary`/`GetProcAddress` smoke test for `wm_https.dll`

## Platform/Config Notes

The solution now contains:
- `Pocket PC 2003 (ARMV4)`
- `Windows Mobile 5.0 Pocket PC SDK (ARMV4I)`
- `Windows Mobile 6 Professional SDK (ARMV4I)`

### WM2003 compatibility settings

For `Pocket PC 2003 (ARMV4)` builds, these settings are important:
- CE target macros: `_WIN32_WCE=420`, `WINVER=0x0420`
- Stack cookie disabled for WM2003 only: `/GS-`
- Linker subsystem forced: `/SUBSYSTEM:WINDOWSCE,4.20`
- ARM machine forced to avoid Thumb loader issues on WM2003: `/MACHINE:ARM` (`TargetMachine=3`)

WM5/WM6 configs keep `/GS` enabled.

## Build

1. Open `BearTLS.sln` in Visual Studio 2008.
2. Select your target configuration/platform.
3. For WM2003 device/emulator (ARM): use `Pocket PC 2003 (ARMV4)`.
4. Build the `BearTLS` project.

## Public API

Declared in `BearTLS\wm_https.h`:

```c
typedef struct wm_https_result {
    int ok;
    int tls_error;
    int wsa_error;
    int http_bytes;
} wm_https_result;

typedef struct wm_tls_connection wm_tls_connection;

int wm_https_get(
    const char *host,
    unsigned short port,
    const char *path,
    char *response,
    int response_size,
    wm_https_result *result
);

int wm_https_request(
    const char *host,
    unsigned short port,
    const char *method,
    const char *path,
    const char *extra_headers,
    const char *body,
    char *response,
    int response_size,
    wm_https_result *result
);

int wm_tls_exchange(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
);

int wm_tls_open(
    const char *host,
    unsigned short port,
    const char *sni_host,
    wm_tls_connection **out_conn,
    wm_https_result *result
);

int wm_tls_write(
    wm_tls_connection *conn,
    const void *data,
    unsigned int data_len,
    unsigned int *bytes_written,
    wm_https_result *result
);

int wm_tls_read(
    wm_tls_connection *conn,
    void *buffer,
    unsigned int buffer_size,
    unsigned int *bytes_read,
    wm_https_result *result
);

void wm_tls_close(wm_tls_connection *conn);
```

## Linking in another project

1. Add `BearTLS\wm_https.h` to your include path.
2. Link against `wm_https.lib`.
3. Deploy `wm_https.dll` with your executable on device/emulator.
4. Ensure `ws2.lib` is available in your build (the DLL itself already uses Winsock internally).

## Runtime smoke test for DLL loading

Use project `dll_smoketest` when troubleshooting deploy/runtime failures.

It verifies:
- `LoadLibrary("wm_https.dll")`
- `GetProcAddress("wm_https_get")`
- `GetProcAddress("wm_https_request")`
- `GetProcAddress("wm_tls_exchange")`
- `GetProcAddress("wm_tls_open")`
- `GetProcAddress("wm_tls_write")`
- `GetProcAddress("wm_tls_read")`
- `GetProcAddress("wm_tls_close")`

Then it runs one HTTPS request and shows detailed status in a message box.

## Example: HTTPS GET

```c
#include <stdio.h>
#include "wm_https.h"

int main(void)
{
    char response[4096];
    wm_https_result res;

    if (wm_https_get("www.wikipedia.org", 443, "/", response, sizeof(response), &res)) {
        printf("Success, bytes=%d\n", res.http_bytes);
        printf("%s\n", response);
        return 0;
    }

    printf("FAIL tls=%d wsa=%d bytes=%d\n", res.tls_error, res.wsa_error, res.http_bytes);
    return 1;
}
```

## Certificate trust notes

The DLL uses a compiled-in trust-anchor set (`wm_cert_store.c`) and validates TLS chains against those anchors.

If a target server chain is not rooted in one of those anchors, the handshake fails (`tls_error` set in `wm_https_result`).

## Exported symbols

Defined in `BearTLS\wm_https.def`:
- `wm_https_get`
- `wm_https_request`
- `wm_tls_exchange`
- `wm_tls_open`
- `wm_tls_write`
- `wm_tls_read`
- `wm_tls_close`

## Test app

- `BearTLS\main_example.c`: sample app used by `tls_example`
- `BearTLS\dll_smoketest_main.c`: dynamic-load smoke test used by `dll_smoketest`
