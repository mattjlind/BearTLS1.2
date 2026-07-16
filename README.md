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
- `BearTLS_CAB` (DLL + CabWiz): builds the installer setup DLL and packages release CABs

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

WM5/WM6 runtime DLL configs keep `/GS` enabled. The `BearTLS_CAB` setup DLL disables `/GS` for all target platforms so the small installer DLL links cleanly on the older WM2003 toolchain.

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

int wm_bear_tls_register_runtime(void);
```

## Linking in another project

1. Add `BearTLS\wm_https.h` to your include path.
2. Link against `wm_https.lib`.
3. Prefer loading the shared runtime from the registry value `HKLM\Software\BearTLS\DllPath`.
4. If the registry is missing, try common shared locations such as `\Program Files\BearTLS\wm_https.dll`, `\Storage Card\Program Files\BearTLS\wm_https.dll`, `\CF Card\Program Files\BearTLS\wm_https.dll`, and `\SD Card\Program Files\BearTLS\wm_https.dll`.
5. Keep an app-local DLL only as a final fallback.
6. Ensure `ws2.lib` is available in your build (the DLL itself already uses Winsock internally).

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

## Shared runtime installation

Recommended shared install layout:

```text
\Program Files\BearTLS\
  wm_https.dll
  certs\
    roots.pem
```

Storage-card installs are supported as long as the installer records the actual path in the registry:

```text
HKLM\Software\BearTLS
  InstallDir = "\Storage Card\Program Files\BearTLS"
  DllPath    = "\Storage Card\Program Files\BearTLS\wm_https.dll"
  RootsPath  = "\Storage Card\Program Files\BearTLS\certs\roots.pem"
  Version    = "1.0.0"
```

A setup app can load `wm_https.dll` from its final location and call `wm_bear_tls_register_runtime()` to write those keys automatically.

Apps should discover and load BearTLS; BearTLS discovers its own data files.

## Certificate trust notes

At runtime, `wm_https.dll` first tries to load a PEM root bundle beside itself:

```text
<directory containing wm_https.dll>\certs\roots.pem
```

Every `BEGIN CERTIFICATE` block that decodes to a CA certificate is added to the BearSSL trust-anchor set. The compiled-in trust-anchor set (`wm_cert_store.c` plus `wm_extra_roots.inc`) is always appended as a fallback, so HTTPS still works if `roots.pem` is missing or partially invalid.

The source tree includes `BearTLS\certs\roots.pem`, generated from the local Windows trusted root store as an initial deployable bundle. For broader public Web coverage, replace that file with a Mozilla-derived root bundle during packaging.

If a target server chain is not rooted in one of the file-loaded or embedded anchors, the handshake fails (`tls_error` set in `wm_https_result`).

## Exported symbols

Defined in `BearTLS\wm_https.def`:
- `wm_https_get`
- `wm_https_request`
- `wm_tls_exchange`
- `wm_tls_open`
- `wm_tls_write`
- `wm_tls_read`
- `wm_tls_close`
- `wm_bear_tls_register_runtime`

## CAB packaging

`BearTLS_CAB` builds `BearTLSSetup.dll` and then runs CabWiz through `BearTLS_CAB\make_cab.cmd`.

To build all release CABs from a VS2008 command environment, run:

```bat
BearTLS_CAB\build_release_cabs.cmd
```

That script builds:

```text
Pocket PC 2003 (ARMV4)
Windows Mobile 5.0 Pocket PC SDK (ARMV4I)
Windows Mobile 6 Professional SDK (ARMV4I)
```

The generated CAB installs:

```text
<chosen install directory>\wm_https.dll
<chosen install directory>\certs\roots.pem
```

The CAB uses `BearTLSSetup.dll` as `CESetupDLL`. During install it receives the actual `pszInstallDir` selected by the user and writes:

```text
HKLM\Software\BearTLS\InstallDir
HKLM\Software\BearTLS\DllPath
HKLM\Software\BearTLS\RootsPath
HKLM\Software\BearTLS\Version
```

This keeps registry paths correct for Device, Storage Card, CF Card, or SD Card installs.

CAB output is written under:

```text
BearTLS_CAB\cab_output\<platform>\<configuration>\
```

Current release CAB outputs are:

```text
BearTLS_CAB\cab_output\Pocket PC 2003 (ARMV4)\Release\BearTLS_CAB.ARMV4.CAB
BearTLS_CAB\cab_output\Windows Mobile 5.0 Pocket PC SDK (ARMV4I)\Release\BearTLS_CAB.ARMV4I.CAB
BearTLS_CAB\cab_output\Windows Mobile 6 Professional SDK (ARMV4I)\Release\BearTLS_CAB.ARMV4I.CAB
```

Validation status:

```text
WM2003 ARMV4: tested on device, installs and works
WM5 ARMV4I: built successfully, not yet tested on physical WM5 device
WM6 ARMV4I: tested on device, installs and works
```

## Test app

- `BearTLS\main_example.c`: sample app used by `tls_example`
- `BearTLS\dll_smoketest_main.c`: dynamic-load smoke test used by `dll_smoketest`

