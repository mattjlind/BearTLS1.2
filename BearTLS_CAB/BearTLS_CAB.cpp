// BearTLS_CAB.cpp : CAB setup DLL for BearTLS.
// Writes install-location-aware BearTLS registry values.

#include <windows.h>

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

typedef enum tagINSTALL_INIT_CODE {
    codeINSTALL_INIT_CONTINUE = 0,
    codeINSTALL_INIT_CANCEL = 1
} codeINSTALL_INIT;

typedef enum tagINSTALL_EXIT_CODE {
    codeINSTALL_EXIT_DONE = 0,
    codeINSTALL_EXIT_UNINSTALL = 1
} codeINSTALL_EXIT;

typedef enum tagUNINSTALL_INIT_CODE {
    codeUNINSTALL_INIT_CONTINUE = 0,
    codeUNINSTALL_INIT_CANCEL = 1
} codeUNINSTALL_INIT;

typedef enum tagUNINSTALL_EXIT_CODE {
    codeUNINSTALL_EXIT_DONE = 0
} codeUNINSTALL_EXIT;

static int bt_copy_string(WCHAR *dest, DWORD dest_count, const WCHAR *src)
{
    DWORD i;

    if (dest == 0 || dest_count == 0 || src == 0) {
        return 0;
    }

    for (i = 0; i + 1 < dest_count && src[i] != 0; ++i) {
        dest[i] = src[i];
    }
    dest[i] = 0;
    return src[i] == 0;
}

static int bt_append_string(WCHAR *dest, DWORD dest_count, const WCHAR *suffix)
{
    DWORD len;
    DWORD i;

    if (dest == 0 || dest_count == 0 || suffix == 0) {
        return 0;
    }

    len = 0;
    while (len < dest_count && dest[len] != 0) {
        len++;
    }
    if (len >= dest_count) {
        return 0;
    }

    for (i = 0; len + i + 1 < dest_count && suffix[i] != 0; ++i) {
        dest[len + i] = suffix[i];
    }
    dest[len + i] = 0;
    return suffix[i] == 0;
}

static void bt_set_reg_string(HKEY key, const WCHAR *name, const WCHAR *value)
{
    if (key == 0 || name == 0 || value == 0) {
        return;
    }

    RegSetValueEx(key, name, 0, REG_SZ, (const BYTE *)value,
        (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
}

static int bt_write_registry(const WCHAR *install_dir)
{
    HKEY key;
    DWORD disp;
    WCHAR dll_path[MAX_PATH];
    WCHAR roots_path[MAX_PATH];
    LONG rc;

    if (install_dir == 0 || install_dir[0] == 0) {
        return 0;
    }

    if (!bt_copy_string(dll_path, MAX_PATH, install_dir)
        || !bt_append_string(dll_path, MAX_PATH, L"\\wm_https.dll"))
    {
        return 0;
    }

    if (!bt_copy_string(roots_path, MAX_PATH, install_dir)
        || !bt_append_string(roots_path, MAX_PATH, L"\\certs\\roots.pem"))
    {
        return 0;
    }

    rc = RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"Software\\BearTLS", 0, 0,
        0, 0, 0, &key, &disp);
    if (rc != ERROR_SUCCESS) {
        return 0;
    }

    bt_set_reg_string(key, L"InstallDir", install_dir);
    bt_set_reg_string(key, L"DllPath", dll_path);
    bt_set_reg_string(key, L"RootsPath", roots_path);
    bt_set_reg_string(key, L"Version", L"1.0.0");
    RegCloseKey(key);
    return 1;
}

extern "C" __declspec(dllexport) codeINSTALL_INIT Install_Init(
    HWND hwndParent,
    BOOL fFirstCall,
    BOOL fPreviouslyInstalled,
    LPCTSTR pszInstallDir)
{
    (void)hwndParent;
    (void)fFirstCall;
    (void)fPreviouslyInstalled;
    (void)pszInstallDir;
    return codeINSTALL_INIT_CONTINUE;
}

extern "C" __declspec(dllexport) codeINSTALL_EXIT Install_Exit(
    HWND hwndParent,
    LPCTSTR pszInstallDir,
    WORD cFailedDirs,
    WORD cFailedFiles,
    WORD cFailedRegKeys,
    WORD cFailedRegVals,
    WORD cFailedShortcuts)
{
    (void)hwndParent;
    (void)cFailedDirs;
    (void)cFailedFiles;
    (void)cFailedRegKeys;
    (void)cFailedRegVals;
    (void)cFailedShortcuts;

    if (!bt_write_registry(pszInstallDir)) {
        MessageBox(hwndParent, L"BearTLS installed, but registry registration failed.",
            L"BearTLS", MB_OK | MB_ICONEXCLAMATION);
    }
    return codeINSTALL_EXIT_DONE;
}

extern "C" __declspec(dllexport) codeUNINSTALL_INIT Uninstall_Init(
    HWND hwndParent,
    LPCTSTR pszInstallDir)
{
    (void)hwndParent;
    (void)pszInstallDir;
    return codeUNINSTALL_INIT_CONTINUE;
}

extern "C" __declspec(dllexport) codeUNINSTALL_EXIT Uninstall_Exit(HWND hwndParent)
{
    (void)hwndParent;
    RegDeleteKey(HKEY_LOCAL_MACHINE, L"Software\\BearTLS");
    return codeUNINSTALL_EXIT_DONE;
}

