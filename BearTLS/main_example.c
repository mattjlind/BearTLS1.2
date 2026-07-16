#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "wm_https.h"

typedef struct wm_test_site {
    const char *host;
    const char *path;
} wm_test_site;

static void show_ascii_message(const char *titleA, const char *textA)
{
    WCHAR wtitle[128];
    WCHAR wtext[8192];

    MultiByteToWideChar(CP_ACP, 0, titleA, -1, wtitle, 128);
    MultiByteToWideChar(CP_ACP, 0, textA, -1, wtext, 8192);

    MessageBox(NULL, wtext, wtitle, MB_OK);
}

static void append_text(char *dst, int dst_size, const char *src)
{
    size_t used;
    size_t left;
    size_t want;

    if (dst == NULL || src == NULL || dst_size <= 0) {
        return;
    }

    used = strlen(dst);
    if (used >= (size_t)(dst_size - 1)) {
        return;
    }

    left = (size_t)(dst_size - 1) - used;
    want = strlen(src);
    if (want > left) {
        want = left;
    }

    memcpy(dst + used, src, want);
    dst[used + want] = '\0';
}

static void append_status_line(char *report, int report_size, const char *host, const char *response)
{
    const char *line_end;
    int line_len;
    char line[256];

    line_end = strstr(response, "\r\n");
    if (line_end == NULL) {
        line_end = response + strlen(response);
    }

    line_len = (int)(line_end - response);
    if (line_len > 120) {
        line_len = 120;
    }
    if (line_len < 0) {
        line_len = 0;
    }

    _snprintf(line, sizeof(line), "%s: ", host);
    line[sizeof(line) - 1] = '\0';
    append_text(report, report_size, line);

    if (line_len > 0) {
        memcpy(line, response, (size_t)line_len);
        line[line_len] = '\0';
        append_text(report, report_size, line);
    } else {
        append_text(report, report_size, "(no response line)");
    }

    append_text(report, report_size, "\r\n");
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPWSTR lpCmd, int nShow)
{
    static const wm_test_site sites[] = {
        { "www.wikipedia.org", "/" },
        { "www.google.com", "/" },
        { "github.com", "/" },
        { "microsoft.com", "/" }
    };
    static char response[1024];
    static char report[2048];
    wm_https_result res;
    char line[256];
    int i;

    (void)hInst;
    (void)hPrev;
    (void)lpCmd;
    (void)nShow;

    report[0] = '\0';

    for (i = 0; i < (int)(sizeof(sites) / sizeof(sites[0])); i ++) {
        response[0] = '\0';

        if (wm_https_get(sites[i].host, 443, sites[i].path, response, sizeof(response), &res)) {
            append_status_line(report, sizeof(report), sites[i].host, response);
        } else {
            _snprintf(line, sizeof(line), "%s: FAIL tls=%d wsa=%d bytes=%d\r\n",
                sites[i].host, res.tls_error, res.wsa_error, res.http_bytes);
            line[sizeof(line) - 1] = '\0';
            append_text(report, sizeof(report), line);
        }
    }

    show_ascii_message("HTTPS Tests", report);

    return 0;
}
