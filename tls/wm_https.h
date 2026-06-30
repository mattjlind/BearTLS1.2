#ifndef WM_HTTPS_H
#define WM_HTTPS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wm_https_result {
    int ok;
    int tls_error;
    int wsa_error;
    int http_bytes;
} wm_https_result;

typedef struct wm_tls_connection wm_tls_connection;

/* HTTPS GET using a compiled-in BearSSL trust-anchor set.
 * Notes:
 *  - host may be a DNS hostname or a numeric IPv4 string
 *  - response is always NUL-terminated if response_size > 0
 *  - returns 1 on success, 0 on failure
 */
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

/* Generic TLS text exchange for protocol scripting (IMAP/POP3/etc.).
 * request_text is sent once after handshake; response is collected until close.
 */
int wm_tls_exchange(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
);

/* Streaming TLS API for binary protocols and large HTTP transfers.
 * Returns 1 on success, 0 on failure. wm_tls_read returns 1 with
 * *bytes_read == 0 when the peer closes the connection.
 */
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

#ifdef __cplusplus
}
#endif

#endif
