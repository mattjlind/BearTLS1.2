#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include "bearssl.h"
#include "wm_https.h"
#include "wm_cert_store.h"

#pragma comment(lib, "ws2.lib")

#define WM_HTTPS_IOBUF_SIZE BR_SSL_BUFSIZE_BIDI
#define WM_HTTPS_RECV_CHUNK 1024
#define WM_HTTPS_TIMEOUT_MS 5000
#define WM_HTTPS_REQUEST_SIZE 4096

struct wm_tls_connection {
    SOCKET sock;
    br_ssl_client_context ssl_client;
    br_x509_minimal_context x509_minimal;
    unsigned char iobuf[WM_HTTPS_IOBUF_SIZE];
    int closed;
};

static void
wm_https_zero_result(wm_https_result *result)
{
    if (result != 0) {
        result->ok = 0;
        result->tls_error = 0;
        result->wsa_error = 0;
        result->http_bytes = 0;
    }
}

static int
wm_https_connect_ipv4(const char *host, unsigned short port, SOCKET *out_sock, int *out_wsa_error)
{
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in addr;
    struct hostent *host_entry;
    int timeout_ms;
    unsigned long ip_addr;

    *out_sock = INVALID_SOCKET;
    if (out_wsa_error != 0) {
        *out_wsa_error = 0;
    }

    if (WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        if (out_wsa_error != 0) {
            *out_wsa_error = WSAGetLastError();
        }
        return 0;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        if (out_wsa_error != 0) {
            *out_wsa_error = WSAGetLastError();
        }
        WSACleanup();
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    ip_addr = inet_addr(host);
    if (ip_addr != INADDR_NONE) {
        addr.sin_addr.s_addr = ip_addr;
    } else {
        host_entry = gethostbyname(host);
        if (host_entry == 0 || host_entry->h_addr_list == 0 || host_entry->h_addr_list[0] == 0) {
            if (out_wsa_error != 0) {
                *out_wsa_error = WSAGetLastError();
                if (*out_wsa_error == 0) {
                    *out_wsa_error = WSAHOST_NOT_FOUND;
                }
            }
            closesocket(sock);
            WSACleanup();
            return 0;
        }

        memcpy(&addr.sin_addr, host_entry->h_addr_list[0], sizeof(addr.sin_addr));
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        if (out_wsa_error != 0) {
            *out_wsa_error = WSAGetLastError();
        }
        closesocket(sock);
        WSACleanup();
        return 0;
    }

    timeout_ms = WM_HTTPS_TIMEOUT_MS;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
        (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR)
    {
        /* WinCE stacks may reject SO_RCVTIMEO with WSAENOPROTOOPT.
         * This timeout is optional for the synchronous test client.
         */
        if (out_wsa_error != 0) {
            *out_wsa_error = 0;
        }
    }

    *out_sock = sock;
    return 1;
}

static void
wm_https_disconnect(SOCKET sock)
{
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    WSACleanup();
}

static int
wm_tls_send_pending_records(wm_tls_connection *conn, wm_https_result *result)
{
    unsigned char *buf;
    size_t len;

    buf = br_ssl_engine_sendrec_buf(&conn->ssl_client.eng, &len);
    while (len > 0) {
        int wr;

        wr = send(conn->sock, (const char *)buf, (int)len, 0);
        if (wr <= 0) {
            if (result != 0) {
                result->wsa_error = WSAGetLastError();
            }
            return 0;
        }

        br_ssl_engine_sendrec_ack(&conn->ssl_client.eng, (size_t)wr);
        buf = br_ssl_engine_sendrec_buf(&conn->ssl_client.eng, &len);
    }

    return 1;
}

static int
wm_tls_recv_pending_records(wm_tls_connection *conn, wm_https_result *result)
{
    unsigned char *buf;
    size_t len;
    int rd;
    int want;

    buf = br_ssl_engine_recvrec_buf(&conn->ssl_client.eng, &len);
    if (len == 0) {
        return 1;
    }

    want = (len < WM_HTTPS_RECV_CHUNK) ? (int)len : WM_HTTPS_RECV_CHUNK;
    rd = recv(conn->sock, (char *)buf, want, 0);
    if (rd == SOCKET_ERROR) {
        if (result != 0) {
            result->wsa_error = WSAGetLastError();
        }
        return 0;
    }
    if (rd == 0) {
        conn->closed = 1;
        return 1;
    }

    br_ssl_engine_recvrec_ack(&conn->ssl_client.eng, (size_t)rd);
    return 1;
}

static int
wm_tls_drive_records(wm_tls_connection *conn, wm_https_result *result)
{
    unsigned state;

    state = br_ssl_engine_current_state(&conn->ssl_client.eng);

    if (state & BR_SSL_CLOSED) {
        conn->closed = 1;
        if (result != 0) {
            result->tls_error = br_ssl_engine_last_error(&conn->ssl_client.eng);
        }
        return 0;
    }

    if (state & BR_SSL_SENDREC) {
        return wm_tls_send_pending_records(conn, result);
    }

    if (state & BR_SSL_RECVREC) {
        return wm_tls_recv_pending_records(conn, result);
    }

    return 1;
}

int
wm_tls_open(
    const char *host,
    unsigned short port,
    const char *sni_host,
    wm_tls_connection **out_conn,
    wm_https_result *result
)
{
    wm_tls_connection *conn;
    const br_x509_trust_anchor *trust_anchors;
    size_t trust_anchor_count;
    const char *sni_name;
    unsigned state;

    wm_https_zero_result(result);

    if (host == 0 || out_conn == 0) {
        return 0;
    }

    *out_conn = 0;
    conn = (wm_tls_connection *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        sizeof(*conn));
    if (conn == 0) {
        return 0;
    }

    conn->sock = INVALID_SOCKET;
    sni_name = (sni_host != 0 && sni_host[0] != '\0') ? sni_host : host;

    if (!wm_https_connect_ipv4(host, port, &conn->sock,
        (result != 0) ? &result->wsa_error : 0))
    {
        HeapFree(GetProcessHeap(), 0, conn);
        return 0;
    }

    if (!wm_cert_store_init()) {
        wm_https_disconnect(conn->sock);
        HeapFree(GetProcessHeap(), 0, conn);
        return 0;
    }

    trust_anchors = wm_cert_store_anchors();
    trust_anchor_count = wm_cert_store_anchor_count();

    br_ssl_client_init_full(&conn->ssl_client, &conn->x509_minimal,
        trust_anchors, trust_anchor_count);
    br_ssl_engine_set_versions(&conn->ssl_client.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_buffer(&conn->ssl_client.eng, conn->iobuf,
        sizeof(conn->iobuf), 1);

    if (!br_ssl_client_reset(&conn->ssl_client, sni_name, 0)) {
        if (result != 0) {
            result->tls_error = br_ssl_engine_last_error(&conn->ssl_client.eng);
        }
        wm_https_disconnect(conn->sock);
        HeapFree(GetProcessHeap(), 0, conn);
        return 0;
    }

    while (1) {
        state = br_ssl_engine_current_state(&conn->ssl_client.eng);
        if ((state & BR_SSL_SENDAPP) || (state & BR_SSL_RECVAPP)) {
            break;
        }
        if (!wm_tls_drive_records(conn, result) || conn->closed) {
            wm_https_disconnect(conn->sock);
            HeapFree(GetProcessHeap(), 0, conn);
            return 0;
        }
    }

    if (result != 0) {
        result->ok = 1;
    }
    *out_conn = conn;
    return 1;
}

int
wm_tls_write(
    wm_tls_connection *conn,
    const void *data,
    unsigned int data_len,
    unsigned int *bytes_written,
    wm_https_result *result
)
{
    const unsigned char *src;
    unsigned int sent;

    wm_https_zero_result(result);
    if (bytes_written != 0) {
        *bytes_written = 0;
    }

    if (conn == 0 || (data == 0 && data_len > 0)) {
        return 0;
    }

    src = (const unsigned char *)data;
    sent = 0;

    while (sent < data_len) {
        unsigned state;

        state = br_ssl_engine_current_state(&conn->ssl_client.eng);

        if (state & BR_SSL_CLOSED) {
            conn->closed = 1;
            if (result != 0) {
                result->tls_error = br_ssl_engine_last_error(&conn->ssl_client.eng);
            }
            return 0;
        }

        if (state & BR_SSL_SENDAPP) {
            unsigned char *buf;
            size_t len;
            size_t take;

            buf = br_ssl_engine_sendapp_buf(&conn->ssl_client.eng, &len);
            take = data_len - sent;
            if (take > len) {
                take = len;
            }

            if (take > 0) {
                memcpy(buf, src + sent, take);
                br_ssl_engine_sendapp_ack(&conn->ssl_client.eng, take);
                br_ssl_engine_flush(&conn->ssl_client.eng, 0);
                sent += (unsigned int)take;
                if (bytes_written != 0) {
                    *bytes_written = sent;
                }
                continue;
            }
        }

        if (!wm_tls_drive_records(conn, result) || conn->closed) {
            return 0;
        }
    }

    if (result != 0) {
        result->ok = 1;
    }
    return 1;
}

int
wm_tls_read(
    wm_tls_connection *conn,
    void *buffer,
    unsigned int buffer_size,
    unsigned int *bytes_read,
    wm_https_result *result
)
{
    unsigned char *dst;

    wm_https_zero_result(result);
    if (bytes_read != 0) {
        *bytes_read = 0;
    }

    if (conn == 0 || buffer == 0 || buffer_size == 0) {
        return 0;
    }

    dst = (unsigned char *)buffer;

    while (1) {
        unsigned state;

        state = br_ssl_engine_current_state(&conn->ssl_client.eng);

        if (state & BR_SSL_CLOSED) {
            conn->closed = 1;
            if (result != 0) {
                result->tls_error = br_ssl_engine_last_error(&conn->ssl_client.eng);
                result->ok = (result->tls_error == 0);
            }
            return (result == 0 || result->tls_error == 0);
        }

        if (state & BR_SSL_RECVAPP) {
            unsigned char *buf;
            size_t len;
            size_t take;

            buf = br_ssl_engine_recvapp_buf(&conn->ssl_client.eng, &len);
            take = len;
            if (take > buffer_size) {
                take = buffer_size;
            }

            if (take > 0) {
                memcpy(dst, buf, take);
                br_ssl_engine_recvapp_ack(&conn->ssl_client.eng, take);
                if (bytes_read != 0) {
                    *bytes_read = (unsigned int)take;
                }
                if (result != 0) {
                    result->ok = 1;
                    result->http_bytes = (int)take;
                }
                return 1;
            }
        }

        if (!wm_tls_drive_records(conn, result)) {
            return 0;
        }
        if (conn->closed) {
            if (result != 0) {
                result->ok = 1;
            }
            return 1;
        }
    }
}

void
wm_tls_close(wm_tls_connection *conn)
{
    if (conn == 0) {
        return;
    }

    if (!conn->closed) {
        br_ssl_engine_close(&conn->ssl_client.eng);
        while (br_ssl_engine_current_state(&conn->ssl_client.eng) & BR_SSL_SENDREC) {
            if (!wm_tls_send_pending_records(conn, 0)) {
                break;
            }
        }
    }

    wm_https_disconnect(conn->sock);
    HeapFree(GetProcessHeap(), 0, conn);
}

static void
wm_https_append_request_text(char *request, int request_size, size_t *used, const char *text)
{
    size_t chunk_len;
    size_t request_cap;

    if (request == 0 || request_size <= 0 || used == 0 || text == 0) {
        return;
    }

    request_cap = (size_t)request_size;
    if (*used >= request_cap - 1) {
        return;
    }

    chunk_len = strlen(text);
    if (chunk_len > request_cap - *used - 1) {
        chunk_len = request_cap - *used - 1;
    }
    memcpy(request + *used, text, chunk_len);
    *used += chunk_len;
    request[*used] = '\0';
}

static void
wm_https_append_request_data(char *request, int request_size, size_t *used, const char *data, size_t data_len)
{
    size_t request_cap;

    if (request == 0 || request_size <= 0 || used == 0 || data == 0) {
        return;
    }

    request_cap = (size_t)request_size;
    if (*used >= request_cap - 1) {
        return;
    }

    if (data_len > request_cap - *used - 1) {
        data_len = request_cap - *used - 1;
    }
    memcpy(request + *used, data, data_len);
    *used += data_len;
    request[*used] = '\0';
}

static void
wm_https_build_request(
    const char *host,
    unsigned short port,
    const char *method,
    const char *path,
    const char *extra_headers,
    const char *body,
    char *request,
    int request_size
)
{
    size_t used;
    size_t request_cap;
    size_t body_len;
    char port_text[16];
    int include_port;

    if (request_size <= 0) {
        return;
    }

    request[0] = '\0';
    request_cap = (size_t)request_size;
    used = 0;

    body_len = body != 0 ? strlen(body) : 0;
    include_port = !((port == 443) || (port == 80));

    wm_https_append_request_text(request, request_size, &used,
        (method != 0 && method[0] != '\0') ? method : "GET");
    wm_https_append_request_text(request, request_size, &used, " ");
    wm_https_append_request_text(request, request_size, &used,
        (path != 0 && path[0] != '\0') ? path : "/");
    wm_https_append_request_text(request, request_size, &used, " HTTP/1.1\r\nHost: ");
    wm_https_append_request_text(request, request_size, &used, host);
    if (include_port) {
        _snprintf(port_text, sizeof(port_text), ":%u", (unsigned)port);
        port_text[sizeof(port_text) - 1] = '\0';
        wm_https_append_request_text(request, request_size, &used, port_text);
    }
    wm_https_append_request_text(request, request_size, &used,
        "\r\nUser-Agent: Mozilla/5.0 (Windows CE; ARM; HP iPAQ 212)"
        "\r\nAccept: */*"
        "\r\nConnection: close");
    if (extra_headers != 0 && extra_headers[0] != '\0') {
        wm_https_append_request_text(request, request_size, &used, "\r\n");
        wm_https_append_request_text(request, request_size, &used, extra_headers);
    }
    if (body_len > 0) {
        char length_text[32];

        _snprintf(length_text, sizeof(length_text), "\r\nContent-Length: %u",
            (unsigned)body_len);
        length_text[sizeof(length_text) - 1] = '\0';
        wm_https_append_request_text(request, request_size, &used, length_text);
    }
    wm_https_append_request_text(request, request_size, &used, "\r\n\r\n");
    if (body_len > 0) {
        wm_https_append_request_data(request, request_size, &used, body, body_len);
    }
}

static int
wm_tls_exchange_internal(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    wm_tls_connection *conn;
    int response_len;
    int ok;
    unsigned int wrote;

    wm_https_zero_result(result);

    if (host == 0 || request_text == 0 || response == 0 || response_size <= 1) {
        return 0;
    }

    response[0] = '\0';

    if (!wm_tls_open(host, port, sni_host, &conn, result)) {
        return 0;
    }

    if (!wm_tls_write(conn, request_text, (unsigned int)strlen(request_text),
        &wrote, result))
    {
        wm_tls_close(conn);
        return 0;
    }

    response_len = 0;
    ok = 0;

    while (1) {
        unsigned int got;

        if (!wm_tls_read(conn, response + response_len,
            (unsigned int)(response_size - response_len - 1), &got, result))
        {
            wm_tls_close(conn);
            return 0;
        }

        if (got == 0) {
            break;
        }

        response_len += (int)got;
        response[response_len] = '\0';
        ok = 1;

        if (response_len >= response_size - 1) {
            break;
        }
    }

    wm_tls_close(conn);

    if (result != 0) {
        result->ok = ok;
        result->http_bytes = response_len;
    }
    return ok;
}

int
wm_https_request(
    const char *host,
    unsigned short port,
    const char *method,
    const char *path,
    const char *extra_headers,
    const char *body,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    char request[WM_HTTPS_REQUEST_SIZE];

    if (host == 0 || path == 0 || response == 0 || response_size <= 1) {
        return 0;
    }

    wm_https_build_request(host, port, method, path, extra_headers, body,
        request, sizeof(request));
    return wm_tls_exchange_internal(host, port, host, request,
        response, response_size, result);
}

int
wm_https_get(
    const char *host,
    unsigned short port,
    const char *path,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    return wm_https_request(host, port, "GET", path, 0, 0,
        response, response_size, result);
}

int
wm_tls_exchange(
    const char *host,
    unsigned short port,
    const char *sni_host,
    const char *request_text,
    char *response,
    int response_size,
    wm_https_result *result
)
{
    return wm_tls_exchange_internal(host, port, sni_host, request_text,
        response, response_size, result);
}
