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
#define WM_MEGA_RSA_MAX_COMPONENT 512
#define WM_MEGA_RSA_MAX_MODULUS 1024

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
wm_mega_mpi_read(
    const unsigned char *data,
    unsigned int data_len,
    unsigned int *pos,
    const unsigned char **value,
    unsigned int *value_len
)
{
    unsigned int bits;
    unsigned int bytes;

    if (data == 0 || pos == 0 || value == 0 || value_len == 0) {
        return 0;
    }
    if (*pos + 2 > data_len) {
        return 0;
    }

    bits = ((unsigned int)data[*pos] << 8) | (unsigned int)data[*pos + 1];
    bytes = (bits + 7) >> 3;
    *pos += 2;
    if (*pos + bytes > data_len) {
        return 0;
    }

    *value = data + *pos;
    *value_len = bytes;
    *pos += bytes;
    return 1;
}

static unsigned int
wm_mega_actual_len(const unsigned char *data, unsigned int data_len)
{
    while (data_len > 0 && *data == 0) {
        data++;
        data_len--;
    }
    return data_len;
}

int
wm_mega_rsa_decrypt_session(
    const unsigned char *mega_privk,
    unsigned int mega_privk_len,
    const unsigned char *mega_csid,
    unsigned int mega_csid_len,
    unsigned char *sid,
    unsigned int sid_len
)
{
    const unsigned char *mp;
    const unsigned char *mq;
    const unsigned char *md;
    const unsigned char *mu;
    const unsigned char *cipher_mpi;
    unsigned int plen;
    unsigned int qlen;
    unsigned int dlen;
    unsigned int ulen;
    unsigned int cipher_len;
    unsigned int pos;
    unsigned int xlen;
    unsigned int actual_len;
    unsigned int base;
    unsigned int i;
    unsigned char x[WM_MEGA_RSA_MAX_MODULUS];
    br_rsa_private_key sk;

    if (mega_privk == 0 || mega_csid == 0 || sid == 0 || sid_len == 0) {
        return 0;
    }

    pos = 0;
    if (!wm_mega_mpi_read(mega_privk, mega_privk_len, &pos, &mp, &plen)
        || !wm_mega_mpi_read(mega_privk, mega_privk_len, &pos, &mq, &qlen)
        || !wm_mega_mpi_read(mega_privk, mega_privk_len, &pos, &md, &dlen)
        || !wm_mega_mpi_read(mega_privk, mega_privk_len, &pos, &mu, &ulen))
    {
        return 0;
    }

    pos = 0;
    if (!wm_mega_mpi_read(mega_csid, mega_csid_len, &pos,
        &cipher_mpi, &cipher_len))
    {
        return 0;
    }

    if (plen == 0 || qlen == 0 || dlen == 0 || ulen == 0) {
        return 0;
    }
    if (plen > WM_MEGA_RSA_MAX_COMPONENT
        || qlen > WM_MEGA_RSA_MAX_COMPONENT
        || dlen > WM_MEGA_RSA_MAX_MODULUS
        || ulen > WM_MEGA_RSA_MAX_COMPONENT)
    {
        return 0;
    }

    xlen = plen + qlen;
    if (xlen == 0 || xlen > sizeof(x) || cipher_len > xlen) {
        return 0;
    }

    memset(x, 0, sizeof(x));
    memcpy(x + xlen - cipher_len, cipher_mpi, cipher_len);

    memset(&sk, 0, sizeof(sk));
    sk.n_bitlen = xlen * 8;
    sk.p = (unsigned char *)mq;
    sk.plen = qlen;
    sk.q = (unsigned char *)mp;
    sk.qlen = plen;
    sk.dp = (unsigned char *)md;
    sk.dplen = dlen;
    sk.dq = (unsigned char *)md;
    sk.dqlen = dlen;
    sk.iq = (unsigned char *)mu;
    sk.iqlen = ulen;

    if (!br_rsa_private_get_default()(x, &sk)) {
        memset(x, 0, sizeof(x));
        return 0;
    }

    actual_len = wm_mega_actual_len(x, xlen);
    if (actual_len < xlen) {
        memmove(x, x + xlen - actual_len, actual_len);
    }

    base = plen + qlen - 2;
    if (actual_len > base) {
        base = actual_len;
    }
    if (base < sid_len) {
        memset(x, 0, sizeof(x));
        return 0;
    }
    base -= sid_len;

    for (i = sid_len; i > 0; --i) {
        unsigned int byte_index;

        byte_index = base + (sid_len - i);
        if (byte_index >= actual_len) {
            sid[i - 1] = 0;
        } else {
            sid[i - 1] = x[actual_len - 1 - byte_index];
        }
    }

    memset(x, 0, sizeof(x));
    return 1;
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

#define WM_HASHCASH_TOKEN_BYTES 48
#define WM_HASHCASH_PREFIX_BYTES 4
#define WM_HASHCASH_REPEAT 262144UL
#define WM_HASHCASH_CHUNK_REPEATS 256UL
#define WM_HASHCASH_FULL_CHUNKS 1023UL
#define WM_HASHCASH_TAIL_REPEATS 254UL
#define WM_HASHCASH_TIMEOUT_MS 300000UL

static unsigned long
wm_hashcash_load_be32(const unsigned char *p)
{
    return ((unsigned long)p[0] << 24)
        | ((unsigned long)p[1] << 16)
        | ((unsigned long)p[2] << 8)
        | (unsigned long)p[3];
}

static void
wm_hashcash_store_be32(unsigned char *p, unsigned long v)
{
    p[0] = (unsigned char)((v >> 24) & 0xff);
    p[1] = (unsigned char)((v >> 16) & 0xff);
    p[2] = (unsigned char)((v >> 8) & 0xff);
    p[3] = (unsigned char)(v & 0xff);
}

static int
wm_hashcash_from64(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '-' || ch == '+') {
        return 62;
    }
    if (ch == '_' || ch == '/') {
        return 63;
    }
    return -1;
}

static int
wm_hashcash_b64_decode(const char *text, unsigned char *out, unsigned int out_size)
{
    unsigned int used;
    unsigned int bitbuf;
    int bitcount;

    used = 0;
    bitbuf = 0;
    bitcount = 0;
    while (text != 0 && *text != '\0') {
        int v;

        if (*text == '=') {
            break;
        }
        v = wm_hashcash_from64(*text++);
        if (v < 0) {
            return -1;
        }
        bitbuf = (bitbuf << 6) | (unsigned int)v;
        bitcount += 6;
        if (bitcount >= 8) {
            bitcount -= 8;
            if (used >= out_size) {
                return -1;
            }
            out[used++] = (unsigned char)((bitbuf >> bitcount) & 0xff);
        }
    }

    return (int)used;
}

static int
wm_hashcash_b64_encode(
    const unsigned char *data,
    int data_len,
    char *out,
    unsigned int out_size
)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    unsigned int used;
    int i;

    used = 0;
    i = 0;
    while (i < data_len) {
        int remain;
        unsigned int value;
        int chars;
        int c;

        remain = data_len - i;
        value = (unsigned int)data[i] << 16;
        if (remain > 1) {
            value |= (unsigned int)data[i + 1] << 8;
        }
        if (remain > 2) {
            value |= (unsigned int)data[i + 2];
        }

        chars = remain >= 3 ? 4 : remain + 1;
        if (used + (unsigned int)chars >= out_size) {
            return 0;
        }
        for (c = 0; c < chars; ++c) {
            out[used++] = alphabet[(value >> (18 - c * 6)) & 0x3f];
        }
        i += 3;
    }

    if (used >= out_size) {
        return 0;
    }
    out[used] = '\0';
    return 1;
}

static unsigned long
wm_hashcash_threshold(unsigned int e)
{
    unsigned int shift;

    shift = ((e >> 6) * 7) + 3;
    return (unsigned long)((((e & 63) << 1) + 1) << shift);
}

static void
wm_hashcash_progress(
    wm_hashcash_progress_fn progress,
    void *user_data,
    const char *message
)
{
    if (progress != 0 && message != 0) {
        progress(message, user_data);
    }
}

int
wm_hashcash_solve(
    const char *token,
    unsigned int easiness,
    char *prefix_b64,
    unsigned int prefix_b64_size,
    wm_hashcash_progress_fn progress,
    void *progress_user_data
)
{
    unsigned char token_bin[WM_HASHCASH_TOKEN_BYTES];
    unsigned char prefix[WM_HASHCASH_PREFIX_BYTES];
    unsigned char first[64];
    unsigned char digest[32];
    unsigned char chunk[WM_HASHCASH_TOKEN_BYTES * WM_HASHCASH_CHUNK_REPEATS];
    unsigned char tail[WM_HASHCASH_TOKEN_BYTES * WM_HASHCASH_TAIL_REPEATS];
    unsigned long threshold;
    unsigned long nonce;
    unsigned long i;
    int decoded;
    DWORD start_tick;
    DWORD last_tick;

    if (token == 0 || prefix_b64 == 0 || prefix_b64_size == 0 || easiness > 255) {
        return 0;
    }

    decoded = wm_hashcash_b64_decode(token, token_bin, sizeof(token_bin));
    if (decoded != WM_HASHCASH_TOKEN_BYTES) {
        return 0;
    }

    threshold = wm_hashcash_threshold(easiness);

    memset(first, 0, sizeof(first));
    memcpy(first + 4, token_bin, WM_HASHCASH_TOKEN_BYTES);
    memcpy(first + 4 + WM_HASHCASH_TOKEN_BYTES, token_bin, 12);

    for (i = 0; i < WM_HASHCASH_CHUNK_REPEATS; ++i) {
        memcpy(chunk + i * WM_HASHCASH_TOKEN_BYTES,
            token_bin, WM_HASHCASH_TOKEN_BYTES);
    }
    for (i = 0; i < WM_HASHCASH_TAIL_REPEATS; ++i) {
        memcpy(tail + i * WM_HASHCASH_TOKEN_BYTES,
            token_bin, WM_HASHCASH_TOKEN_BYTES);
    }

    start_tick = GetTickCount();
    last_tick = start_tick;
    for (nonce = 0; ; ++nonce) {
        br_sha256_context ctx;
        DWORD now_tick;

        wm_hashcash_store_be32(first, nonce);
        br_sha256_init(&ctx);
        br_sha256_update(&ctx, first, sizeof(first));
        br_sha256_update(&ctx, token_bin + 12, 36);
        for (i = 0; i < WM_HASHCASH_FULL_CHUNKS; ++i) {
            br_sha256_update(&ctx, chunk, sizeof(chunk));

            if ((i & 31UL) == 31UL) {
                now_tick = GetTickCount();
                if (now_tick - last_tick >= 5000UL) {
                    char msg[128];

                    _snprintf(msg, sizeof(msg),
                        "BearSSL hashcash nonce %lu: %lu/1023 chunks in %lu seconds...",
                        nonce, i + 1UL, (now_tick - start_tick) / 1000UL);
                    msg[sizeof(msg) - 1] = '\0';
                    wm_hashcash_progress(progress, progress_user_data, msg);
                    last_tick = now_tick;
                }

                if (now_tick - start_tick >= WM_HASHCASH_TIMEOUT_MS) {
                    wm_hashcash_progress(progress, progress_user_data,
                        "BearSSL hashcash timed out.");
                    return 0;
                }
            }
        }
        br_sha256_update(&ctx, tail, sizeof(tail));
        br_sha256_out(&ctx, digest);

        if (wm_hashcash_load_be32(digest) <= threshold) {
            wm_hashcash_store_be32(prefix, nonce);
            return wm_hashcash_b64_encode(prefix, sizeof(prefix),
                prefix_b64, prefix_b64_size);
        }

        if ((nonce & 7UL) == 7UL) {
            char msg[96];

            _snprintf(msg, sizeof(msg),
                "BearSSL hashcash tried %lu nonces in %lu seconds...",
                nonce + 1UL, (GetTickCount() - start_tick) / 1000UL);
            msg[sizeof(msg) - 1] = '\0';
            wm_hashcash_progress(progress, progress_user_data, msg);
        }

        if (nonce == 0xffffffffUL) {
            break;
        }
    }

    return 0;
}

static int
wm_pbkdf2_hmac_sha512_once(
    const char *password,
    const unsigned char *data,
    unsigned int data_len,
    unsigned char *out
)
{
    br_hmac_key_context kc;
    br_hmac_context hc;

    if (password == 0 || data == 0 || out == 0) {
        return 0;
    }

    br_hmac_key_init(&kc, &br_sha512_vtable, password, strlen(password));
    br_hmac_init(&hc, &kc, 0);
    br_hmac_update(&hc, data, data_len);
    br_hmac_out(&hc, out);
    return 1;
}

int
wm_pbkdf2_sha512_b64salt(
    const char *password,
    const char *salt_b64,
    unsigned int iterations,
    unsigned char *out,
    unsigned int out_len,
    wm_hashcash_progress_fn progress,
    void *progress_user_data
)
{
    unsigned char salt[64];
    unsigned char first_input[68];
    unsigned char u[64];
    unsigned char t[64];
    unsigned int salt_len;
    unsigned int produced;
    unsigned int block_index;
    int decoded;

    if (password == 0 || salt_b64 == 0 || out == 0 || out_len == 0 || iterations == 0) {
        return 0;
    }

    decoded = wm_hashcash_b64_decode(salt_b64, salt, sizeof(salt));
    if (decoded <= 0) {
        return 0;
    }
    salt_len = (unsigned int)decoded;

    produced = 0;
    block_index = 1;
    while (produced < out_len) {
        unsigned int i;
        unsigned int copy_len;

        if (salt_len + 4 > sizeof(first_input)) {
            return 0;
        }

        memcpy(first_input, salt, salt_len);
        first_input[salt_len + 0] = (unsigned char)((block_index >> 24) & 0xff);
        first_input[salt_len + 1] = (unsigned char)((block_index >> 16) & 0xff);
        first_input[salt_len + 2] = (unsigned char)((block_index >> 8) & 0xff);
        first_input[salt_len + 3] = (unsigned char)(block_index & 0xff);

        if (!wm_pbkdf2_hmac_sha512_once(password, first_input, salt_len + 4, u)) {
            return 0;
        }
        memcpy(t, u, sizeof(t));

        for (i = 1; i < iterations; ++i) {
            unsigned int j;

            if (!wm_pbkdf2_hmac_sha512_once(password, u, sizeof(u), u)) {
                return 0;
            }
            for (j = 0; j < sizeof(t); ++j) {
                t[j] ^= u[j];
            }

            if ((i % 10000U) == 0U && block_index == 1U) {
                char msg[96];

                _snprintf(msg, sizeof(msg),
                    "PBKDF2-SHA512 %u/%u iterations...",
                    i, iterations);
                msg[sizeof(msg) - 1] = '\0';
                wm_hashcash_progress(progress, progress_user_data, msg);
            }
        }

        copy_len = out_len - produced;
        if (copy_len > sizeof(t)) {
            copy_len = sizeof(t);
        }
        memcpy(out + produced, t, copy_len);
        produced += copy_len;
        block_index++;
    }

    memset(salt, 0, sizeof(salt));
    memset(first_input, 0, sizeof(first_input));
    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
    return 1;
}
