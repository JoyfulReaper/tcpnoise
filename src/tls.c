#include "tls.h"

#include <openssl/tls1.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <time.h>

#define TLS_HELLO_DEADLINE_MS 500

bool tls_inspect_client_hello(SSL_CTX *ctx, int fd, struct tls_hello_info *info)
{
    if (ctx == NULL || fd < 0 || info == NULL)
        return false;

    memset(info, 0, sizeof *info);

    int old_flags = fcntl(fd, F_GETFL);
    if (old_flags < 0 || fcntl(fd, F_SETFL, old_flags | O_NONBLOCK) < 0)
        return false;

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL || SSL_set_fd(ssl, fd) != 1)
    {
        SSL_free(ssl);
        (void)fcntl(fd, F_SETFL, old_flags);
        return false;
    }

    SSL_set_app_data(ssl, info);
    SSL_set_accept_state(ssl);

    struct timespec now;
    bool seen = false;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
    {
        int64_t deadline = (int64_t)now.tv_sec * 1000000000LL + now.tv_nsec +
            (int64_t)TLS_HELLO_DEADLINE_MS * 1000000LL;

        for (;;)
        {
            int result = SSL_accept(ssl);

            if (info->seen)
            {
                seen = true;
                break;
            }

            if (result == 1)
                break;

            int ssl_error = SSL_get_error(ssl, result);

            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
                break;

            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
                break;

            int64_t remaining = deadline -
                ((int64_t)now.tv_sec * 1000000000LL + now.tv_nsec);

            if (remaining <= 0)
                break;

            struct pollfd pfd = {
                .fd = fd,
                .events = ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT
            };

            int timeout_ms = (int)((remaining + 999999LL) / 1000000LL);

            int ready = poll(&pfd, 1, timeout_ms);

			if (ready < 0)
			{
				if (errno == EINTR)
					continue;

				break;
			}

			if (ready == 0)
				break;

			if (pfd.revents & (POLLERR | POLLNVAL))
				break;

			if ((pfd.revents & POLLHUP) && !(pfd.revents & pfd.events))
				break;
        }
    }

    SSL_free(ssl);
    (void)fcntl(fd, F_SETFL, old_flags);

    return seen;
}

bool tls_parse_sni(const unsigned char *ext, size_t ext_len, char *hostname, size_t hostname_size)
{
    if (hostname == NULL || hostname_size == 0)
        return false;

    hostname[0] = '\0';

    if (ext == NULL || ext_len < 2)
        return false;

    size_t list_len = ((size_t)ext[0] << 8) | ext[1];

    if (list_len == 0 || list_len != ext_len - 2)
        return false;

    size_t host_start = 0;
    size_t host_len = 0;

    for (size_t pos = 2; pos < ext_len;)
    {
        if (ext_len - pos < 3)
            return false;

        unsigned int name_type = ext[pos++];
        size_t name_len = ((size_t)ext[pos] << 8) | ext[pos + 1];
        pos += 2;

        if (name_len > ext_len - pos)
            return false;

        if (name_type == TLSEXT_NAMETYPE_host_name)
        {
            // Reject empty or duplicate host_name entries.
            if (host_len != 0 || name_len == 0 || name_len >= hostname_size)
                return false;

            for (size_t i = 0; i < name_len; i++)
            {
                unsigned char c = ext[pos + i];

                if (!((c >= 'a' && c <= 'z') ||
                      (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') ||
                      c == '-' || c == '.'))
                    return false;
            }

            host_start = pos;
            host_len = name_len;
        }

        pos += name_len;
    }

    if (host_len == 0)
        return false;

    memcpy(hostname, ext + host_start, host_len);
    hostname[host_len] = '\0';

    return true;
}

static int capture_client_hello(SSL *ssl, int *alert, void *arg)
{
    (void)alert;
    (void)arg;

    struct tls_hello_info *info = SSL_get_app_data(ssl);

    if (info != NULL)
    {
        info->seen = true;
        info->legacy_version = SSL_client_hello_get0_legacy_version(ssl);
        info->sni[0] = '\0';
        info->version_count = 0;

        const unsigned char *ext = NULL;
        size_t ext_len = 0;

        if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &ext, &ext_len) == 1)
        {
            tls_parse_sni(ext, ext_len, info->sni, sizeof info->sni);
        }

        ext = NULL;
        ext_len = 0;

        if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_versions, &ext, &ext_len) == 1)
        {
            tls_parse_supported_versions(
                ext,
                ext_len,
                info->versions,
                TLS_MAX_VERSIONS,
                &info->version_count);
        }
        
        info->alpn[0] = '\0';

		ext = NULL;
		ext_len = 0;

		if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &ext, &ext_len) == 1)
		{
			tls_parse_alpn(ext, ext_len, info->alpn, sizeof info->alpn);
		}
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

void tls_register_client_hello_callback(SSL_CTX *ctx)
{
    SSL_CTX_set_client_hello_cb(ctx, capture_client_hello, NULL);
}

bool tls_parse_alpn(const unsigned char *ext, size_t ext_len, char *output, size_t output_size)
{
    if (output == NULL || output_size == 0)
        return false;

    output[0] = '\0';

    if (ext == NULL || ext_len < 4)
        return false;

    size_t list_len = ((size_t)ext[0] << 8) | ext[1];

    if (list_len != ext_len - 2)
        return false;

    size_t pos = 2;
    size_t required = 0;
    size_t count = 0;

    // Validate the complete extension before writing output.
    while (pos < ext_len)
    {
        size_t name_len = ext[pos++];

        if (name_len == 0 || name_len > ext_len - pos)
            return false;

        for (size_t i = 0; i < name_len; i++)
        {
            unsigned char c = ext[pos + i];

            if (c < 0x21 || c > 0x7e)
                return false;
        }

        required += name_len + (count > 0 ? 2 : 0);

        if (required >= output_size)
            return false;

        pos += name_len;
        count++;
    }

    if (count == 0)
        return false;

    pos = 2;
    size_t written = 0;

    while (pos < ext_len)
    {
        size_t name_len = ext[pos++];

        if (written > 0)
        {
            output[written++] = ',';
            output[written++] = ' ';
        }

        memcpy(output + written, ext + pos, name_len);
        written += name_len;
        pos += name_len;
    }

    output[written] = '\0';
    return true;
}

bool tls_parse_supported_versions(
    const unsigned char *ext,
    size_t ext_len,
    uint16_t *versions,
    size_t capacity,
    size_t *version_count)
{
    if (version_count == NULL)
        return false;

    *version_count = 0;

    if (ext == NULL || versions == NULL || ext_len < 3)
        return false;

    size_t list_len = ext[0];

    // Each TLS version occupies exactly two bytes.
    if (list_len < 2 || (list_len % 2) != 0 ||
        list_len != ext_len - 1)
        return false;

    size_t count = list_len / 2;

    if (count > capacity)
        return false;

    for (size_t i = 0; i < count; i++)
    {
        size_t pos = 1 + i * 2;

        versions[i] =
            ((uint16_t)ext[pos] << 8) |
            ext[pos + 1];
    }

    *version_count = count;
    return true;
}
