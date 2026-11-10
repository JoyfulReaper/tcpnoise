#ifndef TCPNOISE_TLS_H
#define TCPNOISE_TLS_H

#include <stdbool.h>
#include <stddef.h>
#include <openssl/ssl.h>
#include <stdint.h>

#define TLS_MAX_VERSIONS 16

struct tls_hello_info
{
    bool seen;
    unsigned int legacy_version;
    char sni[256];
    char alpn[256];
    uint16_t versions[TLS_MAX_VERSIONS];
	size_t version_count;
};

bool tls_parse_sni(const unsigned char *ext, size_t ext_len, char *hostname, size_t hostname_size);

void tls_register_client_hello_callback(SSL_CTX *ctx);

bool tls_inspect_client_hello(SSL_CTX *ctx, int fd, struct tls_hello_info *info);

bool tls_parse_supported_versions(
    const unsigned char *ext,
    size_t ext_len,
    uint16_t *versions,
    size_t capacity,
    size_t *version_count);

bool tls_parse_alpn(
    const unsigned char *ext,
    size_t ext_len,
    char *output,
    size_t output_size);

#endif
