#include "tls.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void test_socket_client_hello(void)
{
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    assert(client_ctx != NULL && server_ctx != NULL);

    tls_register_client_hello_callback(server_ctx);

    SSL *client = SSL_new(client_ctx);
    assert(client != NULL);

    BIO *client_read = BIO_new(BIO_s_mem());
    BIO *client_write = BIO_new(BIO_s_mem());
    assert(client_read != NULL && client_write != NULL);

    SSL_set_bio(client, client_read, client_write);
    SSL_set_connect_state(client);

    assert(SSL_set_tlsext_host_name(client, "example.com") == 1);

	static const unsigned char offered_alpn[] = {
		0x02, 'h', '2',
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};

	assert(SSL_set_alpn_protos(client, offered_alpn, sizeof offered_alpn) == 0);

    // Generate a TLS ClientHello.
    (void)SSL_do_handshake(client);

    unsigned char data[4096];
    int length = BIO_read(client_write, data, sizeof data);
    assert(length > 0);

    // Send the ClientHello through a genuine socket.
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(send(sockets[1], data, length, 0) == length);

    struct tls_hello_info info = {0};

    assert(tls_inspect_client_hello(server_ctx, sockets[0], &info));
    assert(info.seen);
    assert(strcmp(info.sni, "example.com") == 0);
	assert(strcmp(info.alpn, "h2, http/1.1") == 0);

    close(sockets[0]);
    close(sockets[1]);

    SSL_free(client);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
}

static void test_client_hello_callback(void)
{
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    assert(client_ctx != NULL && server_ctx != NULL);

    tls_register_client_hello_callback(server_ctx);

    SSL *client = SSL_new(client_ctx);
    SSL *server = SSL_new(server_ctx);
    assert(client != NULL && server != NULL);

    BIO *client_read = BIO_new(BIO_s_mem());
    BIO *client_write = BIO_new(BIO_s_mem());
    BIO *server_read = BIO_new(BIO_s_mem());
    BIO *server_write = BIO_new(BIO_s_mem());
    assert(client_read && client_write && server_read && server_write);

    // SSL_set_bio takes ownership of the BIOs.
    SSL_set_bio(client, client_read, client_write);
    SSL_set_bio(server, server_read, server_write);

    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    assert(SSL_set_tlsext_host_name(client, "example.com") == 1);

    struct tls_hello_info info = {0};
    SSL_set_app_data(server, &info);

    // Generate a genuine TLS ClientHello.
    assert(SSL_do_handshake(client) <= 0);

    unsigned char wire[4096];
    int count = BIO_read(client_write, wire, sizeof wire);
    assert(count > 0);

    // Feed the ClientHello into the server's input BIO.
    assert(BIO_write(server_read, wire, count) == count);

    // This invokes our callback.
    // The handshake need not succeed without a certificate.
    (void)SSL_do_handshake(server);

    assert(info.seen);
    assert(info.legacy_version != 0);
    assert(strcmp(info.sni, "example.com") == 0);

	assert(info.version_count > 0);

	bool found_tls13 = false;

	for (size_t i = 0; i < info.version_count; i++)
	{
		if (info.versions[i] == 0x0304)
			found_tls13 = true;
	}

	assert(found_tls13);

	static const unsigned char valid_alpn[] = {
		0x00, 0x0c,
		0x02, 'h', '2',
		0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};

	char alpn[256];

	assert(tls_parse_alpn(valid_alpn, sizeof valid_alpn, alpn, sizeof alpn));
	assert(strcmp(alpn, "h2, http/1.1") == 0);

	// Truncated extension must fail without returning partial data.
	assert(!tls_parse_alpn(valid_alpn, sizeof valid_alpn - 1, alpn, sizeof alpn));
	assert(alpn[0] == '\0');

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
}



int main(void)
{
    static const unsigned char valid[] = {
        0x00, 0x0e, 0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };

    char hostname[256];

    assert(tls_parse_sni(valid, sizeof valid, hostname, sizeof hostname));
    assert(strcmp(hostname, "example.com") == 0);

    // Truncated extension.
    assert(!tls_parse_sni(valid, sizeof valid - 1, hostname, sizeof hostname));
    assert(hostname[0] == '\0');

    // Output buffer too small.
    assert(!tls_parse_sni(valid, sizeof valid, hostname, 5));
    assert(hostname[0] == '\0');

    // Embedded NUL in the hostname.
    static const unsigned char embedded_nul[] = {0, 4, 0, 0, 1, 0};
    assert(!tls_parse_sni(embedded_nul, sizeof embedded_nul, hostname, sizeof hostname));

	// Valid hostname followed by a malformed trailing entry.
	// The SNI name list declares 15 bytes: 14 valid bytes + 1 invalid byte.
	static const unsigned char malformed_trailing[] = {
		0x00, 0x0f,
		0x00, 0x00, 0x0b,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0xff
	};

	static const unsigned char valid_versions[] = {
		0x04, 0x03, 0x04, 0x03, 0x03
	};

	uint16_t versions[4] = {0};
	size_t version_count = 0;

	assert(tls_parse_supported_versions(
		valid_versions, sizeof valid_versions,
		versions, 4, &version_count));

	assert(version_count == 2);
	assert(versions[0] == 0x0304); // TLS 1.3
	assert(versions[1] == 0x0303); // TLS 1.2

	// Truncated extension.
	assert(!tls_parse_supported_versions(
		valid_versions, sizeof valid_versions - 1,
		versions, 4, &version_count));

	assert(version_count == 0);

	// Output capacity too small.
	assert(!tls_parse_supported_versions(
		valid_versions, sizeof valid_versions,
		versions, 1, &version_count));

	assert(version_count == 0);

	// Odd-length version list.
	static const unsigned char odd_versions[] = {
		0x03, 0x03, 0x04, 0x03
	};

	assert(!tls_parse_supported_versions(
		odd_versions, sizeof odd_versions,
		versions, 4, &version_count));

	assert(!tls_parse_sni(
		malformed_trailing,
		sizeof malformed_trailing,
		hostname,
		sizeof hostname));

		test_client_hello_callback();
		test_socket_client_hello();

		puts("TLS SNI tests passed");
		return 0;
	}
