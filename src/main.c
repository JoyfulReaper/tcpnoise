/*
 * tcpnoise
 * A fun little C tool
 * See what the bots want or something
 * Copyright 2026 Kyle Givler
 * Licensed under the 3-Clause BSD License
 */

#include "banner.h"
#include "logging.h"
#include "network.h"
#include "database.h"
#include "messaging.h"
#include "http.h"
#include "tls.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <poll.h>
#include <stddef.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define NATS_SERVER "nats://10.99.0.1:4222"
#define MAX_PAYLOAD_LEN 4096
#define MAX_PORT 64
#define MAX_LISTENERS (MAX_PORT * 2)
#define MAX_SENSOR_NAME 256

volatile sig_atomic_t running = 1;

struct listener
{
	int fd;
	uint16_t port;
	int family;
	size_t port_index;
	struct banner_pool const *banners;
	FILE *log_file;
	bool tls_inspection;
};

struct connection_event
{
	uint64_t connection_number;
	uint16_t port;
	uint16_t remote_port;
	char ip[INET6_ADDRSTRLEN];
	uint64_t seen_count;
	char timestamp[64];
	char timestamp_utc[64];
	char payload[MAX_PAYLOAD_LEN];
	ssize_t payload_len;
};

enum connection_result
{
	CONNECTION_OK,
	CONNECTION_SHUTDOWN,
	CONNECTION_FATAL
};


void print_usage(char *program)
{
    fprintf(stderr,
        "Usage: %s [--bind IPv4-or-IPv6-address] <port> [port ...]\n",
        program);
}

bool uint16_exists(const uint16_t *arr, size_t size, uint16_t target)
{
	for (size_t i = 0; i < size; i++)
	{
		if (arr[i] == target)
		{
			return true;
		}
	}
	return false;
}

bool process_arguments(
    int argc,
    char *argv[],
    uint16_t *ports,
    size_t *port_count,
    const char **bind_address,
    int *bind_family)
{
    int first_port = 1;

    *bind_address = NULL;
    *bind_family = AF_UNSPEC;

    if (argc >= 2 && strcmp(argv[1], "--bind") == 0)
    {
        if (argc < 4)
            return false;

        *bind_address = argv[2];
        first_port = 3;

        struct in_addr ipv4;
        struct in6_addr ipv6;

        if (inet_pton(AF_INET, *bind_address, &ipv4) == 1)
            *bind_family = AF_INET;
        else if (inet_pton(AF_INET6, *bind_address, &ipv6) == 1)
            *bind_family = AF_INET6;
        else
            return false;
    }

    if (argc <= first_port || argc - first_port > MAX_PORT)
        return false;

    for (int i = first_port; i < argc; i++)
    {
        char *end;
        errno = 0;
        long value = strtol(argv[i], &end, 10);

        if (errno == ERANGE ||
            end == argv[i] ||
            *end != '\0' ||
            value < 1 ||
            value > 65535)
        {
            return false;
        }

        uint16_t parsed_port = (uint16_t)value;

        if (!uint16_exists(ports, *port_count, parsed_port))
        {
            ports[*port_count] = parsed_port;
            (*port_count)++;
        }
    }

    return true;
}

void close_listeners(struct listener listeners[], size_t listener_count)
{
	for(size_t i = 0; i < listener_count; i++)
	{
		close(listeners[i].fd);
	}
}

void handle_signal(int signal)
{
	(void)signal;
	running = 0;
}

void capture_timestamp_utc(char *buffer, size_t buffer_size)
{
	snprintf(buffer, buffer_size, "(unknown time)");

	time_t now = time(NULL);
	if(now == (time_t)-1)
	{
		return;
	}

	struct tm *t_info = gmtime(&now);
	if(t_info == NULL)
	{
		return;
	}

	if(strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", t_info) == 0)
	{
		snprintf(buffer, buffer_size, "(unknown time)");
	}
}

void capture_timestamp(char *buffer, size_t buffer_size)
{
	snprintf(buffer, buffer_size, "(unknown time)");

	time_t now = time(NULL);
	if(now == (time_t)-1)
	{
		return;
	}

	struct tm *t_info = localtime(&now);
	if(t_info == NULL)
	{
		return;
	}

	if(strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", t_info) == 0)
	{
		snprintf(buffer, buffer_size, "(unknown time)");
	}
}

enum connection_result handle_connection(
	int cfd,
	const struct listener *listener,
	SSL_CTX *tls_ctx,
	sqlite3 *db,
	natsConnection *nats_connection,
	const char *sensor_name,
	uint64_t connection_number,
	const struct sockaddr_storage *peer_addr,
	socklen_t peer_addr_size)
{
	struct connection_event event;

	bool banner_sent = false;

	capture_timestamp(event.timestamp, sizeof event.timestamp);
	capture_timestamp_utc(event.timestamp_utc, sizeof event.timestamp_utc);

	const char *banner = listener->tls_inspection
		? NULL
		: choose_banner(listener->banners);
	if(banner != NULL)
	{
		if(send_banner(cfd, banner))
		{
			banner_sent = true;
		} else {
			// printf("Failed to send banner: %s\n", banner);
		}
	}

	event.connection_number = connection_number;
	event.port = listener->port;

	int ip_version;
	if(listener->family == AF_INET)
	{
		ip_version = 4;
	}
	else if(listener->family == AF_INET6)
	{
		ip_version = 6;
	}
	else
	{
		fprintf(stderr, "Unexpected listener address family: %d\n", listener->family);
		close(cfd);
		return CONNECTION_FATAL;
	}

	struct tls_hello_info tls_info = {0};
	bool tls_seen = false;

	enum receive_status payload_result = RECEIVE_DATA;
	event.payload_len = 0;
	event.payload[0] = '\0';

	if (listener->tls_inspection)
	{
		if (tls_ctx == NULL)
		{
			close(cfd);
			return CONNECTION_FATAL;
		}

		tls_seen = tls_inspect_client_hello(tls_ctx, cfd, &tls_info);
	}
	else
	{
		if (!set_receive_timeout(cfd))
		{
			close(cfd);
			return CONNECTION_FATAL;
		}

		payload_result = receive_payload(
			cfd,
			event.payload,
			sizeof event.payload,
			&event.payload_len);
	}

	if(payload_result == RECEIVE_INTERRUPTED)
	{
		if(!running)
		{
			close(cfd);
			return CONNECTION_SHUTDOWN;
		}

		perror("recv");
	}
	else if(payload_result == RECEIVE_ERROR)
	{
		perror("recv");
	}

	char user_agent[256];
	bool has_user_agent = false;

	if (!listener->tls_inspection && payload_result == RECEIVE_DATA)
	{
		has_user_agent = extract_http_user_agent(
			event.payload,
			(size_t)event.payload_len,
			user_agent,
			sizeof user_agent);
	}

	resolve_remote(
		peer_addr,
		peer_addr_size,
		event.ip,
		sizeof event.ip,
		&event.remote_port);

	if(!database_record_seen_ip(
		db,
		event.ip,
		event.timestamp_utc,
		&event.seen_count))
	{
		fprintf(stderr, "Failed to update persistent seen-IP table\n");
		event.seen_count = 0;
	}

	if(!database_record_port_connection(
		db,
		event.port,
		ip_version,
		event.timestamp_utc))
	{
		fprintf(stderr,
			"Failed to update persistent port activity table\n");
	}

	messaging_publish_connection(
		nats_connection,
		sensor_name,
		event.connection_number,
		event.port,
		ip_version,
		event.ip,
		event.remote_port,
		event.seen_count,
		banner,
		banner_sent,
		event.payload,
		event.payload_len > 0 ? (size_t)event.payload_len : 0,
		has_user_agent ? user_agent : NULL,
		event.timestamp_utc);

	char remote_endpoint[INET6_ADDRSTRLEN + 8];
	format_remote_endpoint(
		remote_endpoint,
		sizeof remote_endpoint,
		peer_addr->ss_family,
		event.ip,
		event.remote_port);

	const char *family_name =
		listener->family == AF_INET6 ? "IPv6" : "IPv4";

	const char *console_time = event.timestamp;
	if(strlen(event.timestamp) >= 19)
	{
		console_time = event.timestamp + 11;
	}

	char output_buffer[256];

	int cx = snprintf(
		output_buffer,
		sizeof output_buffer,
		"[%s] connection #%" PRIu64 "  TCP/%hu  %s  %s  seen=%" PRIu64,
		console_time,
		event.connection_number,
		event.port,
		family_name,
		remote_endpoint,
		event.seen_count);

	if(cx >= (int)sizeof output_buffer)
	{
		fprintf(stderr, "output_buffer is too small\n");
		close(cfd);
		return CONNECTION_OK;
	}
	else if(cx < 0)
	{
		fprintf(stderr, "Encoding error\n");
		close(cfd);
		return CONNECTION_OK;
	}

	char log_buffer[256];

	int lx = snprintf(
		log_buffer,
		sizeof log_buffer,
		"[%s] connection #%" PRIu64 "  TCP/%hu  %s  %s  seen=%" PRIu64,
		event.timestamp,
		event.connection_number,
		event.port,
		family_name,
		remote_endpoint,
		event.seen_count);

	if(lx >= (int)sizeof log_buffer)
	{
		fprintf(stderr, "log_buffer is too small\n");
		close(cfd);
		return CONNECTION_OK;
	}
	else if(lx < 0)
	{
		fprintf(stderr, "Encoding error\n");
		close(cfd);
		return CONNECTION_OK;
	}

	printf("%s\n", output_buffer);

	if(banner == NULL)
	{
		printf("           banner: <none>\n");
	}
	else if(banner_sent)
	{
		printf("           banner: %s\n", banner);
	}
	else
	{
		printf("           banner: <send failed> %s\n", banner);
	}

	if(has_user_agent)
	{
		printf("           user-agent: %s\n", user_agent);
	}

	if (listener->tls_inspection)
	{
		printf("           tls-clienthello: %s\n",
			tls_seen ? "seen" : "not observed");

		if (tls_seen)
		{
			printf("           sni: %s\n",
				tls_info.sni[0] ? tls_info.sni : "<absent>");

			printf("           legacy-version: 0x%04x\n",
				tls_info.legacy_version);
				
			printf("           offered-versions:");

			if (tls_info.version_count == 0)
			{
				printf(" <absent>");
			}
			else
			{
				for (size_t i = 0; i < tls_info.version_count; i++)
				{
					printf(" 0x%04x", (unsigned int)tls_info.versions[i]);
				}
			}

			printf("\n");
			printf("           offered-alpn: %s\n",
				tls_info.alpn[0] ? tls_info.alpn : "<absent>");
		}
	}
	else if (payload_result == RECEIVE_DATA)
	{
		printf("           payload: ");
		print_payload(stdout, event.payload, event.payload_len);
	}
	else if(payload_result == RECEIVE_CLOSED)
	{
		printf("           payload: <peer closed>\n");
	}
	else if(payload_result == RECEIVE_TIMEOUT)
	{
		printf("           payload: <timeout>\n");
	}
	else if(payload_result == RECEIVE_INTERRUPTED)
	{
		printf("           payload: <interrupted>\n");
	}
	else
	{
		printf("           payload: <receive error>\n");
	}

	close(cfd);

	if (listener->tls_inspection)
	{
		int written = fprintf(
			listener->log_file,
			"%s\n"
			"- banner: <none>\n"
			"- tls-clienthello: %s\n",
			log_buffer,
			tls_seen ? "seen" : "not observed");

		if (tls_seen)
		{
			if (fprintf(
				listener->log_file,
				"- sni: %s\n"
				"- legacy-version: 0x%04x\n",
				tls_info.sni[0] ? tls_info.sni : "<absent>",
				tls_info.legacy_version) < 0)
			{
				written = -1;
			}
		}
		
		if (tls_seen && written >= 0)
		{
			if (fprintf(listener->log_file, "- offered-versions:") < 0)
				written = -1;

			if (tls_info.version_count == 0)
			{
				if (fprintf(listener->log_file, " <absent>") < 0)
					written = -1;
			}
			else
			{
				for (size_t i = 0; i < tls_info.version_count; i++)
				{
					if (fprintf(listener->log_file, " 0x%04x",
						(unsigned int)tls_info.versions[i]) < 0)
					{
						written = -1;
						break;
					}
				}
			}

			// Finish the offered-versions line.
			if (written >= 0 && fputc('\n', listener->log_file) == EOF)
				written = -1;

			// Write ALPN exactly once, on its own line.
			if (written >= 0 &&
				fprintf(listener->log_file, "- offered-alpn: %s\n",
					tls_info.alpn[0] ? tls_info.alpn : "<absent>") < 0)
			{
				written = -1;
			}
		}

		if (written < 0 || fflush(listener->log_file) != 0)
			perror("TLS connection log");
	}
	else
	{
		log_connection(
			listener->log_file,
			log_buffer,
			event.payload,
			event.payload_len,
			payload_result,
			banner,
			banner_sent,
			has_user_agent ? user_agent : NULL);
	}

	return CONNECTION_OK;
}

int main (int argc, char *argv[])
{
	srand(time(NULL));

	// Parse port
	uint16_t ports[MAX_PORT];
	size_t port_count = 0;

        const char *bind_address = NULL;
        int bind_family = AF_UNSPEC;

	struct listener listeners[MAX_LISTENERS];
	size_t listener_count = 0;

	uint64_t connection_counts[MAX_PORT] = {0};
	struct banner_pool banner_pools[MAX_PORT] = {0};

	FILE *log_files[MAX_PORT] = {0};

	struct pollfd pollfds[MAX_LISTENERS];

	int families[] = { AF_INET, AF_INET6 };
	size_t family_count = sizeof families / sizeof families[0];

        if(!process_arguments(
            argc, argv, ports, &port_count,
            &bind_address, &bind_family))
	{
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	uint16_t tls_port = 0;
	const char *tls_port_env = getenv("TCPNOISE_TLS_PORT");

	if (tls_port_env != NULL && tls_port_env[0] != '\0')
	{
		char *end;
		errno = 0;

		long value = strtol(tls_port_env, &end, 10);

		if (errno != 0 || end == tls_port_env || *end != '\0' ||
			value < 1 || value > 65535 ||
			!uint16_exists(ports, port_count, (uint16_t)value))
		{
			fprintf(stderr, "Invalid TCPNOISE_TLS_PORT: %s\n", tls_port_env);
			return EXIT_FAILURE;
		}

		tls_port = (uint16_t)value;
	}

    // Restrict listeners to the requested address family.
	// Without --bind, retain the original IPv4 + IPv6 behavior.
	if (bind_family != AF_UNSPEC)
	{
		families[0] = bind_family;
		family_count = 1;
	}

	// Sensor Name
	const char *sensor_override = getenv("TCPNOISE_SENSOR");
	char sensor_name[MAX_SENSOR_NAME];
	if(sensor_override != NULL && sensor_override[0] != '\0')
	{
		snprintf(sensor_name, sizeof sensor_name, "%s", sensor_override);
	}
	else if(gethostname(sensor_name, sizeof sensor_name) != 0)
	{
		perror("gethostname");
		snprintf(sensor_name, sizeof sensor_name, "unknown");
	}
	sensor_name[sizeof sensor_name -1] = '\0';

	// Register signal handler
	struct sigaction action;
	memset(&action, 0, sizeof action);
	action.sa_handler = handle_signal;
	sigemptyset(&action.sa_mask);

	if(sigaction(SIGINT, &action, NULL) == -1)
	{
		perror("sigaction SIGINT");
		return EXIT_FAILURE;
	}

	if(sigaction(SIGTERM, &action, NULL) == -1)
	{
		perror("sigaction SIGTERM");
		return EXIT_FAILURE;
	}

	action.sa_handler = SIG_IGN;
	if(sigaction(SIGPIPE, &action, NULL) == -1)
	{
		perror("sigaction SIGPIPE");
		return EXIT_FAILURE;
	}

	// Create, Bind and Listen on socket
	for(size_t i = 0; i < port_count; i++)
	{
		if(!load_banner_file(ports[i], &banner_pools[i]))
		{
			fprintf(stderr, "Failed to load banner for port: %" PRIu16 "\n", ports[i]);
			free_banner_pools(banner_pools, port_count);
			close_listeners(listeners, listener_count);
			close_log_files(log_files, port_count);
			return EXIT_FAILURE;
		}

		// Open log files
		char logfilename[64];
		if(!get_log_filename(ports[i], logfilename, sizeof logfilename))
		{
			fprintf(stderr, "Failed to get log filename for port: %" PRIu16 "\n", ports[i]);
			close_log_files(log_files, port_count);
			close_listeners(listeners, listener_count);
			free_banner_pools(banner_pools, port_count);
			return EXIT_FAILURE;
		}
		log_files[i] = fopen(logfilename, "a");
		if(log_files[i] == NULL)
		{
			perror("fopen");
			close_log_files(log_files, port_count);
			close_listeners(listeners, listener_count);
			free_banner_pools(banner_pools, port_count);
			return EXIT_FAILURE;
		}

		for(size_t f = 0; f < family_count; f++)
		{
			size_t listener_index = listener_count;

			listeners[listener_index].family = families[f];
			listeners[listener_index].port = ports[i];
			listeners[listener_index].port_index = i;
			listeners[listener_index].fd = create_socket(listeners[listener_index].family);
			listeners[listener_index].banners = &banner_pools[i];
			listeners[listener_index].log_file = log_files[i];
			listeners[listener_index].tls_inspection = (ports[i] == tls_port);

			if (listeners[listener_index].fd < 0)
			{
				close_log_files(log_files, port_count);
				close_listeners(listeners, listener_count);
				free_banner_pools(banner_pools, port_count);
				return EXIT_FAILURE;
			}

			if(!bind_socket(
				listeners[listener_index].fd,
				listeners[listener_index].port,
				listeners[listener_index].family,
				bind_address))
			{
				close_log_files(log_files, port_count);
				close(listeners[listener_index].fd);
				free_banner_pools(banner_pools, port_count);
				close_listeners(listeners, listener_count);
				return EXIT_FAILURE;
			}

			if(!listen_socket(listeners[listener_index].fd))
			{
				close_log_files(log_files, port_count);
				close(listeners[listener_index].fd);
				free_banner_pools(banner_pools, port_count);
				close_listeners(listeners, listener_count);
				return EXIT_FAILURE;
			}

			pollfds[listener_index].fd = listeners[listener_index].fd;
			pollfds[listener_index].events = POLLIN;
			pollfds[listener_index].revents = 0;

			listener_count++;

			const char *family_name = listeners[listener_index].family == AF_INET ? "IPv4" : "IPv6";
			printf("Listening for noise on port: %hu (%s)\n", listeners[listener_index].port, family_name);
		}
	}

	// Open database
	sqlite3 *db = NULL;
	if(!database_open("tcpnoise.db", &db))
	{
		fprintf(stderr, "Failed to open tcpnoise database.\n");

		close_log_files(log_files, port_count);
		free_banner_pools(banner_pools, port_count);
		close_listeners(listeners, listener_count);

		return EXIT_FAILURE;
	}

	if(!database_initialize(db))
	{
		database_close(db);
		close_log_files(log_files, port_count);
		free_banner_pools(banner_pools, port_count);
		close_listeners(listeners, listener_count);

		return EXIT_FAILURE;
	}

	// Connect to NATS
	const char *nats_url = getenv("TCPNOISE_NATS_URL");

	if (nats_url == NULL || nats_url[0] == '\0')
		nats_url = NATS_SERVER;

	natsConnection *nats_connection = messaging_connect(nats_url);

	SSL_CTX *tls_ctx = NULL;

	if (tls_port != 0)
	{
		tls_ctx = SSL_CTX_new(TLS_server_method());

		if (tls_ctx == NULL)
		{
			fprintf(stderr, "Failed to initialize TLS context\n");

			messaging_disconnect(nats_connection);
			database_close(db);
			close_log_files(log_files, port_count);
			free_banner_pools(banner_pools, port_count);
			close_listeners(listeners, listener_count);

			return EXIT_FAILURE;
		}

		tls_register_client_hello_callback(tls_ctx);

		printf("TLS ClientHello inspection enabled on port %" PRIu16 "\n", tls_port);
	}

	// Main loop
	while (running) {
		int num_selected = poll(pollfds, listener_count, -1);
		if(num_selected == -1 && errno == EINTR && running == 0)
		{
			printf("\nShutdown signal caught, shutting down...\n");
			break;
		}
		if (num_selected == -1)
		{
			perror("poll");
			database_close(db);
			close_log_files(log_files, port_count);
			free_banner_pools(banner_pools, port_count);
			close_listeners(listeners, listener_count);
			return EXIT_FAILURE;
		}

		// Poll
		for(size_t i = 0; i < listener_count; i++)
		{
			if(pollfds[i].revents & POLLIN)
			{
				struct sockaddr_storage peer_addr;
				socklen_t peer_addr_size = sizeof peer_addr;
				int cfd = accept_connection(listeners[i].fd, &peer_addr, &peer_addr_size);

				if(cfd < 0 && errno == EINTR && running == 0)
				{
					printf("\nShutdown signal caught, shutting down...\n");
					break;
				}
				else if(cfd < 0)
				{
					database_close(db);
					close_log_files(log_files, port_count);
					free_banner_pools(banner_pools, port_count);
					close_listeners(listeners, listener_count);
					SSL_CTX_free(tls_ctx);
					return EXIT_FAILURE;
				}
				size_t port_index = listeners[i].port_index;
				connection_counts[port_index]++;

				enum connection_result result =
					handle_connection(
						cfd,
						&listeners[i],
						tls_ctx,
						db,
						nats_connection,
						sensor_name,
						connection_counts[port_index],
						&peer_addr,
						peer_addr_size);

				if(result == CONNECTION_SHUTDOWN)
				{
					break;
				}
				else if(result == CONNECTION_FATAL)
				{
					database_close(db);
					close_log_files(log_files, port_count);
					free_banner_pools(banner_pools, port_count);
					close_listeners(listeners, listener_count);
					SSL_CTX_free(tls_ctx);
					return EXIT_FAILURE;
				}
			}
		}
	}

	messaging_disconnect(nats_connection);
	SSL_CTX_free(tls_ctx);
	close_listeners(listeners, listener_count);
	close_log_files(log_files, port_count);

	if(!database_close(db))
	{
		fprintf(stderr, "Failed to close tcpnoise database.\n");
		return EXIT_FAILURE;
	}

	for(size_t i = 0; i < port_count; i++)
	{
		free_banner_pool(&banner_pools[i]);
		printf("Port %"PRIu16" connection attempts: %" PRIu64 "\n", ports[i], connection_counts[i]);
	}

	return EXIT_SUCCESS;
}
