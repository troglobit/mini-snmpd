/* -----------------------------------------------------------------------------
 * Copyright (C) 2008 Robert Ernst <robert.ernst@linux-solutions.at>
 *
 * This file may be distributed and/or modified under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 * WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See COPYING for GPL licensing information.
 */



#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>

#include "mini_snmpd.h"



/* -----------------------------------------------------------------------------
 * Helper functions
 */

static void print_help(void)
{
	fprintf(stderr, "usage: mini_snmpd [options]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "-p, --udp-port nnn     set the UDP port to bind to (161)\n");
	fprintf(stderr, "-P, --tcp-port nnn     set the TCP port to bind to (161)\n");
	fprintf(stderr, "-c, --community nnn    set the community string (public)\n");
	fprintf(stderr, "-D, --description nnn  set the system description (empty)\n");
	fprintf(stderr, "-V, --vendor nnn       set the system vendor (empty)\n");
	fprintf(stderr, "-L, --location nnn     set the system location (empty)\n");
	fprintf(stderr, "-C, --contact nnn      set the system contact (empty)\n");
	fprintf(stderr, "-d, --disks nnn        set the disks to monitor (/)\n");
	fprintf(stderr, "-i, --interfaces nnn   set the network interfaces to monitor (lo)\n");
	fprintf(stderr, "-t, --timeout nnn      set the timeout for MIB updates (1 second)\n");
	fprintf(stderr, "-a, --auth             require authentication (thus SNMP version 2c)\n");
	fprintf(stderr, "-v, --verbose          verbose syslog messages \n");
	fprintf(stderr, "-l, --licensing        print licensing info and exit\n");
	fprintf(stderr, "-h, --help             print this help and exit\n");
	fprintf(stderr, "\n");
}

static void print_version(void)
{
	fprintf(stderr, "Mini SNMP Daemon Version " VERSION "\n");
	fprintf(stderr, "A minimal simple network management protocol daemon for embedded Linux\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Copyright (C) 2008 Robert Ernst <robert.ernst@aon.at>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "This program is free software; you can redistribute it and/or modify\n");
	fprintf(stderr, "it under the terms of the GNU General Public License as published by\n");
	fprintf(stderr, "the Free Software Foundation; either version 2 of the License, or\n");
	fprintf(stderr, "(at your option) any later version.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "This program is distributed in the hope that it will be useful,\n");
	fprintf(stderr, "but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	fprintf(stderr, "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	fprintf(stderr, "GNU General Public License for more details.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "You should have received a copy of the GNU General Public License\n");
	fprintf(stderr, "along with this program; if not, write to the Free Software\n");
	fprintf(stderr, "Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\n");
	fprintf(stderr, "\n");
}

static void handle_signal(int signo)
{
	g_quit = 1;
}

static void handle_udp_client(void)
{
	struct sockaddr_in sockaddr;
	socklen_t socklen;
	int rv;

	/* Read the whole UDP packet from the socket at once */
	socklen = sizeof (sockaddr);
	rv = recvfrom(g_udp_sockfd, g_udp_client.packet, sizeof (g_udp_client.packet),
		0, (struct sockaddr *)&sockaddr, &socklen);
	if (g_udp_client.size == -1) {
		lprintf(LOG_WARNING, "could not receive packet on UDP port %d: %m\n",
			g_udp_port);
		return;
	}
	g_udp_client.timestamp = time(NULL);
	g_udp_client.sockfd = g_udp_sockfd;
	g_udp_client.addr = sockaddr.sin_addr.s_addr;
	g_udp_client.port = sockaddr.sin_port;
	g_udp_client.size = rv;
	g_udp_client.outgoing = 0;
#ifdef DEBUG
	dump_packet(&g_udp_client);
#endif

	/* Call the protocol handler which will prepare the response packet */
	if (snmp(&g_udp_client) == -1) {
		lprintf(LOG_WARNING, "could not handle packet from UDP client %s:%d: %m\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		return;
	} else if (g_udp_client.size == 0) {
		lprintf(LOG_WARNING, "could not handle packet from UDP client %s:%d: ignored\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		return;
	}
	g_udp_client.outgoing = 1;

	/* Send the whole UDP packet to the socket at once */
	rv = sendto(g_udp_sockfd, g_udp_client.packet, g_udp_client.size,
		MSG_DONTWAIT, (struct sockaddr *)&sockaddr, socklen);
	if (rv == -1) {
		lprintf(LOG_WARNING, "could not send packet to UDP client %s:%d: %m\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
	} else if (rv != g_udp_client.size) {
		lprintf(LOG_WARNING, "could not send packet to UDP client %s:%d: "
			"only %d of %d bytes written\n", inet_ntoa(sockaddr.sin_addr),
			sockaddr.sin_port, rv, g_udp_client.size);
	}
#ifdef DEBUG
	dump_packet(&g_udp_client);
#endif
}

static void handle_tcp_connect(void)
{
	struct sockaddr_in tmp_sockaddr;
	struct sockaddr_in sockaddr;
	socklen_t socklen;
	client_t *client;
	int rv;

	/* Accept the new connection (remember the client's IP address and port) */
	socklen = sizeof (sockaddr);
	rv = accept(g_tcp_sockfd, (struct sockaddr *)&sockaddr, &socklen);
	if (rv == -1) {
		lprintf(LOG_ERR, "could not accept TCP connection: %m\n");
		return;
	} else if (rv >= FD_SETSIZE) {
		lprintf(LOG_ERR, "could not accept TCP connection: FD set overflow\n");
		close(rv);
		return;
	}

	/* Create a new client control structure or overwrite the oldest one */
	if (g_tcp_client_list_length >= MAX_NR_CLIENTS) {
		client = find_oldest_client();
		if (client == NULL) {
			lprintf(LOG_ERR, "could not accept TCP connection: internal error");
			exit(EXIT_SYSCALL);
		}
		tmp_sockaddr.sin_addr.s_addr = client->addr;
		tmp_sockaddr.sin_port = client->port;
		lprintf(LOG_WARNING, "maximum number of %d clients reached, kicking out %s:%d\n",
			MAX_NR_CLIENTS, inet_ntoa(tmp_sockaddr.sin_addr), tmp_sockaddr.sin_port);
		close(client->sockfd);
	} else {
		client = malloc(sizeof (client_t));
		if (client == NULL) {
			lprintf(LOG_ERR, "could not accept TCP connection: %m");
			exit(EXIT_SYSCALL);
		}
		g_tcp_client_list[g_tcp_client_list_length++] = client;
	}

	/* Now fill out the client control structure values */
	lprintf(LOG_DEBUG, "connected TCP client %s:%d\n",
		inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
	client->timestamp = time(NULL);
	client->sockfd = rv;
	client->addr = sockaddr.sin_addr.s_addr;
	client->port = sockaddr.sin_port;
	client->size = 0;
	client->outgoing = 0;
}

static void handle_tcp_client_write(client_t *client)
{
	struct sockaddr_in sockaddr;
	int rv;

	/* Send the packet atomically and close socket if that did not work */
	sockaddr.sin_addr.s_addr = client->addr;
	sockaddr.sin_port = client->port;
	rv = send(client->sockfd, client->packet, client->size, 0);
	if (rv == -1) {
		lprintf(LOG_WARNING, "could not send packet to TCP client %s:%d: %m\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	} else if (rv != client->size) {
		lprintf(LOG_WARNING, "could not send packet to TCP client %s:%d: "
			"only %d of %d bytes written\n", inet_ntoa(sockaddr.sin_addr),
			sockaddr.sin_port, rv, client->size);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
#ifdef DEBUG
	dump_packet(client);
#endif

	/* Put the client into listening mode again */
	client->size = 0;
	client->outgoing = 0;
}

static void handle_tcp_client_read(client_t *client)
{
	struct sockaddr_in sockaddr;
	int rv;

	/* Read from the socket what arrived and put it into the buffer */
	sockaddr.sin_addr.s_addr = client->addr;
	sockaddr.sin_port = client->port;
	rv = read(client->sockfd, client->packet + client->size,
		sizeof (client->packet) - client->size);
	if (rv == -1) {
		lprintf(LOG_WARNING, "could not read packet from TCP client %s:%d: %m\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	} else if (rv == 0) {
		lprintf(LOG_DEBUG, "disconnected TCP client %s:%d\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	client->timestamp = time(NULL);
	client->size += rv;

	/* Check whether the packet was fully received and handle packet if yes */
	rv = snmp_packet_complete(client);
	if (rv == -1) {
		lprintf(LOG_WARNING, "could not handle packet from TCP client %s:%d: %m\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	} else if (rv == 0) {
		return;
	}
	client->outgoing = 0;
#ifdef DEBUG
	dump_packet(client);
#endif

	/* Call the protocol handler which will prepare the response packet */
	if (snmp(client) == -1) {
		lprintf(LOG_WARNING, "could not handle packet from TCP client %s:%d: %m\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	} else if (client->size == 0) {
		lprintf(LOG_WARNING, "could not handle packet from TCP client %s:%d: ignored\n",
			inet_ntoa(sockaddr.sin_addr), sockaddr.sin_port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	client->outgoing = 1;
}



/* -----------------------------------------------------------------------------
 * Main program
 */

int main(int argc, char *argv[])
{
	static const char short_options[] = "p:P:c:D:V:L:C:d:i:t:avlh";
	static const struct option long_options[] = {
		{ "udp-port", 1, 0, 'p' },
		{ "tcp-port", 1, 0, 'P' },
		{ "community", 1, 0, 'c' },
		{ "description", 1, 0, 'D' },
		{ "vendor", 1, 0, 'V' },
		{ "location", 1, 0, 'L' },
		{ "contact", 1, 0, 'C' },
		{ "disks", 1, 0, 'd' },
		{ "interfaces", 1, 0, 'i' },
		{ "timeout", 1, 0, 't' },
		{ "auth", 0, 0, 'a' },
		{ "verbose", 0, 0, 'v' },
		{ "licensing", 0, 0, 'l' },
		{ "help", 0, 0, 'h' },
		{ NULL, 0, 0, 0 }
	};
	int option_index = 1;
	int c;

	struct sockaddr_in sockaddr;
	socklen_t socklen;
	fd_set rfds;
	fd_set wfds;
	int nfds;
	int i;

	/* Prevent TERM and HUP signals from interrupting system calls */
	signal(SIGTERM, handle_signal);
	signal(SIGHUP, handle_signal);
	siginterrupt(SIGTERM, 0);
	siginterrupt(SIGHUP, 0);

	/* Open the syslog connection if needed */
#ifdef SYSLOG
	openlog("mini_snmpd", LOG_CONS | LOG_PID, LOG_DAEMON);
#endif

	/* Parse commandline options */
	while (1) {
		c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'p':
				g_udp_port = atoi(optarg);
				break;
			case 'P':
				g_tcp_port = atoi(optarg);
				break;
			case 'c':
				g_community = strdup(optarg);
				break;
			case 'D':
				g_description = strdup(optarg);
				break;
			case 'V':
				g_vendor = strdup(optarg);
				break;
			case 'L':
				g_location = strdup(optarg);
				break;
			case 'C':
				g_contact = strdup(optarg);
				break;
			case 'd':
				g_disk_list_length = split(optarg, ",:;", g_disk_list, MAX_NR_DISKS);
				break;
			case 'i':
				g_interface_list_length = split(optarg, ",:;", g_interface_list, MAX_NR_INTERFACES);
				break;
			case 't':
				g_timeout = atoi(optarg) * 100;
				break;
			case 'a':
				g_auth = 1;
				break;
			case 'v':
				g_verbose = 1;
				break;
			case 'l':
				print_version();
				exit(EXIT_ARGS);
				break;
			default:
				print_help();
				exit(EXIT_ARGS);
		}
	}

	/* Print a starting message (so the user knows the args were ok) */
	lprintf(LOG_INFO, "started, listening on port %d/udp and %d/tcp\n",
		g_udp_port, g_tcp_port);

	/* Build the MIB and execute the first MIB update to get actual values */
	if (mib_build() == -1) {
		exit(EXIT_SYSCALL);
	} else if (mib_update() == -1) {
		exit(EXIT_SYSCALL);
	}
#ifdef DEBUG
	dump_mib(g_mib, g_mib_length);
#endif

	/* Open the server's UDP port and prepare it for listening */
	g_udp_sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (g_udp_sockfd == -1) {
		lprintf(LOG_ERR, "could not create UDP socket: %m\n");
		exit(EXIT_SYSCALL);
	}
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(g_udp_port);
	sockaddr.sin_addr.s_addr = INADDR_ANY;
	socklen = sizeof (sockaddr);
	if (bind(g_udp_sockfd, (struct sockaddr *)&sockaddr, socklen) == -1) {
		lprintf(LOG_ERR, "could not bind UDP socket to port %d: %m\n", g_udp_port);
		exit(EXIT_SYSCALL);
	}

	/* Open the server's TCP port and prepare it for listening */
	g_tcp_sockfd = socket(PF_INET, SOCK_STREAM, 0);
	if (g_tcp_sockfd == -1) {
		lprintf(LOG_ERR, "could not create TCP socket: %m\n");
		exit(EXIT_SYSCALL);
	}
	i = 1;
	if (setsockopt(g_tcp_sockfd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof (i)) == -1) {
		lprintf(LOG_WARNING, "could not set SO_REUSEADDR on TCP socket: %m\n");
		exit(EXIT_SYSCALL);
	}
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(g_tcp_port);
	sockaddr.sin_addr.s_addr = INADDR_ANY;
	socklen = sizeof (sockaddr);
	if (bind(g_tcp_sockfd, (struct sockaddr *)&sockaddr, socklen) == -1) {
		lprintf(LOG_ERR, "could not bind TCP socket to port %d: %m\n", g_tcp_port);
		exit(EXIT_SYSCALL);
	}
	if (listen(g_tcp_sockfd, 128) == -1) {
		lprintf(LOG_ERR, "could not prepare TCP socket for listening: %m\n");
		exit(EXIT_SYSCALL);
	}

	/* Handle incoming connect requests and incoming data */
	while (!g_quit) {
		/* Sleep until we get data or a connection request */
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_SET(g_udp_sockfd, &rfds);
		FD_SET(g_tcp_sockfd, &rfds);
		nfds = (g_udp_sockfd > g_tcp_sockfd) ? g_udp_sockfd : g_tcp_sockfd;
		for (i = 0; i < g_tcp_client_list_length; i++) {
			if (g_tcp_client_list[i]->outgoing) {
				FD_SET(g_tcp_client_list[i]->sockfd, &wfds);
			} else {
				FD_SET(g_tcp_client_list[i]->sockfd, &rfds);
			}
			if (nfds < g_tcp_client_list[i]->sockfd) {
				nfds = g_tcp_client_list[i]->sockfd;
			}
		}
		if (select(nfds + 1, &rfds, &wfds, NULL, NULL) == -1) {
			if (g_quit) {
				break;
			}
			lprintf(LOG_ERR, "could not select from sockets: %m\n");
			exit(EXIT_SYSCALL);
		}
		/* Handle UDP packets, TCP packets and TCP connection connects */
		if (FD_ISSET(g_udp_sockfd, &rfds)) {
			handle_udp_client();
		}
		if (FD_ISSET(g_tcp_sockfd, &rfds)) {
			handle_tcp_connect();
		}
		for (i = 0; i < g_tcp_client_list_length; i++) {
			if (g_tcp_client_list[i]->outgoing) {
				if (FD_ISSET(g_tcp_client_list[i]->sockfd, &wfds)) {
					handle_tcp_client_write(g_tcp_client_list[i]);
				}
			} else {
				if (FD_ISSET(g_tcp_client_list[i]->sockfd, &rfds)) {
					handle_tcp_client_read(g_tcp_client_list[i]);
				}
			}
		}
		/* If there was a TCP disconnect, remove the client from the list */
		for (i = 0; i < g_tcp_client_list_length; i++) {
			if (g_tcp_client_list[i]->sockfd == -1) {
				g_tcp_client_list_length--;
				if (i < g_tcp_client_list_length) {
					free(g_tcp_client_list[i]);
					memmove(&g_tcp_client_list[i], &g_tcp_client_list[i + 1],
						(g_tcp_client_list_length - i) * sizeof (g_tcp_client_list[i]));
				}
			}
		}
	}

	/* We were killed, print a message and exit */
	lprintf(LOG_INFO, "stopped\n");

	return EXIT_OK;
}



/* vim: ts=4 sts=4 sw=4 nowrap
 */
