/* Main program
 *
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/if.h>
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
#include <pwd.h>
#include <grp.h>

#include "mini_snmpd.h"

#ifdef NDM

#include <ndm/sys.h>

static void ndm_core_close_()
{
	ndm_atexit_core_close_(NULL);
}

void ndm_atexit_core_close_(struct ndm_core_t* core)
{
	static struct ndm_core_t* core_ = NULL;

	if (core != NULL) {
		assert( core_ == NULL );
		core_ = core;
		atexit(ndm_core_close_);
	} else {
		ndm_core_close(&core_);
	}
}

#define NDM_USER_ "nobody"

#endif

static void print_help(void)
{
	printf("Mini snmpd v" VERSION " -- Minimal SNMP daemon for embedded UNIX systems\n"
	       "\n"
	       "Usage: mini_snmpd [options]\n"
	       "\n"
#ifdef CONFIG_ENABLE_IPV6
	       "  -4, --use-ipv4         Use IPv4, default\n"
	       "  -6, --use-ipv6         Use IPv6\n"
#endif
	       "  -p, --udp-port PORT    UDP port to bind to, default: 161\n"
	       "  -P, --tcp-port PORT    TCP port to bind to, default: 161\n"
	       "  -c, --community STR    Community string, default: public\n"
	       "  -D, --description STR  System description, default: none\n"
	       "  -V, --vendor OID       System vendor, default: none\n"
	       "  -L, --location STR     System location, default: none\n"
	       "  -C, --contact STR      System contact, default: none\n"
#ifndef NDM
	       "  -d, --disks PATH       Disks to monitor, default: /\n"
	       "  -i, --interfaces IFACE Network interfaces to monitor, default: lo\n"
#endif
	       "  -I, --listen IFACE     Network interface to listen, default: all\n"
	       "  -t, --timeout SEC      Timeout for MIB updates, default: 1 second\n"
	       "  -a, --auth             Enable authentication, i.e. SNMP version 2c\n"
	       "  -n, --foreground       Run in foreground, do not detach from controlling terminal\n"
	       "  -s, --syslog           Use syslog for logging, even if running in the foreground\n"
	       "  -v, --verbose          Verbose messages\n"
	       "  -h, --help             This help text\n"
	       "\n");
}

static void handle_signal(int UNUSED(signo))
{
	g_quit = 1;
}

struct in6_pktinfo_ {
	struct in6_addr	ipi6_addr;
	int		ipi6_ifindex;
};

static void handle_udp_client(const int af)
{
	const int sockfd = (af == AF_INET ? g_udp_sockfd4 : g_udp_sockfd6);
	const char *req_msg = "Failed UDP request from";
	const char *snd_msg = "Failed UDP response to";
	struct sockaddr_in sockaddr4;
	struct sockaddr_in6 sockaddr6;
	my_socklen_t socklen = (af == AF_INET ? sizeof(sockaddr4) : sizeof(sockaddr6));
	ssize_t rv;
	char straddr[my_inet_addrstrlen] = { 0 };
	char cmbuf[
			CMSG_SPACE(sizeof(struct in_pktinfo)) +
			CMSG_SPACE(sizeof(struct sockaddr_in)) +
			CMSG_SPACE(sizeof(struct in6_pktinfo_)) +
			CMSG_SPACE(sizeof(struct sockaddr_in6))];
	struct iovec iov[1];
	struct msghdr mh =
	{
		.msg_name = (af == AF_INET ? (struct sockaddr *)&sockaddr4 : (struct sockaddr *)&sockaddr6),
		.msg_namelen = socklen,
		.msg_iov = iov,
		.msg_iovlen = 1,
		.msg_control = cmbuf,
		.msg_controllen = sizeof(cmbuf)
	};

	if (af == AF_INET) {
		memset(&sockaddr4, 0, sizeof(sockaddr4));
		memset(&g_udp_client.local_addr.sa, 0, sizeof(g_udp_client.local_addr.sa));
	} else {
		memset(&sockaddr6, 0, sizeof(sockaddr6));
		memset(&g_udp_client.local_addr.sa6, 0, sizeof(g_udp_client.local_addr.sa6));
	}

	memset(cmbuf, 0, sizeof(cmbuf));
	g_udp_client.local_port = 0;

	iov[0].iov_base = g_udp_client.packet;
	iov[0].iov_len = sizeof(g_udp_client.packet);

	/* Read the whole UDP packet from the socket at once */
    rv = recvmsg(sockfd, &mh, MSG_DONTWAIT);

	if (rv == -1) {
		lprintf(LOG_WARNING, "Failed receiving UDP request on port %d: %m\n", g_udp_port);
		return;
	}

	for ( struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh)
		; cmsg != NULL
		; cmsg = CMSG_NXTHDR(&mh, cmsg)) {

		if (cmsg->cmsg_level == IPPROTO_IP) {
			if (cmsg->cmsg_type == IP_PKTINFO) {
				struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);

				g_udp_client.local_addr.sa = pi->ipi_addr;
			} else
			if (cmsg->cmsg_type == IP_ORIGDSTADDR) {
				struct sockaddr_in *sin = (struct sockaddr_in *)CMSG_DATA(cmsg);

				g_udp_client.local_port = sin->sin_port;
			}
		} else
		if (cmsg->cmsg_level == IPPROTO_IPV6) {
			if (cmsg->cmsg_type == IPV6_PKTINFO) {
				struct in6_pktinfo_ *pi = (struct in6_pktinfo_ *)CMSG_DATA(cmsg);

				g_udp_client.local_addr.sa6 = pi->ipi6_addr;
			} else
			if (cmsg->cmsg_type == IPV6_ORIGDSTADDR) {
				struct sockaddr_in6 *sin6 =
					(struct sockaddr_in6 *)CMSG_DATA(cmsg);

				g_udp_client.local_port = sin6->sin6_port;
			}
		}
	}

	g_udp_client.timestamp = time(NULL);

	if (af == AF_INET) {
		g_udp_client.sockfd = sockfd;
		g_udp_client.addr.sa = sockaddr4.sin_addr;
		g_udp_client.port = sockaddr4.sin_port;
	} else {
		g_udp_client.sockfd = sockfd;
		g_udp_client.addr.sa6 = sockaddr6.sin6_addr;
		g_udp_client.port = sockaddr6.sin6_port;
	}

	g_udp_client.size = rv;
	g_udp_client.outgoing = 0;
#ifdef DEBUG
	dump_packet(&g_udp_client);
#endif

	/* Call the protocol handler which will prepare the response packet */
	inet_ntop(af, (af == AF_INET ? (void *)&sockaddr4.sin_addr : (void*)&sockaddr6.sin6_addr),
		straddr, sizeof(straddr));

	if (snmp(&g_udp_client) == -1) {
		lprintf(LOG_WARNING, "%s %s:%d: %m\n", req_msg, straddr, g_udp_client.port);
		return;
	}
	if (g_udp_client.size == 0) {
		lprintf(LOG_WARNING, "%s %s:%d: ignored\n", req_msg, straddr, g_udp_client.port);
		return;
	}
	g_udp_client.outgoing = 1;

	/* Send the whole UDP packet to the socket at once */

	if (af == AF_INET && g_udp_client.local_addr.sa.s_addr != 0) {
		char cmsbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
		struct iovec iovs[1];
		struct msghdr mhs;
		struct cmsghdr *cmsg;
		struct in_pktinfo *pktinfo;

		memset(cmsbuf, 0, CMSG_SPACE(sizeof(struct in_pktinfo)));
		iovs[0].iov_base = g_udp_client.packet;
		iovs[0].iov_len = g_udp_client.size;
		memset(&mhs, 0, sizeof(mhs));

		mhs.msg_name = (struct sockaddr*) &sockaddr4;
		mhs.msg_namelen = socklen;
		mhs.msg_control = cmsbuf;
		mhs.msg_controllen = sizeof(cmsbuf);
		mhs.msg_flags = 0;
		mhs.msg_iov = iovs;
		mhs.msg_iovlen = 1;

		cmsg = CMSG_FIRSTHDR(&mhs);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		pktinfo = (struct in_pktinfo*) CMSG_DATA(cmsg);

		pktinfo->ipi_ifindex = 0;
		pktinfo->ipi_spec_dst = g_udp_client.local_addr.sa;

		rv = sendmsg(g_udp_sockfd4, &mhs, MSG_DONTWAIT);
	} else
	if (af == AF_INET6 &&
		(g_udp_client.local_addr.sa6.s6_addr32[0] != 0 ||
		 g_udp_client.local_addr.sa6.s6_addr32[1] != 0 ||
		 g_udp_client.local_addr.sa6.s6_addr32[2] != 0 ||
		 g_udp_client.local_addr.sa6.s6_addr32[3] != 0)) {

		char cmsbuf[CMSG_SPACE(sizeof(struct in6_pktinfo_))];
		struct iovec iovs[1];
		struct msghdr mhs;
		struct cmsghdr *cmsg;
		struct in6_pktinfo_ *pktinfo;

		memset(cmsbuf, 0, CMSG_SPACE(sizeof(struct in6_pktinfo_)));
		iovs[0].iov_base = g_udp_client.packet;
		iovs[0].iov_len = g_udp_client.size;
		memset(&mhs, 0, sizeof(mhs));

		mhs.msg_name = (struct sockaddr*) &sockaddr6;
		mhs.msg_namelen = socklen;
		mhs.msg_control = cmsbuf;
		mhs.msg_controllen = sizeof(cmsbuf);
		mhs.msg_flags = 0;
		mhs.msg_iov = iovs;
		mhs.msg_iovlen = 1;

		cmsg = CMSG_FIRSTHDR(&mhs);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo_));
		pktinfo = (struct in6_pktinfo_*) CMSG_DATA(cmsg);

		pktinfo->ipi6_ifindex = 0;
		pktinfo->ipi6_addr = g_udp_client.local_addr.sa6;

		rv = sendmsg(g_udp_sockfd6, &mhs, MSG_DONTWAIT);
	} else
	{
		rv = sendto(sockfd, g_udp_client.packet, g_udp_client.size,
			MSG_DONTWAIT,
			(af == AF_INET ? (struct sockaddr *)&sockaddr4 : (struct sockaddr *)&sockaddr6),
			socklen);
	}

	inet_ntop(af, (af == AF_INET ? (void *)&sockaddr4.sin_addr : (void*)&sockaddr6.sin6_addr), straddr, sizeof(straddr));
	if (rv == -1)
		lprintf(LOG_WARNING, "%s %s:%d: %m\n", snd_msg, straddr, g_udp_client.port);
	else if ((size_t)rv != g_udp_client.size)
		lprintf(LOG_WARNING, "%s %s:%d: only %zd of %zu bytes sent\n", snd_msg, straddr, g_udp_client.port, rv, g_udp_client.size);

#ifdef DEBUG
	dump_packet(&g_udp_client);
#endif
}

static void handle_tcp_connect(const int af)
{
	const char *msg = "Could not accept TCP connection";
	struct sockaddr_in tmp_sockaddr4;
	struct sockaddr_in6 tmp_sockaddr6;
	struct sockaddr_in sockaddr4;
	struct sockaddr_in6 sockaddr6;
	my_socklen_t socklen = (af == AF_INET ? sizeof(sockaddr4) : sizeof(sockaddr6));
	client_t *client;
	char straddr[my_inet_addrstrlen] = "";
	int rv;
	const int sock = (af == AF_INET ? g_tcp_sockfd4 : g_tcp_sockfd6);

	if (af == AF_INET) {
		memset(&tmp_sockaddr4, 0, sizeof(tmp_sockaddr4));
		memset(&sockaddr4, 0, sizeof(sockaddr4));
	} else {
		memset(&tmp_sockaddr6, 0, sizeof(tmp_sockaddr6));
		memset(&sockaddr6, 0, sizeof(sockaddr6));
	}

	/* Accept the new connection (remember the client's IP address and port) */
	rv = accept(sock, (af == AF_INET ? (struct sockaddr *)&sockaddr4 : (struct sockaddr *)&sockaddr6),
		&socklen);
	if (rv == -1) {
		lprintf(LOG_ERR, "%s: %m\n", msg);
		return;
	}
	if (rv >= FD_SETSIZE) {
		lprintf(LOG_ERR, "%s: FD set overflow\n", msg);
		close(rv);
		return;
	}

	/* Create a new client control structure or overwrite the oldest one */
	if (g_tcp_client_list_length >= MAX_NR_CLIENTS) {
		client = find_oldest_client();
		if (!client) {
			lprintf(LOG_ERR, "%s: internal error", msg);
			exit(EXIT_SYSCALL);
		}

		if (af == AF_INET) {
			tmp_sockaddr4.sin_addr = client->addr.sa;
			tmp_sockaddr4.sin_port = client->port;
			inet_ntop(AF_INET, &tmp_sockaddr4.sin_addr, straddr, sizeof(straddr));
		} else {
			tmp_sockaddr6.sin6_addr = client->addr.sa6;
			tmp_sockaddr6.sin6_port = client->port;
			inet_ntop(AF_INET6, &tmp_sockaddr6.sin6_addr, straddr, sizeof(straddr));
		}

		lprintf(LOG_WARNING, "Maximum number of %d clients reached, kicking out %s:%d\n",
			MAX_NR_CLIENTS, straddr, client->port);
		close(client->sockfd);
	} else {
		client = allocate(sizeof(client_t));
		if (!client) {
			lprintf(LOG_ERR, "%s: %m", msg);
			exit(EXIT_SYSCALL);
		}
		g_tcp_client_list[g_tcp_client_list_length++] = client;
	}

	/* Now fill out the client control structure values */
	inet_ntop(af, (af == AF_INET ? (void *)&sockaddr4.sin_addr : (void *)&sockaddr6.sin6_addr),
		straddr, sizeof(straddr));
	lprintf(LOG_DEBUG, "Connected TCP client %s:%d\n",
		straddr, (af == AF_INET ? sockaddr4.sin_port : sockaddr6.sin6_port));
	client->timestamp = time(NULL);
	client->sockfd = rv;
	client->af = af;

	if (af == AF_INET) {
		client->addr.sa = sockaddr4.sin_addr;
		client->port = sockaddr4.sin_port;
	} else {
		client->addr.sa6 = sockaddr6.sin6_addr;
		client->port = sockaddr6.sin6_port;
	}

	client->size = 0;
	client->outgoing = 0;
}

static void handle_tcp_client_write(client_t *client)
{
	const char *msg = "Failed TCP response to";
	ssize_t rv;
	char straddr[my_inet_addrstrlen] = "";
	struct sockaddr_in sockaddr4;
	struct sockaddr_in6 sockaddr6;

	/* Send the packet atomically and close socket if that did not work */
	if (client->af == AF_INET) {
		sockaddr4.sin_addr = client->addr.sa;
		sockaddr4.sin_port = client->port;
	} else {
		sockaddr6.sin6_addr = client->addr.sa6;
		sockaddr6.sin6_port = client->port;
	}

	rv = send(client->sockfd, client->packet, client->size, 0);
	inet_ntop(client->af, (client->af == AF_INET ? (void *)&sockaddr4.sin_addr : (void *)&sockaddr6.sin6_addr),
		straddr, sizeof(straddr));
	if (rv == -1) {
		lprintf(LOG_WARNING, "%s %s:%d: %m\n", msg, straddr, client->port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	if ((size_t)rv != client->size) {
		lprintf(LOG_WARNING, "%s %s:%d: only %zd of %zu bytes written\n",
			msg, straddr, client->port, rv, client->size);
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
	const char *req_msg = "Failed TCP request from";
	int rv;
	char straddr[my_inet_addrstrlen] = "";
	struct sockaddr_in sockaddr4;
	struct sockaddr_in6 sockaddr6;

	/* Read from the socket what arrived and put it into the buffer */
	if (client->af == AF_INET) {
		sockaddr4.sin_addr = client->addr.sa;
		sockaddr4.sin_port = client->port;
	} else {
		sockaddr6.sin6_addr = client->addr.sa6;
		sockaddr6.sin6_port = client->port;
	}

	rv = read(client->sockfd, client->packet + client->size, sizeof(client->packet) - client->size);
	inet_ntop(client->af, (client->af == AF_INET ? (void *)&sockaddr4.sin_addr : (void *)&sockaddr6.sin6_addr), straddr, sizeof(straddr));
	if (rv == -1) {
		lprintf(LOG_WARNING, "%s %s:%d: %m\n", req_msg, straddr, client->port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	if (rv == 0) {
		lprintf(LOG_DEBUG, "TCP client %s:%d disconnected\n",
			straddr, client->port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	client->timestamp = time(NULL);
	client->size += rv;

	/* Check whether the packet was fully received and handle packet if yes */
	rv = snmp_packet_complete(client);
	if (rv == -1) {
		lprintf(LOG_WARNING, "%s %s:%d: %m\n", req_msg, straddr, client->port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	if (rv == 0) {
		return;
	}
	client->outgoing = 0;

#ifdef DEBUG
	dump_packet(client);
#endif

	/* Call the protocol handler which will prepare the response packet */
	if (snmp(client) == -1) {
		lprintf(LOG_WARNING, "%s %s:%d: %m\n", req_msg, straddr, client->port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	if (client->size == 0) {
		lprintf(LOG_WARNING, "%s %s:%d: ignored\n", req_msg, straddr, client->port);
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}

	client->outgoing = 1;
}


int main(int argc, char *argv[])
{
	static const char short_options[] = "p:P:c:D:V:L:C:d:i:t:T:S:G:M:U:Q:ansvh"
#ifndef __FreeBSD__
		"I:"
#endif
#ifdef CONFIG_ENABLE_IPV6
		"46"
#endif
		;
	static const struct option long_options[] = {
#ifdef CONFIG_ENABLE_IPV6
		{ "use-ipv4", 0, 0, '4' },
		{ "use-ipv6", 0, 0, '6' },
#endif
		{ "udp-port", 1, 0, 'p' },
		{ "tcp-port", 1, 0, 'P' },
		{ "community", 1, 0, 'c' },
		{ "description", 1, 0, 'D' },
		{ "vendor", 1, 0, 'V' },
		{ "location", 1, 0, 'L' },
		{ "contact", 1, 0, 'C' },
#ifndef NDM
		{ "disks", 1, 0, 'd' },
#endif
#ifndef NDM
		{ "interfaces", 1, 0, 'i' },
#endif
#ifndef __FreeBSD__
		{ "listen", 1, 0, 'I' },
#endif
		{ "timeout", 1, 0, 't' },
		{ "traps", 1, 0, 'T' },
		{ "auth", 0, 0, 'a' },
		{ "foreground", 0, 0, 'n' },
		{ "verbose", 0, 0, 'v' },
		{ "syslog", 0, 0, 's' },
		{ "help", 0, 0, 'h' },
		{ NULL, 0, 0, 0 }
	};
	int ticks, c, option_index = 1;
	size_t i;
	fd_set rfds, wfds;
	struct sigaction sig;
	struct ifreq ifreq;
	struct timeval tv_last;
	struct timeval tv_now;
	struct timeval tv_sleep;
	my_socklen_t socklen;
	union {
		struct sockaddr_in sa;
#ifdef CONFIG_ENABLE_IPV6
		struct sockaddr_in6 sa6;
#endif
	} sockaddr;
	int opt = 1;
	bool authenticated = false;

	/* Prevent TERM and HUP signals from interrupting system calls */
	sig.sa_handler = handle_signal;
	sigemptyset (&sig.sa_mask);
	sig.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &sig, NULL);
	sigaction(SIGHUP, &sig, NULL);

	/* Parse commandline options */
	while (1) {
		c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
#ifdef CONFIG_ENABLE_IPV6
			case '4':
				g_family = AF_INET;
				break;

			case '6':
				g_family = AF_INET6;
				break;
#endif
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

			case 'S':
				g_serial = strdup(optarg);
				break;

			case 'G':
				g_mfg = strdup(optarg);
				break;

			case 'M':
				g_model = strdup(optarg);
				break;

			case 'U':
				g_cid = strdup(optarg);
				break;

			case 'Q':
				g_ifmap = strdup(optarg);
				break;

#ifndef __FreeBSD__
			case 'I':
				g_bind_to_device = strdup(optarg);
				break;
#endif
#ifndef NDM
			case 'd':
				g_disk_list_length = split(optarg, ",:;", g_disk_list, MAX_NR_DISKS);
				break;
#endif
#ifndef NDM
			case 'i':
				g_interface_list_length = split(optarg, ",;", g_interface_list, MAX_NR_INTERFACES);
				break;
#endif

			case 't':
				g_timeout = atoi(optarg) * 100;
				break;

			case 'a':
				g_auth = 1;
				break;

			case 'n':
				g_daemon = 0;
				break;

			case 's':
				g_syslog = 1;
				break;

			case 'v':
				g_verbose = 1;
				break;

			default:
				print_help();
				exit(EXIT_ARGS);
		}
	}

#ifdef NDM
	if ((g_ndmcore = ndm_core_open(NDM_AGENT_DEFAULT_,
			NDM_CACHE_TTL_MS_, NDM_CORE_DEFAULT_CACHE_MAX_SIZE)) == NULL)
	{
		lprintf(LOG_ERR, "ndm core connection failed: %s", strerror(errno));

		exit(EXIT_SYSCALL);
	} else
	if (!ndm_core_authenticate_local_service(
			g_ndmcore, "snmp", true, &authenticated) ||
		!authenticated)
	{
		lprintf(LOG_ERR, "ndm core authentication failed: %s", strerror(errno));

		ndm_core_close(&g_ndmcore);

		exit(EXIT_SYSCALL);
	} else
	{
		ndm_atexit_core_close_(g_ndmcore);
	}
#endif

	if (g_daemon) {
		lprintf(LOG_DEBUG, "Daemonizing ...");
		if (-1 == daemon(0, 0)) {
			lprintf(LOG_ERR, "Failed daemonizing: %m");
			return 1;
		}
	}

	openlog(__progname, LOG_CONS, LOG_DAEMON);

	/* Store the starting time since we need it for MIB updates */
	if (gettimeofday(&tv_last, NULL) == -1) {
		memset(&tv_last, 0, sizeof(tv_last));
		memset(&tv_sleep, 0, sizeof(tv_sleep));
	} else {
		tv_sleep.tv_sec = g_timeout / 100;
		tv_sleep.tv_usec = (g_timeout % 100) * 10000;
	}

	/* Build the MIB and execute the first MIB update to get actual values */
	if (mib_build() == -1)
		exit(EXIT_SYSCALL);
	if (mib_update(1) == -1)
		exit(EXIT_SYSCALL);

#ifdef DEBUG
	dump_mib(g_mib, g_mib_length);
#endif

	/* Open the server's UDP port and prepare it for listening */
	g_udp_sockfd4 = socket(PF_INET, SOCK_DGRAM, 0);
	if (g_udp_sockfd4 == -1) {
		lprintf(LOG_ERR, "could not create UDP4 socket: %s\n", ndm_sys_strerror(errno));
		exit(EXIT_SYSCALL);
	}

	if (g_family == AF_INET6) {
		int opt_v6 = 0;
		size_t len = sizeof(opt_v6);

		g_udp_sockfd6 = socket(PF_INET6, SOCK_DGRAM, 0);
		if (g_udp_sockfd6 == -1) {
			lprintf(LOG_ERR, "could not create UDP6 socket: %s\n", ndm_sys_strerror(errno));
			exit(EXIT_SYSCALL);
		}

		if (getsockopt(g_udp_sockfd6, IPPROTO_IPV6, IPV6_V6ONLY, &opt_v6, (socklen_t *)&len) == 0) {
			if (!opt_v6 && setsockopt(g_udp_sockfd6, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0) {
				lprintf(LOG_ERR, "failed to set \"IPv6 only\" socket option: %s\n", ndm_sys_strerror(errno));
				exit(EXIT_SYSCALL);
			}
		}
	}

	memset(&sockaddr, 0, sizeof(sockaddr));

	sockaddr.sa.sin_family = AF_INET;
	sockaddr.sa.sin_port = htons(g_udp_port);
	sockaddr.sa.sin_addr = inaddr_any;
	socklen = sizeof(sockaddr.sa);

	if (setsockopt(g_udp_sockfd4, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt)) != 0) {
		lprintf(LOG_ERR, "failed to enable ip_pktinfo4 on a socket: %s", ndm_sys_strerror(errno));
		exit(EXIT_SYSCALL);
	}

	if (setsockopt(g_udp_sockfd4, IPPROTO_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt)) != 0) {
		lprintf(LOG_ERR, "failed to enable ip_pktinfo4a on a socket: %s", ndm_sys_strerror(errno));
		exit(EXIT_SYSCALL);
	}

	if (bind(g_udp_sockfd4, (struct sockaddr *)&sockaddr, socklen) == -1) {
		lprintf(LOG_ERR, "could not bind UDP socket to port %d: %m\n", g_udp_port);
		exit(EXIT_SYSCALL);
	}

	if (g_family == AF_INET6) {
		sockaddr.sa6.sin6_family = AF_INET6;
		sockaddr.sa6.sin6_port = htons(g_udp_port);
		sockaddr.sa6.sin6_addr = in6addr_any;
		socklen = sizeof(sockaddr.sa6);

		if (setsockopt(g_udp_sockfd6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt)) != 0) {
			lprintf(LOG_ERR, "failed to enable ip_pktinfo6 on a socket: %s", ndm_sys_strerror(errno));
			exit(EXIT_SYSCALL);
		}

		if (setsockopt(g_udp_sockfd6, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &opt, sizeof(opt)) != 0) {
			lprintf(LOG_ERR, "failed to enable ip_pktinfo6a on a socket: %s", ndm_sys_strerror(errno));
			exit(EXIT_SYSCALL);
		}

		if (bind(g_udp_sockfd6, (struct sockaddr *)&sockaddr, socklen) == -1) {
			lprintf(LOG_ERR, "could not bind UDP socket to port %d: %m\n", g_udp_port);
			exit(EXIT_SYSCALL);
		}
	}

#ifndef __FreeBSD__
	if (g_bind_to_device) {
		snprintf(ifreq.ifr_ifrn.ifrn_name, sizeof(ifreq.ifr_ifrn.ifrn_name), "%s", g_bind_to_device);
		if (setsockopt(g_udp_sockfd4, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifreq, sizeof(ifreq)) == -1) {
			lprintf(LOG_WARNING, "could not bind UDP4 socket to device %s: %m\n", g_bind_to_device);
			exit(EXIT_SYSCALL);
		}

		if (g_family == AF_INET6 && setsockopt(g_udp_sockfd6, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifreq, sizeof(ifreq)) == -1) {
			lprintf(LOG_WARNING, "could not bind UDP6 socket to device %s: %m\n", g_bind_to_device);
			exit(EXIT_SYSCALL);
		}
	}
#endif

	/* Open the server's TCP port and prepare it for listening */
	g_tcp_sockfd4 = socket(PF_INET, SOCK_STREAM, 0);
	if (g_tcp_sockfd4 == -1) {
		lprintf(LOG_ERR, "could not create TCP4 socket: %m\n");
		exit(EXIT_SYSCALL);
	}

	if (g_family == AF_INET6) {
		int opt_v6 = 0;
		size_t len = sizeof(opt_v6);

		g_tcp_sockfd6 = socket(PF_INET6, SOCK_STREAM, 0);
		if (g_tcp_sockfd6 == -1) {
			lprintf(LOG_ERR, "could not create TCP6 socket: %m\n");
			exit(EXIT_SYSCALL);
		}

		if (getsockopt(g_tcp_sockfd6, IPPROTO_IPV6, IPV6_V6ONLY, &opt_v6, (socklen_t *)&len) == 0) {
			if (!opt_v6 && setsockopt(g_tcp_sockfd6, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0) {
				lprintf(LOG_ERR, "failed to set \"IPv6 only\" socket option: %s\n", ndm_sys_strerror(errno));
				exit(EXIT_SYSCALL);
			}
		}

		c = 1;
		if (setsockopt(g_tcp_sockfd6, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c)) == -1) {
			lprintf(LOG_WARNING, "could not set SO_REUSEADDR on TCP socket: %m\n");
			exit(EXIT_SYSCALL);
		}
	}

#ifndef __FreeBSD__
	if (g_bind_to_device) {
		snprintf(ifreq.ifr_ifrn.ifrn_name, sizeof(ifreq.ifr_ifrn.ifrn_name), "%s", g_bind_to_device);
		if (setsockopt(g_tcp_sockfd4, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifreq, sizeof(ifreq)) == -1) {
			lprintf(LOG_WARNING, "could not bind TCP socket to device %s: %m\n", g_bind_to_device);
			exit(EXIT_SYSCALL);
		}

		if (g_family == AF_INET6 && setsockopt(g_tcp_sockfd6, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifreq, sizeof(ifreq)) == -1) {
			lprintf(LOG_WARNING, "could not bind TCP socket to device %s: %m\n", g_bind_to_device);
			exit(EXIT_SYSCALL);
		}
	}
#endif

	c = 1;
	if (setsockopt(g_tcp_sockfd4, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c)) == -1) {
		lprintf(LOG_WARNING, "could not set SO_REUSEADDR on TCP socket: %m\n");
		exit(EXIT_SYSCALL);
	}

	memset(&sockaddr, 0, sizeof(sockaddr));

	sockaddr.sa.sin_family = AF_INET;
	sockaddr.sa.sin_port = htons(g_udp_port);
	sockaddr.sa.sin_addr = inaddr_any;
	socklen = sizeof(sockaddr.sa);

	if (bind(g_tcp_sockfd4, (struct sockaddr *)&sockaddr, socklen) == -1) {
		lprintf(LOG_ERR, "could not bind TCP socket to port %d: %m\n", g_tcp_port);
		exit(EXIT_SYSCALL);
	}

	if (listen(g_tcp_sockfd4, 5) == -1) {
		lprintf(LOG_ERR, "could not prepare TCP socket for listening: %m\n");
		exit(EXIT_SYSCALL);
	}

	if (g_family == AF_INET6) {
		sockaddr.sa6.sin6_family = AF_INET6;
		sockaddr.sa6.sin6_port = htons(g_udp_port);
		sockaddr.sa6.sin6_addr = in6addr_any;
		socklen = sizeof(sockaddr.sa6);

		if (bind(g_tcp_sockfd6, (struct sockaddr *)&sockaddr, socklen) == -1) {
			lprintf(LOG_ERR, "could not bind TCP socket to port %d: %m\n", g_tcp_port);
			exit(EXIT_SYSCALL);
		}

		if (listen(g_tcp_sockfd6, 5) == -1) {
			lprintf(LOG_ERR, "could not prepare TCP socket for listening: %m\n");
			exit(EXIT_SYSCALL);
		}
	}

	/* Print a starting message (so the user knows the args were ok) */
	if (g_bind_to_device) {
		lprintf(LOG_INFO, "Listening on port %d/udp and %d/tcp on interface %s\n",
			g_udp_port, g_tcp_port, g_bind_to_device);
	} else {
		lprintf(LOG_INFO, "Listening on port %d/udp and %d/tcp\n", g_udp_port, g_tcp_port);
	}

	if (geteuid() == 0) {
		struct group *grp;
		struct passwd *pwd;

		errno = 0;

		pwd = getpwnam(NDM_USER_);

		if (pwd == NULL) {
			lprintf(LOG_ERR, "Unable to get UID for user \"%s\": %s",
				NDM_USER_, strerror(errno));
			exit(EXIT_SYSCALL);
		}

		errno = 0;

		grp = getgrnam(NDM_USER_);

		if (grp == NULL) {
			lprintf(LOG_ERR, "Unable to get GID for group \"%s\": %s",
				NDM_USER_, strerror(errno));
			exit(EXIT_SYSCALL);
		}

		if (setgid(grp->gr_gid) == -1) {
			lprintf(LOG_ERR, "Unable to set new group \"%s\": %s",
				NDM_USER_, strerror(errno));
			exit(EXIT_SYSCALL);
		}

		if (setuid(pwd->pw_uid) == -1) {
			lprintf(LOG_ERR, "Unable to set new user \"%s\": %s",
				NDM_USER_, strerror(errno));
			exit(EXIT_SYSCALL);
		}

		lprintf(LOG_INFO, "Successfully dropped privileges to %s:%s",
			NDM_USER_, NDM_USER_);
	}

	/* Handle incoming connect requests and incoming data */
	while (!g_quit) {
		int nfds;

		/* Sleep until we get a request or the timeout is over */
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_SET(g_udp_sockfd4, &rfds);
		FD_SET(g_tcp_sockfd4, &rfds);

		if (g_family == AF_INET6) {
			FD_SET(g_udp_sockfd6, &rfds);
			FD_SET(g_tcp_sockfd6, &rfds);
		}

		nfds = g_udp_sockfd4;

		if (g_tcp_sockfd4 > g_udp_sockfd4)
			nfds = g_tcp_sockfd4;

		if (g_family == AF_INET6) {
			if (g_udp_sockfd6 > g_tcp_sockfd4)
				nfds = g_udp_sockfd6;

			if (g_tcp_sockfd6 > g_udp_sockfd6)
				nfds = g_tcp_sockfd6;
		}

		for (i = 0; i < g_tcp_client_list_length; i++) {
			if (g_tcp_client_list[i]->outgoing)
				FD_SET(g_tcp_client_list[i]->sockfd, &wfds);
			else
				FD_SET(g_tcp_client_list[i]->sockfd, &rfds);

			if (nfds < g_tcp_client_list[i]->sockfd)
				nfds = g_tcp_client_list[i]->sockfd;
		}

		if (select(nfds + 1, &rfds, &wfds, NULL, &tv_sleep) == -1) {
			if (g_quit)
				break;

			lprintf(LOG_ERR, "could not select from sockets: %m\n");
			exit(EXIT_SYSCALL);
		}

		/* Determine whether to update the MIB and the next ticks to sleep */
		if (!g_quit) {
			ticks = ticks_since(&tv_last, &tv_now);
			if (ticks < 0 || ticks >= g_timeout) {
				lprintf(LOG_DEBUG, "updating the MIB (full)\n");
				if (mib_update(1) == -1)
					exit(EXIT_SYSCALL);

				memcpy(&tv_last, &tv_now, sizeof(tv_now));
#ifndef NDM
				tv_sleep.tv_sec = g_timeout / 100;
				tv_sleep.tv_usec = (g_timeout % 100) * 10000;
#endif
			} else {
				lprintf(LOG_DEBUG, "updating the MIB (partial)\n");
				if (mib_update(0) == -1)
					exit(EXIT_SYSCALL);

#ifndef NDM
				tv_sleep.tv_sec = (g_timeout - ticks) / 100;
				tv_sleep.tv_usec = ((g_timeout - ticks) % 100) * 10000;
#endif
			}

#ifdef NDM
			/* Update MIB tables once a NDM_IDLE_SLEEP_SEC_ without
			 * clients requests */

			tv_sleep.tv_sec = NDM_IDLE_SLEEP_SEC_;
			tv_sleep.tv_usec = 0;
#endif
		}

#ifdef DEBUG
		dump_mib(g_mib, g_mib_length);
#endif

		/* Handle UDP packets, TCP packets and TCP connection connects */
		if (FD_ISSET(g_udp_sockfd4, &rfds))
			handle_udp_client(AF_INET);

		if (g_family == AF_INET6 && FD_ISSET(g_udp_sockfd6, &rfds))
			handle_udp_client(AF_INET6);

		if (FD_ISSET(g_tcp_sockfd4, &rfds))
			handle_tcp_connect(AF_INET);

		if (g_family == AF_INET6 && FD_ISSET(g_tcp_sockfd6, &rfds))
			handle_tcp_connect(AF_INET6);

		for (i = 0; i < g_tcp_client_list_length; i++) {
			if (g_tcp_client_list[i]->outgoing) {
				if (FD_ISSET(g_tcp_client_list[i]->sockfd, &wfds))
					handle_tcp_client_write(g_tcp_client_list[i]);
			} else {
				if (FD_ISSET(g_tcp_client_list[i]->sockfd, &rfds))
					handle_tcp_client_read(g_tcp_client_list[i]);
			}
		}

		/* If there was a TCP disconnect, remove the client from the list */
		for (i = 0; i < g_tcp_client_list_length; i++) {
			if (g_tcp_client_list[i]->sockfd == -1) {
				g_tcp_client_list_length--;
				if (i < g_tcp_client_list_length) {
					size_t len = (g_tcp_client_list_length - i) * sizeof(g_tcp_client_list[i]);

					free(g_tcp_client_list[i]);
					memmove(&g_tcp_client_list[i], &g_tcp_client_list[i + 1], len);

					/*
					 * list changed, there could be more than
					 * one to remove, start from begining
					 */
					i = -1;
				}
			}
		}
	}

	for (i = 0; i < g_mib_length; ++i) {
		if (g_mib[i].data.buffer != NULL)
			free(g_mib[i].data.buffer);
	}

	for (i = 0; i < g_interface_list_length; ++i) {
		if (g_ifaces_list[i].iface != NULL)
			free(g_ifaces_list[i].iface);
		if (g_ifaces_list[i].name != NULL)
			free(g_ifaces_list[i].name);
		if (g_ifaces_list[i].descr != NULL)
			free(g_ifaces_list[i].descr);
		if (g_ifaces_list[i].mac != NULL)
			free(g_ifaces_list[i].mac);
	}

	/* We were killed, print a message and exit */
	lprintf(LOG_INFO, "stopped\n");

	return EXIT_OK;
}

/* vim: ts=4 sts=4 sw=4 nowrap
 */
