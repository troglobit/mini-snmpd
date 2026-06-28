/* Main program
 *
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 * Copyright (C) 2015-2026  Joachim Wiberg <troglobit@gmail.com>
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
#include <sys/param.h>		/* MIN()/MAX() */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#define SYSLOG_NAMES		/* Expose syslog.h:prioritynames[] */
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

#include "mini-snmpd.h"
#include "netlink.h"

/*
 * The user's -i interface spec (plain names and '+' wildcards), preserved
 * so the monitored set can be rebuilt on netlink events.  expand_interfaces()
 * (re)builds g_interface_list from this.
 */
static char  *iface_pattern[MAX_NR_INTERFACES];
static size_t iface_pattern_len;

static int usage(int rc)
{
	printf("Usage: %s [options]\n"
	       "\n"
#ifdef CONFIG_ENABLE_IPV6
	       "  -4, --use-ipv4         Use only IPv4, default: dual-stack\n"
	       "  -6, --use-ipv6         Use only IPv6, default: dual-stack\n"
#endif
	       "  -a, --auth             Enable authentication, i.e. SNMP version 2c\n"
	       "  -c, --community STR    Community string, default: public\n"
	       "  -C, --contact STR      System contact, default: none\n"
	       "  -d, --disks PATH       Disks to monitor, default: /\n"
	       "  -D, --description STR  System description, default: PRETTY_NAME, os-release(8)\n"
#ifdef HAVE_LIBCONFUSE
	       "  -f, --file FILE        Configuration file. Default: " SYSCONFDIR "/%s.conf\n"
#endif
	       "  -h, --help             This help text\n"
	       "  -i, --interfaces IFACE Network interfaces to monitor, e.g. eth+, default: all\n"
#ifdef __linux__
	       "  -I, --listen IFACE     Network interface to listen, default: all\n"
#endif
	       "  -l, --loglevel LEVEL   Set log level: none, err, info, notice*, debug\n"
	       "  -L, --location STR     System location, default: none\n"
	       "  -n, --foreground       Run in foreground, do not detach from controlling terminal\n"
	       "  -p, --udp-port PORT    UDP port to bind to, default: 161\n"
	       "  -P, --tcp-port PORT    TCP port to bind to, default: 161\n"
	       "  -s, --syslog           Use syslog for logging, even if running in the foreground\n"
	       "  -T, --trap ADDR        SNMPv2c trap sink, addr[:port], may be repeated\n"
	       "  -t, --timeout SEC      Timeout for MIB updates, default: 1 second\n"
	       "  -u, --drop-privs USER  Drop privileges after opening sockets to USER, default: no\n"
	       "  -v, --version          Show program version and exit\n"
	       "  -V, --vendor OID       System vendor, default: none\n"
	       "\n", g_prognm
#ifdef HAVE_LIBCONFUSE
	       , PACKAGE_NAME
#endif
		);

	return rc;
}

static void handle_signal(int UNUSED(signo))
{
	g_quit = 1;
}

static void handle_udp_client(int sockfd)
{
	const char *req_msg = "Failed UDP request from";
	const char *snd_msg = "Failed UDP response to";
	inet_addr_t sockaddr;
	char straddr[INET_ADDRSTR_LEN] = { 0 };
	struct iovec iov;
	struct msghdr mh;
	socklen_t socklen;
	ssize_t rv;
#ifdef __linux__
	/* Control buffer large enough for an IPv4 or IPv6 packet-info cmsg */
	union {
		char buf[CMSG_SPACE(sizeof(struct in_pktinfo))
#ifdef CONFIG_ENABLE_IPV6
			 + CMSG_SPACE(sizeof(struct in6_pktinfo))
#endif
			];
		struct cmsghdr align;
	} cmsg_in, cmsg_out;
	struct cmsghdr *cmsg;
	struct in_pktinfo pkt4;
#ifdef CONFIG_ENABLE_IPV6
	struct in6_pktinfo pkt6;
#endif
	int local_af = 0;
#endif /* __linux__ */

	memset(&sockaddr, 0, sizeof(sockaddr));

	/* Read the whole UDP packet from the socket at once */
	iov.iov_base = g_udp_client.packet;
	iov.iov_len  = sizeof(g_udp_client.packet);
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &sockaddr;
	mh.msg_namelen = sizeof(sockaddr);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;
#ifdef __linux__
	mh.msg_control    = cmsg_in.buf;
	mh.msg_controllen = sizeof(cmsg_in.buf);
#endif

	rv = recvmsg(sockfd, &mh, 0);
	if (rv == -1) {
		logit(LOG_WARNING, errno, "Failed receiving UDP request on port %d", g_udp_port);
		return;
	}
	socklen = mh.msg_namelen;

#ifdef __linux__
	/* Remember which local address the request was sent to */
	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			memcpy(&pkt4, CMSG_DATA(cmsg), sizeof(pkt4));
			local_af = AF_INET;
		}
#ifdef CONFIG_ENABLE_IPV6
		else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			memcpy(&pkt6, CMSG_DATA(cmsg), sizeof(pkt6));
			local_af = AF_INET6;
		}
#endif
	}
#endif /* __linux__ */

	g_udp_client.timestamp = time(NULL);
	g_udp_client.sockfd = sockfd;
	g_udp_client.addr = sockaddr;
	g_udp_client.size = rv;
	g_udp_client.outgoing = 0;
#ifdef DEBUG
	dump_packet(&g_udp_client);
#endif

	/* Call the protocol handler which will prepare the response packet */
	inet_ntop2(&sockaddr, straddr, sizeof(straddr));
	if (snmp(&g_udp_client) == -1) {
		logit(LOG_WARNING, errno, "%s %s:%d", req_msg, straddr, inet_port(&sockaddr));
		return;
	}
	if (g_udp_client.size == 0) {
		logit(LOG_WARNING, 0, "%s %s:%d: ignored", req_msg, straddr, inet_port(&sockaddr));
		return;
	}
	g_udp_client.outgoing = 1;

	/* Reply, from the same local address the request was sent to */
	iov.iov_base = g_udp_client.packet;
	iov.iov_len  = g_udp_client.size;
	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &sockaddr;
	mh.msg_namelen = socklen;
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

#ifdef __linux__
	if (local_af == AF_INET) {
		struct in_pktinfo *pi;

		memset(&cmsg_out, 0, sizeof(cmsg_out));
		mh.msg_control    = cmsg_out.buf;
		mh.msg_controllen = CMSG_SPACE(sizeof(*pi));
		cmsg = CMSG_FIRSTHDR(&mh);
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type  = IP_PKTINFO;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(*pi));
		pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
		pi->ipi_spec_dst = pkt4.ipi_addr;     /* reply source address */
		pi->ipi_ifindex  = pkt4.ipi_ifindex;  /* out the same interface */
	}
#ifdef CONFIG_ENABLE_IPV6
	else if (local_af == AF_INET6) {
		struct in6_pktinfo *pi;

		memset(&cmsg_out, 0, sizeof(cmsg_out));
		mh.msg_control    = cmsg_out.buf;
		mh.msg_controllen = CMSG_SPACE(sizeof(*pi));
		cmsg = CMSG_FIRSTHDR(&mh);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type  = IPV6_PKTINFO;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(*pi));
		pi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		pi->ipi6_addr    = pkt6.ipi6_addr;     /* reply source address */
		pi->ipi6_ifindex = pkt6.ipi6_ifindex;  /* out the same interface */
	}
#endif
#endif /* __linux__ */

	rv = sendmsg(sockfd, &mh, MSG_DONTWAIT);
	if (rv == -1)
		logit(LOG_WARNING, errno, "%s %s:%d", snd_msg, straddr, inet_port(&sockaddr));
	else if ((size_t)rv != g_udp_client.size)
		logit(LOG_WARNING, 0, "%s %s:%d: only %zd of %zu bytes sent", snd_msg, straddr, inet_port(&sockaddr), rv, g_udp_client.size);

#ifdef DEBUG
	dump_packet(&g_udp_client);
#endif
}

static void handle_tcp_connect(int sockfd)
{
	const char *msg = "Could not accept TCP connection";
	inet_addr_t sockaddr;
	socklen_t socklen;
	client_t *client;
	char straddr[INET_ADDRSTR_LEN] = "";
	int rv;

	memset(&sockaddr, 0, sizeof(sockaddr));

	/* Accept the new connection (remember the client's IP address and port) */
	socklen = sizeof(sockaddr);
	rv = accept(sockfd, (struct sockaddr *)&sockaddr, &socklen);
	if (rv == -1) {
		logit(LOG_ERR, errno, "%s", msg);
		return;
	}
	if (rv >= FD_SETSIZE) {
		logit(LOG_ERR, 0, "%s: FD set overflow", msg);
		close(rv);
		return;
	}

	/* Create a new client control structure or overwrite the oldest one */
	if (g_tcp_client_list_length >= MAX_NR_CLIENTS) {
		client = find_oldest_client();
		if (!client) {
			logit(LOG_ERR, 0, "%s: internal error", msg);
			exit(EXIT_SYSCALL);
		}

		inet_ntop2(&client->addr, straddr, sizeof(straddr));
		logit(LOG_WARNING, 0, "Maximum number of %d clients reached, kicking out %s:%d",
		      MAX_NR_CLIENTS, straddr, inet_port(&client->addr));
		close(client->sockfd);
	} else {
		client = allocate(sizeof(client_t));
		if (!client)
			exit(EXIT_SYSCALL);

		g_tcp_client_list[g_tcp_client_list_length++] = client;
	}

	/* Now fill out the client control structure values */
	inet_ntop2(&sockaddr, straddr, sizeof(straddr));
	logit(LOG_DEBUG, 0, "Connected TCP client %s:%d", straddr, inet_port(&sockaddr));
	client->timestamp = time(NULL);
	client->sockfd = rv;
	client->addr = sockaddr;
	client->size = 0;
	client->outgoing = 0;
}

static void handle_tcp_client_write(client_t *client)
{
	const char *msg = "Failed TCP response to";
	ssize_t rv;
	char straddr[INET_ADDRSTR_LEN] = "";

	/* Send the packet atomically and close socket if that did not work */
	rv = send(client->sockfd, client->packet, client->size, 0);
	inet_ntop2(&client->addr, straddr, sizeof(straddr));
	if (rv == -1) {
		logit(LOG_WARNING, errno, "%s %s:%d", msg, straddr, inet_port(&client->addr));
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	if ((size_t)rv != client->size) {
		logit(LOG_WARNING, 0, "%s %s:%d: only %zd of %zu bytes written",
		      msg, straddr, inet_port(&client->addr), rv, client->size);
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
	char straddr[INET_ADDRSTR_LEN] = "";

	/* Read from the socket what arrived and put it into the buffer */
	rv = read(client->sockfd, client->packet + client->size, sizeof(client->packet) - client->size);
	inet_ntop2(&client->addr, straddr, sizeof(straddr));
	if (rv == -1) {
		logit(LOG_WARNING, errno, "%s %s:%d", req_msg, straddr, inet_port(&client->addr));
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	if (rv == 0) {
		logit(LOG_DEBUG, 0, "TCP client %s:%d disconnected",
		      straddr, inet_port(&client->addr));
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	client->timestamp = time(NULL);
	client->size += rv;

	/* Check whether the packet was fully received and handle packet if yes */
	rv = snmp_packet_complete(client);
	if (rv == -1) {
		logit(LOG_WARNING, errno, "%s %s:%d", req_msg, straddr, inet_port(&client->addr));
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
		logit(LOG_WARNING, errno, "%s %s:%d", req_msg, straddr, inet_port(&client->addr));
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}
	if (client->size == 0) {
		logit(LOG_WARNING, 0, "%s %s:%d: ignored", req_msg, straddr, inet_port(&client->addr));
		close(client->sockfd);
		client->sockfd = -1;
		return;
	}

	client->outgoing = 1;
}

static int log_level(char *arg)
{
	int i, rc;

	for (i = 0; prioritynames[i].c_name; i++) {
		size_t min = MIN(strlen(prioritynames[i].c_name), strlen(arg));

		if (!strncasecmp(prioritynames[i].c_name, arg, min)) {
			g_level = prioritynames[i].c_val;
			return 0;
		}
	}

	rc = atoi(arg);
	if (-1 == rc)
		return rc;

	g_level = rc;
	return 0;
}

static char *progname(char *arg0)
{
       char *nm;

       nm = strrchr(arg0, '/');
       if (nm)
	       nm++;
       else
	       nm = arg0;

       return nm;
}

/* The loopback interface, lo on Linux, lo0 on the BSDs */
static int is_loopback(const char *name)
{
	return !strcmp(name, "lo") || !strcmp(name, "lo0");
}

/* A trailing '+' marks an interface name as a prefix wildcard */
static int ifname_is_wildcard(const char *name)
{
	size_t len = strlen(name);

	return len > 0 && name[len - 1] == '+';
}

/* Append @name to @list (owned copy) unless already present or full */
static void add_unique(char **list, size_t *len, const char *name)
{
	char *dup;
	size_t i;

	if (*len >= MAX_NR_INTERFACES)
		return;
	for (i = 0; i < *len; i++) {
		if (!strcmp(list[i], name))
			return;
	}
	dup = strdup(name);
	if (dup)
		list[(*len)++] = dup;
}

/*
 * Expand interface name wildcards in the interface list against the
 * interfaces present at start-up.  Following iptables (and smcroute), a
 * trailing '+' is a prefix match: eth+ matches eth0, eth15, ..., and a
 * lone + matches every interface.  '+' is not a shell metacharacter, so
 * patterns survive on the command line unquoted.  Plain names are kept
 * verbatim, so this only affects users who actually pass a wildcard.
 *
 * The expansion is a one-shot at start-up; interfaces created later are
 * not picked up.
 */
static void expand_interfaces(void)
{
	char *list[MAX_NR_INTERFACES];
	struct if_nameindex *ifni = NULL, *p;
	size_t len = 0, i;
	int wild = 0;

	for (i = 0; i < iface_pattern_len; i++) {
		if (ifname_is_wildcard(iface_pattern[i]))
			wild = 1;
	}

	if (wild) {
		ifni = if_nameindex();
		if (!ifni)
			logit(LOG_WARNING, errno, "Failed listing interfaces, cannot expand wildcards");
	}

	for (i = 0; i < iface_pattern_len; i++) {
		char *pat = iface_pattern[i];
		size_t prefix;

		/* A plain name is kept verbatim */
		if (!ifname_is_wildcard(pat)) {
			add_unique(list, &len, pat);
			continue;
		}

		/* Trailing '+': prefix match against the interfaces present now */
		if (!ifni)
			continue;
		prefix = strlen(pat) - 1;
		for (p = ifni; p->if_index != 0; p++) {
			if (!strncmp(pat, p->if_name, prefix))
				add_unique(list, &len, p->if_name);
		}
	}

	if (ifni)
		if_freenameindex(ifni);

	/* Keep loopback first, so it lands on ifIndex 1 like the kernel does */
	for (i = 0; i < len; i++) {
		if (is_loopback(list[i])) {
			char *lo = list[i];
			size_t k;

			for (k = i; k > 0; k--)
				list[k] = list[k - 1];
			list[0] = lo;
			break;
		}
	}

	/* Swap in the freshly expanded list, freeing the previous one */
	for (i = 0; i < g_interface_list_length; i++)
		free(g_interface_list[i]);
	for (i = 0; i < len; i++)
		g_interface_list[i] = list[i];
	g_interface_list_length = len;

	logit(LOG_DEBUG, 0, "Monitoring %zu interface(s)", len);
}

/*
 * Re-expand the interface list and rebuild the MIB from scratch, e.g. when
 * netlink reports an interface or address change.  Picks up interfaces
 * created since start-up and drops ones that went away.
 */
static void rebuild_mib(void)
{
	expand_interfaces();
	mib_reset();
	if (mib_build() == -1 || mib_update(1) == -1)
		exit(EXIT_SYSCALL);
}

/*
 * Open and bind a listening socket of @family (AF_INET/AF_INET6) for the
 * given socket @type on @port.  Returns the descriptor, or -1 on error.
 */
static int open_socket(int family, int type, int port)
{
	const char *fam = family == AF_INET ? "IPv4" : "IPv6";
	const char *proto = type == SOCK_DGRAM ? "UDP" : "TCP";
	inet_addr_t addr;
	int sd, val = 1;

	sd = socket(family, type, 0);
	if (sd == -1) {
		logit(LOG_WARNING, errno, "could not create %s %s socket", fam, proto);
		return -1;
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == -1)
		logit(LOG_WARNING, errno, "could not set SO_REUSEADDR on %s %s socket", fam, proto);

#ifdef CONFIG_ENABLE_IPV6
	/* Keep the IPv6 listener separate, no v4-mapped addresses */
	if (family == AF_INET6 &&
	    setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) == -1)
		logit(LOG_WARNING, errno, "could not set IPV6_V6ONLY on %s socket", proto);
#endif

#ifdef __linux__
	/*
	 * Capture the local destination address of incoming UDP requests so
	 * the reply can be sent from that same address.  On multi-homed or
	 * wildcard-bound hosts the kernel would otherwise pick the source by
	 * routing, which confuses many SNMP clients.
	 */
	if (type == SOCK_DGRAM) {
		if (family == AF_INET &&
		    setsockopt(sd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val)) == -1)
			logit(LOG_WARNING, errno, "could not set IP_PKTINFO on %s socket", proto);
#ifdef CONFIG_ENABLE_IPV6
		if (family == AF_INET6 &&
		    setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val)) == -1)
			logit(LOG_WARNING, errno, "could not set IPV6_RECVPKTINFO on %s socket", proto);
#endif
	}

	if (g_bind_to_device) {
		struct ifreq ifreq;

		memset(&ifreq, 0, sizeof(ifreq));
		snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", g_bind_to_device);
		if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifreq, sizeof(ifreq)) == -1) {
			logit(LOG_WARNING, errno, "could not bind %s %s socket to device %s", fam, proto, g_bind_to_device);
			close(sd);
			return -1;
		}
	}
#endif

	inet_anyaddr(family, port, &addr);
	if (bind(sd, (struct sockaddr *)&addr, inet_len(&addr)) == -1) {
		logit(LOG_WARNING, errno, "could not bind %s %s socket to port %d", fam, proto, port);
		close(sd);
		return -1;
	}

	if (type == SOCK_STREAM && listen(sd, 128) == -1) {
		logit(LOG_WARNING, errno, "could not listen on %s TCP socket", fam);
		close(sd);
		return -1;
	}

	return sd;
}

int main(int argc, char *argv[])
{
	static const char short_options[] = "ac:C:d:D:hi:l:L:np:P:sT:t:u:vV:"
#ifdef __linux__
		"I:"
#endif
#ifdef CONFIG_ENABLE_IPV6
		"46"
#endif
#ifdef HAVE_LIBCONFUSE
		"f:"
#endif
		;
	static const struct option long_options[] = {
#ifdef CONFIG_ENABLE_IPV6
		{ "use-ipv4",    0, 0, '4' },
		{ "use-ipv6",    0, 0, '6' },
#endif
		{ "auth",        0, 0, 'a' },
		{ "community",   1, 0, 'c' },
		{ "contact",     1, 0, 'C' },
		{ "disks",       1, 0, 'd' },
		{ "description", 1, 0, 'D' },
#ifdef HAVE_LIBCONFUSE
		{ "file",        1, 0, 'f' },
#endif
		{ "help",        0, 0, 'h' },
		{ "interfaces",  1, 0, 'i' },
#ifdef __linux__
		{ "listen",      1, 0, 'I' },
#endif
		{ "loglevel",    1, 0, 'l' },
		{ "location",    1, 0, 'L' },
		{ "foreground",  0, 0, 'n' },
		{ "udp-port",    1, 0, 'p' },
		{ "tcp-port",    1, 0, 'P' },
		{ "syslog",      0, 0, 's' },
		{ "trap",        1, 0, 'T' },
		{ "timeout",     1, 0, 't' },
		{ "drop-privs",  1, 0, 'u' },
		{ "version",     0, 0, 'v' },
		{ "vendor",      1, 0, 'V' },
		{ NULL, 0, 0, 0 }
	};
	int ticks, nfds, c, sd, nl_sd, option_index = 1;
	size_t i, j;
	fd_set rfds, wfds;
	struct sigaction sig;
	struct timeval tv_last;
	struct timeval tv_now;
	struct timeval tv_sleep;
	int udp_fds[2] = { -1, -1 }, tcp_fds[2] = { -1, -1 };
	size_t n_udp = 0, n_tcp = 0;
#ifdef HAVE_LIBCONFUSE
	char path[256] = "";
	char *config = NULL;
#endif

	g_prognm = progname(argv[0]);

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
		case 'a':
			g_auth = 1;
			break;

		case 'c':
			g_community = optarg;
			break;

		case 'C':
			g_contact = optarg;
			break;

		case 'd':
			g_disk_list_length = split(optarg, ",:;", g_disk_list, MAX_NR_DISKS);
			break;

		case 'D':
			g_description = optarg;
			break;
#ifdef HAVE_LIBCONFUSE
		case 'f':
			config = optarg;
			break;
#endif
		case 'h':
			return usage(0);

		case 'i':
			g_interface_list_length = split(optarg, ",;", g_interface_list, MAX_NR_INTERFACES);
			break;
#ifdef __linux__
		case 'I':
			g_bind_to_device = strdup(optarg);
			break;
#endif
		case 'l':
			if (log_level(optarg))
				return usage(1);
			break;

		case 'L':
			g_location = optarg;
			break;

		case 'n':
			g_daemon = 0;
			break;

		case 'p':
			g_udp_port = atoi(optarg);
			break;

		case 'P':
			g_tcp_port = atoi(optarg);
			break;

		case 's':
			g_syslog = 1;
			break;

		case 'T':
			if (g_trap_dst_len >= MAX_NR_TRAPS)
				logit(LOG_ERR, 0, "Too many trap sinks, ignoring '%s'", optarg);
			else if (inet_pton2(optarg, 162, &g_trap_dst[g_trap_dst_len]) == 0)
				g_trap_dst_len++;
			else
				logit(LOG_ERR, 0, "Invalid trap address '%s'", optarg);
			break;

		case 't':
			g_timeout = atoi(optarg);
			break;

		case 'u':
			g_user = optarg;
			break;

		case 'v':
			printf("v" PACKAGE_VERSION "\n");
			printf("Bug report address: %s\n", PACKAGE_BUGREPORT);
#ifdef PACKAGE_URL
			printf("Project homepage: %s\n", PACKAGE_URL);
#endif
			return 0;

		case 'V':
			g_vendor = optarg;
			break;

		default:
			return usage(EXIT_ARGS);
		}
	}

	if (g_syslog)
		openlog(g_prognm, LOG_CONS | LOG_PID, LOG_DAEMON);

	logit(LOG_NOTICE, 0, PROGRAM_IDENT " starting");

	if (g_daemon) {
		logit(LOG_DEBUG, 0, "Daemonizing ...");
		if (-1 == daemon(0, 0)) {
			logit(LOG_ERR, errno, "Failed daemonizing");
			return 1;
		}
	}

#ifdef HAVE_LIBCONFUSE
	if (!config) {
		snprintf(path, sizeof(path), "%s/%s.conf", SYSCONFDIR, PACKAGE_NAME);
		config = path;
	} else if (access(config, F_OK)) {
		logit(LOG_ERR, errno, "Failed reading config file '%s'", config);
		return 1;
	}

	if (read_config(config))
		return 1;
#endif

	if (!g_community)
		g_community = "public";
	if (!g_vendor)
		g_vendor = VENDOR;
	if (!g_description)
		g_description = os_pretty_name();
	if (!g_description)
		g_description = "";
	if (!g_location)
		g_location = "";
	if (!g_contact)
		g_contact = "";

	/* No disks given?  Monitor the root filesystem. */
	if (g_disk_list_length == 0) {
		g_disk_list[0] = "/";
		g_disk_list_length = 1;
	}

	/* No interfaces given?  Monitor them all (loopback lands on ifIndex 1). */
	if (g_interface_list_length == 0) {
		g_interface_list[0] = "+";
		g_interface_list_length = 1;
	}

	/* Preserve the -i spec so the list can be rebuilt on netlink events,
	 * then let expand_interfaces() build the concrete g_interface_list. */
	for (i = 0; i < g_interface_list_length; i++)
		iface_pattern[i] = g_interface_list[i];
	iface_pattern_len = g_interface_list_length;
	g_interface_list_length = 0;

	g_timeout *= 100;

	/* Store the starting time since we need it for MIB updates */
	if (gettimeofday(&tv_last, NULL) == -1) {
		memset(&tv_last, 0, sizeof(tv_last));
		memset(&tv_sleep, 0, sizeof(tv_sleep));
	} else {
		tv_sleep.tv_sec = g_timeout / 100;
		tv_sleep.tv_usec = (g_timeout % 100) * 10000;
	}

	/* Expand any interface patterns (eth*, vlan*, ...) before building the MIB */
	expand_interfaces();

	/* Build the MIB and execute the first MIB update to get actual values */
	if (mib_build() == -1)
		exit(EXIT_SYSCALL);
	if (mib_update(1) == -1)
		exit(EXIT_SYSCALL);

	/* Prevent TERM and HUP signals from interrupting system calls */
	sig.sa_handler = handle_signal;
	sigemptyset (&sig.sa_mask);
	sig.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &sig, NULL);
	sigaction(SIGINT, &sig, NULL);
	sigaction(SIGHUP, &sig, NULL);

#ifdef DEBUG
	dump_mib(g_mib, g_mib_length);
#endif

	/*
	 * Open one UDP+TCP listening socket per enabled address family.
	 * Default (AF_UNSPEC) is dual-stack; -4/-6 restrict to one family.
	 * A family that fails to open is skipped, we only bail if nothing
	 * could be opened at all.
	 */
	if (g_family != AF_INET6) {
		if ((sd = open_socket(AF_INET, SOCK_DGRAM,  g_udp_port)) != -1)
			udp_fds[n_udp++] = sd;
		if ((sd = open_socket(AF_INET, SOCK_STREAM, g_tcp_port)) != -1)
			tcp_fds[n_tcp++] = sd;
	}
#ifdef CONFIG_ENABLE_IPV6
	if (g_family != AF_INET) {
		if ((sd = open_socket(AF_INET6, SOCK_DGRAM,  g_udp_port)) != -1)
			udp_fds[n_udp++] = sd;
		if ((sd = open_socket(AF_INET6, SOCK_STREAM, g_tcp_port)) != -1)
			tcp_fds[n_tcp++] = sd;
	}
#endif

	if (n_udp == 0 && n_tcp == 0) {
		logit(LOG_ERR, 0, "Could not open any listening socket, exiting.");
		exit(EXIT_SYSCALL);
	}

	/* Print a starting message (so the user knows the args were ok) */
	if (g_bind_to_device)
		logit(LOG_NOTICE, 0, "Listening on port %d/udp and %d/tcp on interface %s",
		      g_udp_port, g_tcp_port, g_bind_to_device);
	else
		logit(LOG_NOTICE, 0, "Listening on port %d/udp and %d/tcp", g_udp_port, g_tcp_port);

	if (g_user && geteuid() == 0) {
		struct passwd *pwd;
		struct group *grp;

		errno = 0;

		pwd = getpwnam(g_user);
		if (pwd == NULL) {
			logit(LOG_ERR, errno, "Unable to get UID for user \"%s\"", g_user);
			exit(EXIT_SYSCALL);
		}

		errno = 0;

		grp = getgrnam(g_user);
		if (grp == NULL) {
			logit(LOG_ERR, errno, "Unable to get GID for group \"%s\"", g_user);
			exit(EXIT_SYSCALL);
		}

		if (setgid(grp->gr_gid) == -1) {
			logit(LOG_ERR, errno, "Unable to set new group \"%s\"", g_user);
			exit(EXIT_SYSCALL);
		}

		if (setuid(pwd->pw_uid) == -1) {
			logit(LOG_ERR, errno, "Unable to set new user \"%s\"", g_user);
			exit(EXIT_SYSCALL);
		}

		logit(LOG_INFO, 0, "Successfully dropped privileges to %s:%s", g_user, g_user);
	}

	/*
	 * Tell system we're up and running by creating /run/mini-snmpd.pid
	 */
	if (pidfile(NULL))
		logit(LOG_ERR, errno, "Failed creating PID file");

	/* Watch for interface/address changes; the poll below is the fallback */
	nl_sd = netlink_init();

	/* Announce we are (re)started to any configured trap sinks */
	snmp_trap(TRAP_COLDSTART, NULL, 0);

	/* Handle incoming connect requests and incoming data */
	while (!g_quit) {
		/* Sleep until we get a request or the timeout is over */
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		nfds = 0;
		for (j = 0; j < n_udp; j++) {
			FD_SET(udp_fds[j], &rfds);
			if (nfds < udp_fds[j])
				nfds = udp_fds[j];
		}
		for (j = 0; j < n_tcp; j++) {
			FD_SET(tcp_fds[j], &rfds);
			if (nfds < tcp_fds[j])
				nfds = tcp_fds[j];
		}
		if (nl_sd >= 0) {
			FD_SET(nl_sd, &rfds);
			if (nfds < nl_sd)
				nfds = nl_sd;
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

			logit(LOG_ERR, errno, "could not select from sockets");
			exit(EXIT_SYSCALL);
		}

		/* Determine whether to update the MIB and the next ticks to sleep */
		ticks = ticks_since(&tv_last, &tv_now);
		if (ticks < 0 || ticks >= g_timeout) {
			logit(LOG_DEBUG, 0, "updating the MIB (full)");
			if (mib_update(1) == -1)
				exit(EXIT_SYSCALL);

			memcpy(&tv_last, &tv_now, sizeof(tv_now));
			tv_sleep.tv_sec = g_timeout / 100;
			tv_sleep.tv_usec = (g_timeout % 100) * 10000;
		} else {
			logit(LOG_DEBUG, 0, "updating the MIB (partial)");
			if (mib_update(0) == -1)
				exit(EXIT_SYSCALL);

			tv_sleep.tv_sec = (g_timeout - ticks) / 100;
			tv_sleep.tv_usec = ((g_timeout - ticks) % 100) * 10000;
		}

#ifdef DEBUG
		dump_mib(g_mib, g_mib_length);
#endif

		/* Handle UDP packets, TCP packets and TCP connection connects */
		for (j = 0; j < n_udp; j++) {
			if (FD_ISSET(udp_fds[j], &rfds))
				handle_udp_client(udp_fds[j]);
		}

		for (j = 0; j < n_tcp; j++) {
			if (FD_ISSET(tcp_fds[j], &rfds))
				handle_tcp_connect(tcp_fds[j]);
		}

		/* Rescan and rebuild the MIB on interface/address changes */
		if (nl_sd >= 0 && FD_ISSET(nl_sd, &rfds)) {
			if (netlink_read(nl_sd) > 0)
				rebuild_mib();
		}

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

	netlink_exit(nl_sd);

	/* We were signaled, print a message and exit */
	logit(LOG_NOTICE, 0, PROGRAM_IDENT " stopping");
	if (g_syslog)
		closelog();

	return EXIT_OK;
}

/* vim: ts=4 sts=4 sw=4 nowrap
 */
