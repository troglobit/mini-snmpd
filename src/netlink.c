/* Netlink interface monitor for Linux
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
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

#ifdef __linux__

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "mini-snmpd.h"
#include "netlink.h"

#define NL_BUFSZ 4096

/*
 * Open a netlink socket subscribed to interface link and address events.
 * Returns the socket fd on success, -1 on failure.
 */
int netlink_init(void)
{
	struct sockaddr_nl sa = { 0 };
	int sd;

	sd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (sd < 0) {
		logit(LOG_WARNING, errno, "Failed creating netlink socket");
		return -1;
	}

	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		logit(LOG_WARNING, errno, "Failed binding netlink socket");
		close(sd);
		return -1;
	}

	return sd;
}

/*
 * Drain all pending netlink messages.  Returns 1 if any link or address
 * change event was seen (caller should rescan interfaces), 0 if nothing
 * relevant arrived, or -1 on a fatal socket error.
 *
 * ENOBUFS means the kernel dropped events because we were too slow; treat
 * that as an implicit change so the caller rescans to catch up.
 */
int netlink_read(int sd)
{
	char buf[NL_BUFSZ];
	struct nlmsghdr *nh;
	ssize_t len;
	size_t l;
	int changed = 0;

	while (1) {
		len = recv(sd, buf, sizeof(buf), 0);
		if (len < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == EINTR)
				continue;
			if (errno == ENOBUFS) {
				logit(LOG_WARNING, 0, "Netlink buffer overflow, interface events may have been lost");
				changed = 1;
				break;
			}
			logit(LOG_ERR, errno, "Netlink recv error");
			return -1;
		}

		l = (size_t)len;
		for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, l); nh = NLMSG_NEXT(nh, l)) {
			switch (nh->nlmsg_type) {
			case RTM_NEWLINK:
			case RTM_DELLINK:
			case RTM_NEWADDR:
			case RTM_DELADDR:
				changed = 1;
				break;

			default:
				break;
			}
		}
	}

	return changed;
}

void netlink_exit(int sd)
{
	if (sd >= 0)
		close(sd);
}

#endif /* __linux__ */
