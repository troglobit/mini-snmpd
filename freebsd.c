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



#ifdef __FREEBSD__



#include <sys/limits.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <math.h>

#include "mini_snmpd.h"



unsigned int get_process_uptime(void)
{
	/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
	static unsigned int uptime_start = 0;
	unsigned int uptime_now;

	uptime_now = get_system_uptime();
	if (uptime_start == 0) {
		uptime_start = uptime_now;
	}
	return uptime_now - uptime_start;
}

unsigned int get_system_uptime(void)
{
	/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
	char buffer[128];

	if (read_file("/proc/uptime", buffer, sizeof (buffer)) != -1) {
		return (unsigned int)(atof(buffer) * 100);
	} else {
		return -1;
	}
}

void get_loadinfo(loadinfo_t *loadinfo)
{
	char buffer[128];
	char *ptr;
	int i;

	if (read_file("/proc/loadavg", buffer, sizeof (buffer)) != -1) {
		ptr = buffer;
		for (i = 0; i < 3; i++) {
			while (isspace(*ptr)) {
				ptr++;
			}
			if (*ptr != '\0') {
				loadinfo->avg[i] = strtod(ptr, &ptr) * 100;
			}
		}
	} else {
		memset(loadinfo, 0, sizeof (loadinfo_t));
	}
}

void get_meminfo(meminfo_t *meminfo)
{
	char buffer[BUFSIZ];

	if (read_file("/proc/meminfo", buffer, sizeof (buffer)) != -1) {
		meminfo->total = read_value(buffer, "MemTotal:");
		meminfo->free = read_value(buffer, "MemFree:");
		meminfo->shared = read_value(buffer, "MemShared:");
		meminfo->buffers = read_value(buffer, "Buffers:");
		meminfo->cached = read_value(buffer, "Cached:");
	} else {
		memset(meminfo, 0, sizeof (meminfo_t));
	}
}

void get_cpuinfo(cpuinfo_t *cpuinfo)
{
	char buffer[BUFSIZ];
	unsigned int values[4];

	if (read_file("/proc/stat", buffer, sizeof (buffer)) != -1) {
		read_values(buffer, "cpu", values, 4);
		cpuinfo->user = values[0];
		cpuinfo->nice = values[1];
		cpuinfo->system = values[2];
		cpuinfo->idle = values[3];
		cpuinfo->irqs = read_value(buffer, "intr");
		cpuinfo->cntxts = read_value(buffer, "ctxt");
	} else {
		memset(cpuinfo, 0, sizeof (cpuinfo_t));
	}
}

void get_diskinfo(diskinfo_t *diskinfo)
{
	struct statfs fs;
	int i;

	for (i = 0; i < g_disk_list_length; i++) {
		if (statfs(g_disk_list[i], &fs) != -1) {
			diskinfo->total[i] = ((float)fs.f_blocks * fs.f_bsize) / 1024;
			diskinfo->free[i] = ((float)fs.f_bfree * fs.f_bsize) / 1024;
			diskinfo->used[i] = ((float)(fs.f_blocks - fs.f_bfree) * fs.f_bsize) / 1024;
			diskinfo->blocks_used_percent[i] = ((float)(fs.f_blocks - fs.f_bfree)
				* 100 + fs.f_blocks - 1) / fs.f_blocks;
			if (fs.f_files > 0) {
				diskinfo->inodes_used_percent[i] = ((float)(fs.f_files - fs.f_ffree)
					* 100 + fs.f_files - 1) / fs.f_files;
			} else {
				diskinfo->inodes_used_percent[i] = 0;
			}
		} else {
			diskinfo->total[i] = 0;
			diskinfo->free[i] = 0;
			diskinfo->used[i] = 0;
			diskinfo->blocks_used_percent[i] = 0;
			diskinfo->inodes_used_percent[i] = 0;
		}
	}
}

void get_netinfo(netinfo_t *netinfo)
{
	struct ifreq ifreq;
	char buffer[BUFSIZ];
	char name[16];
	unsigned int values[16];
	int fd;
	int i;


	if (read_file("/proc/net/dev", buffer, sizeof (buffer)) == -1) {
		buffer[0] = '\0';
	}
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	for (i = 0; i < g_interface_list_length; i++) {
		snprintf(ifreq.ifr_name, sizeof (ifreq.ifr_name), "%s", g_interface_list[i]);
		if (fd != -1 && ioctl(fd, SIOCGIFFLAGS, &ifreq) != -1) {
			if (ifreq.ifr_flags & IFF_UP) {
				netinfo->status[i] = (ifreq.ifr_flags & IFF_RUNNING) ? 1 : 7;
			} else {
				netinfo->status[i] = 2;
			}
		} else {
			netinfo->status[i] = 4;
		}
		if (buffer[0] != '\0') {
			snprintf(name, sizeof (name), "%s:", g_interface_list[i]);
			read_values(buffer, name, values, 16);
		} else {
			memset(values, 0, sizeof (values));
		}
		netinfo->rx_bytes[i] = values[0];
		netinfo->rx_packets[i] = values[1];
		netinfo->rx_errors[i] = values[2];
		netinfo->rx_drops[i] = values[3];
		netinfo->tx_bytes[i] = values[8];
		netinfo->tx_packets[i] = values[9];
		netinfo->tx_errors[i] = values[10];
		netinfo->tx_drops[i] = values[11];
	}
	if (fd != -1) {
		close(fd);
	}
}



#endif /* __FREEBSD__ */



/* vim: ts=4 sts=4 sw=4 nowrap
 */
