/* Linux backend
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
#ifdef __linux__

#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/vfs.h>
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


/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
unsigned int get_process_uptime(void)
{
	static unsigned int uptime_start = 0;
	unsigned int uptime_now = get_system_uptime();

	if (uptime_start == 0)
		uptime_start = uptime_now;

	return uptime_now - uptime_start;
}

/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
unsigned int get_system_uptime(void)
{
	char buf[128];

	if (read_file("/proc/uptime", buf, sizeof(buf)) == -1)
		return -1;

	return (unsigned int)(atof(buf) * 100);
}

void get_loadinfo(loadinfo_t *loadinfo)
{
	int i;
	char buf[128];
	char *ptr;

	if (read_file("/proc/loadavg", buf, sizeof(buf)) == -1) {
		memset(loadinfo, 0, sizeof(loadinfo_t));
		return;
	}

	ptr = buf;
	for (i = 0; i < 3; i++) {
		while (isspace(*ptr))
			ptr++;

		if (*ptr != 0)
			loadinfo->avg[i] = strtod(ptr, &ptr) * 100;
	}
}

void get_meminfo(meminfo_t *meminfo)
{
	char buf[BUFSIZ];

	if (read_file("/proc/meminfo", buf, sizeof(buf)) == -1) {
		memset(meminfo, 0, sizeof(meminfo_t));
		return;
	}

	meminfo->total   = read_value(buf, "MemTotal");
	meminfo->free    = read_value(buf, "MemFree");
	meminfo->shared  = read_value(buf, "MemShared");
	meminfo->buffers = read_value(buf, "Buffers");
	meminfo->cached  = read_value(buf, "Cached");
}

void get_cpuinfo(cpuinfo_t *cpuinfo)
{
	char buf[BUFSIZ];
	unsigned int values[4];

	if (read_file("/proc/stat", buf, sizeof(buf)) == -1) {
		memset(cpuinfo, 0, sizeof(cpuinfo_t));
		return;
	}

	read_values(buf, "cpu", values, 4);
	cpuinfo->user   = values[0];
	cpuinfo->nice   = values[1];
	cpuinfo->system = values[2];
	cpuinfo->idle   = values[3];
	cpuinfo->irqs   = read_value(buf, "intr");
	cpuinfo->cntxts = read_value(buf, "ctxt");
}

void get_diskinfo(diskinfo_t *diskinfo)
{
	size_t i;
	struct statfs fs;

	for (i = 0; i < g_disk_list_length; i++) {
		if (statfs(g_disk_list[i], &fs) == -1) {
			diskinfo->total[i]               = 0;
			diskinfo->free[i]                = 0;
			diskinfo->used[i]                = 0;
			diskinfo->blocks_used_percent[i] = 0;
			diskinfo->inodes_used_percent[i] = 0;
		} else {
			diskinfo->total[i] = ((float)fs.f_blocks * fs.f_bsize) / 1024;
			diskinfo->free[i]  = ((float)fs.f_bfree  * fs.f_bsize) / 1024;
			diskinfo->used[i]  = ((float)(fs.f_blocks - fs.f_bfree) * fs.f_bsize) / 1024;
			diskinfo->blocks_used_percent[i] =
				((float)(fs.f_blocks - fs.f_bfree) * 100 + fs.f_blocks - 1) / fs.f_blocks;
			if (fs.f_files <= 0)
				diskinfo->inodes_used_percent[i] = 0;
			else
				diskinfo->inodes_used_percent[i] =
					((float)(fs.f_files - fs.f_ffree) * 100 + fs.f_files - 1) / fs.f_files;
		}
	}
}

void get_netinfo(netinfo_t *netinfo)
{
	int fd;
	size_t i;
	char buf[BUFSIZ];
	unsigned int values[16];
	struct ifreq ifreq;


	if (read_file("/proc/net/dev", buf, sizeof(buf)) == -1)
		buf[0] = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	for (i = 0; i < g_interface_list_length; i++) {
		snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", g_interface_list[i]);
		if (fd == -1 || ioctl(fd, SIOCGIFFLAGS, &ifreq) == -1) {
			netinfo->status[i] = 4;
		} else {
			if (ifreq.ifr_flags & IFF_UP)
				netinfo->status[i] = (ifreq.ifr_flags & IFF_RUNNING) ? 1 : 7;
			else
				netinfo->status[i] = 2;
		}

		read_values(buf, g_interface_list[i], values, 16);
		netinfo->rx_bytes[i]   = values[0];
		netinfo->rx_packets[i] = values[1];
		netinfo->rx_errors[i]  = values[2];
		netinfo->rx_drops[i]   = values[3];
		netinfo->tx_bytes[i]   = values[8];
		netinfo->tx_packets[i] = values[9];
		netinfo->tx_errors[i]  = values[10];
		netinfo->tx_drops[i]   = values[11];
	}

	if (fd != -1)
		close(fd);
}

#endif /* __linux__ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
