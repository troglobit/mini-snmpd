/* FreeBSD backend
 *
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 * Copyright (C) 2015       Joachim Nilsson <troglobit@gmail.com>
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
#ifdef __FreeBSD__

#include <sys/limits.h>
#include <sys/param.h>
#include <sys/mount.h>

#include <sys/resource.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <vm/vm_param.h>
#include <ifaddrs.h>

#include <sys/time.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mini_snmpd.h"

unsigned int get_process_uptime(void)
{
	static unsigned int uptime_start = 0;
	unsigned int uptime_now = get_system_uptime();

	if (uptime_start == 0)
		uptime_start = uptime_now;

	return uptime_now - uptime_start;
}

unsigned int get_system_uptime(void)
{
#if 1
	struct timespec tv;

	if (clock_gettime(CLOCK_UPTIME_PRECISE, &tv))
		return -1;

	return tv.tv_sec;
#else
        int             mib[2] = { CTL_KERN, KERN_BOOTTIME };
        size_t          len;
        struct timeval  uptime;

        len = sizeof(uptime);
        if (0 != sysctl(mib, 2, &uptime, &len, NULL, 0))
                return -1;

        return time(NULL) - uptime.tv_sec;
#endif
}

void get_loadinfo(loadinfo_t *loadinfo)
{
	struct loadavg avgs;
	size_t len = sizeof(avgs);
	int i, mib[2] = { CTL_VM, VM_LOADAVG };

	memset(loadinfo, 0, sizeof(loadinfo_t));
	if (sysctl(mib, 2, &avgs, &len, NULL, 0))
		return;

	for (i = 0; i < 3; i++)
		loadinfo->avg[i] = (float)avgs.ldavg[i] / (float)avgs.fscale * 100;
}

void get_meminfo(meminfo_t *meminfo)
{
	struct vmtotal vmt;
	unsigned long physmem, cache_cnt = 0;
	unsigned int pagesize;
	size_t len;
	int ret = 0, mib[2] = { CTL_HW, HW_PHYSMEM };

	memset(meminfo, 0, sizeof(meminfo_t));

	len = sizeof(physmem);
	ret = sysctl(mib, 2, &physmem, &len, NULL, 0);
	if (ret) {
		perror("hw.physmem");
		return;
	}

	mib[1] = HW_PAGESIZE;
	ret = sysctl(mib, 2, &pagesize, &len, NULL, 0);
	if (ret) {
		perror("hw.pagesize");
		return;
	}

	mib[0] = CTL_VM; mib[1] = VM_TOTAL;
	len = sizeof(vmt);
	ret = sysctl(mib, 2, &vmt, &len, NULL, 0);
	if (ret) {
		perror("vm.total");
		return;
	}

	meminfo->total   = (unsigned int)physmem / 1024;
	meminfo->free    = vmt.t_free * pagesize / 1024;
	meminfo->shared  = vmt.t_vmshr;  /* avmshr or vmrshr */
	meminfo->buffers = 0;		 /* Not on FreeBSD? */
	sysctlbyname("vm.stats.vm.v_cache_count", &cache_cnt, &len, NULL, 0);
	meminfo->cached  = (unsigned int)cache_cnt * pagesize / 1024;
}

void get_cpuinfo(cpuinfo_t *cpuinfo)
{
	long cp_info[CPUSTATES];
	size_t len = sizeof(cp_info);

	memset(cpuinfo, 0, sizeof(*cpuinfo));
	if (sysctlbyname("kern.cp_time", &cp_info, &len, NULL, 0) < 0)
		return;

	cpuinfo->user   = cp_info[CP_USER];
	cpuinfo->nice   = cp_info[CP_NICE];
	cpuinfo->system = cp_info[CP_SYS];
	cpuinfo->idle   = cp_info[CP_IDLE];
	cpuinfo->irqs   = cp_info[CP_INTR];
	cpuinfo->cntxts = 0;	/* TODO */
}

void get_diskinfo(diskinfo_t *diskinfo)
{
	struct statfs fs;
	size_t i;

	memset(diskinfo, 0, sizeof(*diskinfo));
	for (i = 0; i < g_disk_list_length; i++) {
		if (statfs(g_disk_list[i], &fs) == -1)
			continue;

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

static int find_ifname(char *ifname)
{
	int i;

	for (i = 0; i < g_interface_list_length; i++) {
		if (!strcmp(g_interface_list[i], ifname))
			return i;
	}

	return -1;
}

void get_netinfo(netinfo_t *netinfo)
{
	struct ifaddrs *ifap, *ifa;

	memset(netinfo, 0, sizeof(*netinfo));
	if (getifaddrs(&ifap) < 0)
		return;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct if_data *ifd = ifa->ifa_data;
		int i;


		i = find_ifname(ifa->ifa_name);
		if (i == -1 || ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		if (ifd->ifi_link_state == LINK_STATE_UNKNOWN)
			netinfo->status[i] = 4;
		else
			netinfo->status[i] = ifd->ifi_link_state == LINK_STATE_UP ? 1 : 2;

		switch (ifd->ifi_type) {
		default:
		case IFT_ETHER:
			netinfo->if_type[i] = 6; /* ethernetCsmacd(6) */
			break;
		case IFT_PPP:
			netinfo->if_type[i] = 23; /* ppp(23) */
			break;
		case IFT_LOOP:
			netinfo->if_type[i] = 24; /* softwareLoopback(24) */
			break;
		case IFT_SLIP:
			netinfo->if_type[i] = 28; /* slip(28) */
			break;
		}

		netinfo->rx_bytes[i]   = ifd->ifi_ibytes;
		netinfo->rx_packets[i] = ifd->ifi_ipackets;
		netinfo->rx_errors[i]  = ifd->ifi_ierrors;
		netinfo->rx_drops[i]   = ifd->ifi_iqdrops;
		netinfo->tx_bytes[i]   = ifd->ifi_obytes;
		netinfo->tx_packets[i] = ifd->ifi_opackets;
		netinfo->tx_errors[i]  = ifd->ifi_oerrors;
		netinfo->tx_drops[i]   = ifd->ifi_collisions;

		memcpy(&netinfo->mac_addr[i][0], LLADDR((struct sockaddr_dl *)ifa->ifa_addr), 6);
	}

	freeifaddrs(ifap);
}

#endif /* __FreeBSD__ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
