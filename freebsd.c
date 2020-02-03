/* FreeBSD backend
 *
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 * Copyright (C) 2015-2020  Joachim Nilsson <troglobit@gmail.com>
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
#include <net/if_var.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_timer.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "mini-snmpd.h"

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
	len = sizeof(cache_cnt);
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

void get_ipinfo(ipinfo_t *ipinfo)
{
	size_t len;

	memset(ipinfo, 0, sizeof(ipinfo_t));

	len = sizeof(ipinfo->ipForwarding);
	sysctlbyname("net.inet.ip.forwarding", &ipinfo->ipForwarding, &len, NULL, 0);

	len = sizeof(ipinfo->ipDefaultTTL);
	sysctlbyname("net.inet.ip.ttl", &ipinfo->ipDefaultTTL, &len, NULL, 0);

	ipinfo->ipReasmTimeout = IPFRAGTTL;
}

void get_tcpinfo(tcpinfo_t *tcpinfo)
{
	struct clockinfo clockinfo;
	struct tcpstat tcps;
	size_t len;

	memset(tcpinfo, 0, sizeof(*tcpinfo));

	len = sizeof(clockinfo);
	if (sysctlbyname("kern.clockrate", &clockinfo, &len, NULL, 0) == -1)
		return;
	if (len != sizeof(clockinfo))
		return;

	len = sizeof(tcps);
	if (sysctlbyname("net.inet.tcp.stats", &tcps, &len, NULL, 0) == -1)
		return;

	if (sizeof(tcps) != len)
		return;

	tcpinfo->tcpRtoAlgorithm = 4; /* Van Jacobson */
#define hz clockinfo.hz
	tcpinfo->tcpRtoMin = 1000 * TCPTV_MIN / hz;
	tcpinfo->tcpRtoMax = 1000 * TCPTV_REXMTMAX / hz;
#undef hz
	tcpinfo->tcpMaxConn = -1;
	tcpinfo->tcpActiveOpens = tcps.tcps_connattempt;
	tcpinfo->tcpPassiveOpens = tcps.tcps_accepts;
	tcpinfo->tcpAttemptFails = tcps.tcps_conndrops;
	tcpinfo->tcpEstabResets = tcps.tcps_drops;
	tcpinfo->tcpCurrEstab = tcps.tcps_connects + tcps.tcps_closed;
	tcpinfo->tcpInSegs = tcps.tcps_rcvtotal;
	tcpinfo->tcpOutSegs = tcps.tcps_sndtotal - tcps.tcps_sndrexmitpack;
	tcpinfo->tcpRetransSegs = tcps.tcps_sndrexmitpack;
	tcpinfo->tcpInErrs = tcps.tcps_rcvbadsum + tcps.tcps_rcvbadoff + tcps.tcps_rcvshort;
	tcpinfo->tcpOutRsts = tcps.tcps_sndctrl; /* Not just sent RSTs, includes SYN + FIN */
}

void get_udpinfo(udpinfo_t *udpinfo)
{
	struct udpstat udps;
	size_t len = sizeof(udps);

	memset(udpinfo, 0, sizeof(*udpinfo));

	if (sysctlbyname("net.inet.udp.stats", &udps, &len, NULL, 0) == -1)
		return;

	if (sizeof(udps) != len)
		return;

	udpinfo->udpInDatagrams  = udps.udps_ipackets;
	udpinfo->udpNoPorts      = (udps.udps_noport +
				    udps.udps_noportbcast +
				    udps.udps_noportmcast);
	udpinfo->udpInErrors     = (udps.udps_hdrops +
				    udps.udps_badsum +
				    udps.udps_badlen);
	udpinfo->udpOutDatagrams = udps.udps_opackets;
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

void get_netinfo(netinfo_t *netinfo)
{
	struct ifaddrs *ifap, *ifa;

	memset(netinfo, 0, sizeof(*netinfo));
	if (getifaddrs(&ifap) < 0)
		return;

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_in *addr, *mask, *bcaddr;
		struct sockaddr_dl *sdl;
		struct if_data *ifd;
		int i;

		if (!ifa->ifa_addr)
			continue;

		i = find_ifname(ifa->ifa_name);
		if (i == -1)
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			memcpy(netinfo->mac_addr[i], LLADDR(sdl), sizeof(netinfo->mac_addr[i]));

			ifd = ifa->ifa_data;
			if (!ifd)
				continue;

			if (ifa->ifa_flags & IFF_UP)
				switch (ifd->ifi_link_state) {
				case LINK_STATE_UP:
					netinfo->status[i] = 1;
					break;
				case LINK_STATE_DOWN:
					netinfo->status[i] = 7;
					break;
				default:
				case LINK_STATE_UNKNOWN:
					netinfo->status[i] = 4;
					break;
				}
			else
				netinfo->status[i] = 2; /* Down */

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

			netinfo->if_mtu[i]        = ifd->ifi_mtu;
			netinfo->if_speed[i]      = ifd->ifi_baudrate;
			netinfo->ifindex[i]       = if_nametoindex(ifa->ifa_name);
			netinfo->lastchange[1]    = ifd->ifi_lastchange.tv_sec;
			netinfo->rx_bytes[i]      = ifd->ifi_ibytes;
			netinfo->rx_packets[i]    = ifd->ifi_ipackets;
			netinfo->rx_mc_packets[i] = ifd->ifi_imcasts;
			netinfo->rx_bc_packets[i] = 0;			/* XXX: Couldn't find at first glance */
			netinfo->rx_errors[i]     = ifd->ifi_ierrors;
			netinfo->rx_drops[i]      = ifd->ifi_iqdrops;
			netinfo->tx_bytes[i]      = ifd->ifi_obytes;
			netinfo->tx_packets[i]    = ifd->ifi_opackets;
			netinfo->tx_mc_packets[i] = ifd->ifi_omcasts;
			netinfo->tx_bc_packets[i] = 0;			/* XXX: Couldn't find at first glance */
			netinfo->tx_errors[i]     = ifd->ifi_oerrors;
			netinfo->tx_drops[i]      = ifd->ifi_collisions;
			break;

		case AF_INET:
			if (!ifa->ifa_addr || !ifa->ifa_netmask)
				continue;

			addr = (struct sockaddr_in *)ifa->ifa_addr;
			mask = (struct sockaddr_in *)ifa->ifa_netmask;
			if (addr) {
				netinfo->in_addr[i] = ntohl(addr->sin_addr.s_addr);
				netinfo->in_mask[i] = ntohl(mask->sin_addr.s_addr);
			}

			bcaddr = (struct sockaddr_in *)ifa->ifa_broadaddr;
			if (bcaddr && (ifa->ifa_flags & IFF_BROADCAST)) {
				netinfo->in_bcaddr[i] = ntohl(bcaddr->sin_addr.s_addr);
				netinfo->in_bcent[i]  = netinfo->in_bcaddr[i] ? 1 : 0;
			}
			break;
		}
	}

	freeifaddrs(ifap);
}

#endif /* __FreeBSD__ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
