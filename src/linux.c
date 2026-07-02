/* Linux backend
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
#ifdef __linux__

#include <netpacket/packet.h>
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
#include <ifaddrs.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <utmp.h>
#include <glob.h>

#include "mini-snmpd.h"


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

unsigned int get_process_count(void)
{
	struct sysinfo si;

	if (sysinfo(&si) == -1)
		return 0;

	return (unsigned int)si.procs;
}

unsigned int get_user_count(void)
{
	unsigned int num = 0;
	struct utmp *ut;

	setutent();
	while ((ut = getutent())) {
		if (ut->ut_type == USER_PROCESS)
			num++;
	}
	endutent();

	return num;
}

void get_loadinfo(loadinfo_t *loadinfo)
{
	char buf[128];
	char *ptr;
	int i;

	memset(loadinfo, 0, sizeof(loadinfo_t));
	if (read_file("/proc/loadavg", buf, sizeof(buf)) == -1)
		return;

	ptr = buf;
	for (i = 0; i < 3; i++) {
		while (isspace(*ptr))
			ptr++;

		if (*ptr == 0)
			continue;

		loadinfo->avg[i] = strtod(ptr, &ptr) * 100;
	}
}

void get_meminfo(meminfo_t *meminfo)
{
	field_t fields[] = {
		{ "MemTotal",  1, { &meminfo->total   }},
		{ "MemFree",   1, { &meminfo->free    }},
		{ "MemShared", 1, { &meminfo->shared  }},
		{ "Buffers",   1, { &meminfo->buffers }},
		{ "Cached",    1, { &meminfo->cached  }},
	};

	memset(meminfo, 0, sizeof(meminfo_t));
	parse_file("/proc/meminfo", fields, NELEMS(fields), 0);
}

void get_cpuinfo(cpuinfo_t *cpuinfo)
{
	field_t fields[] = {
		{ "cpu ",  4, { &cpuinfo->user, &cpuinfo->nice, &cpuinfo->system, &cpuinfo->idle }},
		{ "intr ", 1, { &cpuinfo->irqs   }},
		{ "ctxt ", 1, { &cpuinfo->cntxts }},
	};

	memset(cpuinfo, 0, sizeof(cpuinfo_t));
	parse_file("/proc/stat", fields, NELEMS(fields), 0);
}

/* Strip trailing newline from a sysfs one-liner */
static void chomp(char *str)
{
	str[strcspn(str, "\n")] = 0;
}

/* Quiet one-line sysfs reader.  Optional label files and flaky sensors
 * are expected here, so unlike read_file() this does not log failures,
 * which would otherwise spam the log on every MIB update. */
static int sysfs_read(const char *path, char *buf, size_t len)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	if (!fgets(buf, len, fp)) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

/*
 * Temperature sensors from /sys/class/hwmon, in milli-degrees Celsius.
 * Each sensor is named "<chip> <label>", e.g. "k10temp Tctl", falling
 * back to the tempN stem when the driver provides no label.
 */
void get_sensinfo(sensinfo_t *sensinfo)
{
	glob_t gl;
	size_t i;

	memset(sensinfo, 0, sizeof(*sensinfo));

	if (glob("/sys/class/hwmon/hwmon*/temp*_input", 0, NULL, &gl))
		return;

	for (i = 0; i < gl.gl_pathc && sensinfo->count < MAX_NR_SENSORS; i++) {
		char path[256], chip[32], label[32], buf[32];
		char *stem, *sep;
		int val;

		/* A transient read error reads as 0, keeping the row set
		 * stable between MIB build and update */
		val = 0;
		if (sysfs_read(gl.gl_pathv[i], buf, sizeof(buf)) != -1)
			val = atoi(buf);

		/* chip name lives in ../name, label in tempN_label */
		snprintf(path, sizeof(path), "%s", gl.gl_pathv[i]);
		stem = strrchr(path, '/');
		snprintf(chip, sizeof(chip), "hwmon");
		if (stem) {
			*stem = 0;
			snprintf(path + strlen(path), sizeof(path) - strlen(path), "/name");
			if (sysfs_read(path, chip, sizeof(chip)) != -1)
				chomp(chip);
			*stem = '/';
			snprintf(path, sizeof(path), "%s", gl.gl_pathv[i]);
		}

		sep = strstr(path, "_input");
		label[0] = 0;
		if (sep) {
			snprintf(sep, sizeof(path) - (sep - path), "_label");
			if (sysfs_read(path, label, sizeof(label)) != -1)
				chomp(label);
			else
				label[0] = 0;
		}
		if (!label[0]) {
			/* fall back to the tempN stem */
			stem = strrchr(gl.gl_pathv[i], '/');
			snprintf(label, sizeof(label), "%s", stem ? stem + 1 : "temp");
			sep = strstr(label, "_input");
			if (sep)
				*sep = 0;
		}

		snprintf(sensinfo->name[sensinfo->count], sizeof(sensinfo->name[0]),
			 "%s %s", chip, label);
		sensinfo->temp[sensinfo->count] = val > 0 ? (unsigned int)val : 0;
		sensinfo->count++;
	}

	globfree(&gl);
}

/* Per-CPU cumulative jiffies, from the 'cpuN' lines of /proc/stat */
void get_cpuload(cpuload_t *cpuload)
{
	char line[256];
	FILE *fp;

	memset(cpuload, 0, sizeof(*cpuload));

	fp = fopen("/proc/stat", "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		long long v[10] = { 0 };
		long long total = 0, idle;
		unsigned long n;
		char *p;
		int i, got;

		/* Only the per-CPU lines, 'cpuN ...', not the 'cpu ' aggregate */
		if (strncmp(line, "cpu", 3) || !isdigit((unsigned char)line[3]))
			continue;

		n = strtoul(line + 3, &p, 10);
		if (n >= MAX_NR_CPUS)
			continue;

		got = sscanf(p, "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
			     &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9]);
		if (got < 4)
			continue;

		for (i = 0; i < got; i++)
			total += v[i];
		idle = v[3];			/* idle */
		if (got > 4)
			idle += v[4];		/* + iowait */

		cpuload->busy[n]  = total - idle;
		cpuload->total[n] = total;
		if (n + 1 > cpuload->ncpu)
			cpuload->ncpu = n + 1;
	}

	fclose(fp);
}

void get_ipinfo(ipinfo_t *ipinfo)
{
	long long garbage;
	field_t fields[] = {
		{ "Ip", 13,
		  { &ipinfo->ipForwarding,
		    &ipinfo->ipDefaultTTL,
		    &garbage,
		    &garbage,
		    &garbage,
		    &garbage,
		    &garbage,
		    &garbage,
		    &garbage,
		    &garbage,
		    &garbage,
		    &garbage,
		    &ipinfo->ipReasmTimeout } },
	};

	memset(ipinfo, 0, sizeof(ipinfo_t));
	parse_file("/proc/net/snmp", fields, NELEMS(fields), 1);
}

void get_tcpinfo(tcpinfo_t *tcpinfo)
{
	field_t fields[] = {
		{ "Tcp", 14,
		  { &tcpinfo->tcpRtoAlgorithm,
		    &tcpinfo->tcpRtoMin,
		    &tcpinfo->tcpRtoMax,
		    &tcpinfo->tcpMaxConn,
		    &tcpinfo->tcpActiveOpens,
		    &tcpinfo->tcpPassiveOpens,
		    &tcpinfo->tcpAttemptFails,
		    &tcpinfo->tcpEstabResets,
		    &tcpinfo->tcpCurrEstab,
		    &tcpinfo->tcpInSegs,
		    &tcpinfo->tcpOutSegs,
		    &tcpinfo->tcpRetransSegs,
		    &tcpinfo->tcpInErrs,
		    &tcpinfo->tcpOutRsts } },
	};

	if (parse_file("/proc/net/snmp", fields, NELEMS(fields), 1))
		memset(tcpinfo, 0, sizeof(tcpinfo_t));
}

void get_udpinfo(udpinfo_t *udpinfo)
{
	field_t fields[] = {
		{ "Udp", 4,
		  { &udpinfo->udpInDatagrams,
		    &udpinfo->udpNoPorts,
		    &udpinfo->udpInErrors,
		    &udpinfo->udpOutDatagrams } },
	};

	if (parse_file("/proc/net/snmp", fields, NELEMS(fields), 1))
		memset(udpinfo, 0, sizeof(udpinfo_t));
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
	field_t fields[MAX_NR_INTERFACES + 1];

	if (getifaddrs(&ifap) < 0)
		return;

	memset(fields, 0, sizeof(fields));
	memset(netinfo, 0, sizeof(*netinfo));

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_in *addr, *mask, *bcaddr;
		struct sockaddr_ll *sll;
		int i;

		if (!ifa->ifa_addr)
			continue;

		i = find_ifname(ifa->ifa_name);
		if (i == -1)
			continue;

		switch (ifa->ifa_addr->sa_family) {
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

		case AF_INET6:
			/* XXX: Not supported yet */
			break;

		default:
			break;
		}

		if (!netinfo->stats[i]) {
			if (ifa->ifa_flags & IFF_POINTOPOINT)
				netinfo->if_type[i] = 23; /* ppp(23) */
			else if (ifa->ifa_flags & IFF_LOOPBACK)
				netinfo->if_type[i] = 24; /* softwareLoopback(24) */
			else
				netinfo->if_type[i] = 6; /* ethernetCsmacd(6) */

			if (ifa->ifa_flags & IFF_UP)
				netinfo->status[i] = (ifa->ifa_flags & IFF_RUNNING) ? 1 : 7;
			else
				netinfo->status[i] = 2;

			sll = (struct sockaddr_ll *)ifa->ifa_addr;
			memcpy(netinfo->mac_addr[i], sll->sll_addr, sizeof(netinfo->mac_addr[i]));

			if (ethtool_gstats(i, netinfo, &fields[i]) < 0) {
				/* XXX: Tx multicast and Rx/Tx broadcast not available atm. */
				fields[i].prefix    = g_interface_list[i];
				fields[i].len       = 12;
				fields[i].value[0]  = &netinfo->rx_bytes[i];
				fields[i].value[1]  = &netinfo->rx_packets[i];
				fields[i].value[2]  = &netinfo->rx_errors[i];
				fields[i].value[3]  = &netinfo->rx_drops[i];
				fields[i].value[7]  = &netinfo->rx_mc_packets[i];
				fields[i].value[8]  = &netinfo->tx_bytes[i];
				fields[i].value[9]  = &netinfo->tx_packets[i];
				fields[i].value[10] = &netinfo->tx_errors[i];
				fields[i].value[11] = &netinfo->tx_drops[i];
			}

			if (-1 == read_file_value(&netinfo->if_mtu[i], "/sys/class/net/%s/mtu", g_interface_list[i]))
				netinfo->if_mtu[i] = 1500; /* Fallback */

			if (-1 == read_file_value(&netinfo->if_speed[i], "/sys/class/net/%s/speed", g_interface_list[i]))
				netinfo->if_speed[i] = 1000; /* Fallback */
			netinfo->if_speed[i] *= 1000000;     /* to bps */

			netinfo->ifindex[i] = if_nametoindex(ifa->ifa_name);

			/* XXX: Need better tracking on Linux, c.f. FreeBSD ... */
			netinfo->lastchange[1] = get_process_uptime();
			netinfo->stats[i] = 1;
		}
	}

	parse_file("/proc/net/dev", fields, NELEMS(fields), 0);
	freeifaddrs(ifap);
}

#endif /* __linux__ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
