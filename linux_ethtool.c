/* Linux ethtool helpers
 *
 * Copyright (C) 2020  Bjørn Mork <bjorn@mork.no>
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

#include <confuse.h>
#include <fnmatch.h>
#include <net/if.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/sockios.h>
#include <linux/types.h>

#include "ethtool-conf.h"
#include "mini-snmpd.h"

#ifdef CONFIG_ENABLE_ETHTOOL

typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int32_t s32;

/* counter offsets and number of counters per interface */
static struct ethtool_s {
	int n_stats;
	int rx_bytes;
	int rx_mc_packets;
	int rx_bc_packets;
	int rx_packets;
	int rx_errors;
	int rx_drops;
	int tx_bytes;
	int tx_mc_packets;
	int tx_bc_packets;
	int tx_packets;
	int tx_errors;
	int tx_drops;
} ethtool[MAX_NR_INTERFACES];

/* ethtool socket */
static int fd = -1;

static int ethtool_init()
{
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0)
		logit(LOG_ERR, errno, "Cannot get control socket");
	return fd;
}

static struct ethtool_gstrings *get_stringset(const char *iname)
{
	struct ifreq ifr = {};
	struct {
		struct ethtool_sset_info hdr;
		u32 buf[1];
	} sset_info;
	u32 len;
	struct ethtool_gstrings *strings;

	sset_info.hdr.cmd = ETHTOOL_GSSET_INFO;
	sset_info.hdr.reserved = 0;
	sset_info.hdr.sset_mask = 1ULL << ETH_SS_STATS;
	ifr.ifr_data = (void *)&sset_info;
	strcpy(ifr.ifr_name, iname);
	if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
		const u32 *sset_lengths = sset_info.hdr.data;

		len = sset_info.hdr.sset_mask ? sset_lengths[0] : 0;
	} else {
		return NULL;
	}

	strings = calloc(1, sizeof(*strings) + len * ETH_GSTRING_LEN);
	if (!strings)
		return NULL;

	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = ETH_SS_STATS;
	strings->len = len;
	ifr.ifr_data = (void *)strings;
	if (len != 0 && ioctl(fd, SIOCETHTOOL, &ifr)) {
		free(strings);
		return NULL;
	}

	return strings;
}

static int ethtool_match_string(const char *key, struct ethtool_gstrings *strings)
{
	unsigned int i;

	if (!key)
		return -1;
	for (i = 0; i < strings->len; i++) {
		if (!strncmp(key, (char *)&strings->data[i * ETH_GSTRING_LEN], ETH_GSTRING_LEN)) {
			logit(LOG_DEBUG, 0, "found '%s' match at index %u", key, i);
			return i;
		}
	}
	return -1;
}

#define ethtool_parse_opt(_name)													\
	ethtool[intf]._name = ethtool_match_string(cfg_getstr(cfg, #_name), strings);	\
	if (ethtool[intf]._name >= 0)										       		\
		found = 1;

static void ethtool_xlate_intf(cfg_t *cfg, int intf, const char *iname)
{
	struct ethtool_gstrings *strings = get_stringset(iname);
	int found = 0;

	if (!strings)
		return;

	logit(LOG_DEBUG, 0, "got ethtool stats strings for '%s'", iname);

	ethtool_parse_opt(rx_bytes);
	ethtool_parse_opt(rx_mc_packets);
	ethtool_parse_opt(rx_bc_packets);
	ethtool_parse_opt(rx_packets);
	ethtool_parse_opt(rx_errors);
	ethtool_parse_opt(rx_drops);
	ethtool_parse_opt(tx_bytes);
	ethtool_parse_opt(tx_mc_packets);
	ethtool_parse_opt(tx_bc_packets);
	ethtool_parse_opt(tx_packets);
	ethtool_parse_opt(tx_errors);
	ethtool_parse_opt(tx_drops);

	/* save the size of the stats table if we found at least one macth */
	if (found)
		ethtool[intf].n_stats = strings->len;
	else
		logit(LOG_DEBUG, 0, "fount no matching string for '%s'", iname);

	free(strings);
}

void ethtool_xlate_cfg(cfg_t *cfg)
{
	cfg_t *ethtool;
	const char *iname;
	unsigned int i, j;
	int intf;

	if (ethtool_init() < 0)
		return;

	for (i = 0; i < cfg_size(cfg, "ethtool"); i++) {
		ethtool = cfg_getnsec(cfg, "ethtool", i);
		iname = cfg_title(ethtool);
		logit(LOG_INFO, 0, "Parsing ethtool section '%s'", iname);

		/* exact match? */
		intf = find_ifname((char *)iname);
		if (intf >= 0) {
			ethtool_xlate_intf(ethtool, intf, iname);
			continue;
		}

		/* or wildcard match? */
		if (strcspn(iname, "*?[")) {
			for (j = 0; j < g_interface_list_length; j++) {
				if (!fnmatch(iname, g_interface_list[j], 0))
					ethtool_xlate_intf(ethtool, j, g_interface_list[j]);
			}
		}
	}
}

#define set_val(_fieldnum, _name)													\
	if (ethtool[intf]._name >= 0 && ethtool[intf]._name < ethtool[intf].n_stats)	\
		netinfo->_name[intf] = stats->data[ethtool[intf]._name];					\
	else if (_fieldnum >= 0) {														\
			fallback = 1;															\
			field->value[_fieldnum] = &netinfo->_name[intf];						\
	}

int ethtool_gstats(int intf, netinfo_t *netinfo, field_t *field)
{
	struct ifreq ifr = {};
	struct ethtool_stats *stats;
	unsigned int sz_stats;
	int fallback = 0;

	if (fd < 0)
		return fd;
	if (!ethtool[intf].n_stats)
		return -1;

	sz_stats = ethtool[intf].n_stats * sizeof(u64);
	stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));
	if (!stats) {
		logit(LOG_ERR, ENOMEM, "cannot allocate mem for ethtool stats");
		return -ENOMEM;
	}

	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = ethtool[intf].n_stats;
	strcpy(ifr.ifr_name, g_interface_list[intf]);
	ifr.ifr_data = (void *)stats;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0) {
		logit(LOG_ERR, errno, "Cannot get ethtool stats");
		free(stats);
		return -errno;
	}

	set_val( 0, rx_bytes);
	set_val( 7, rx_mc_packets);
	set_val(-1, rx_bc_packets);
	set_val( 1, rx_packets);
	set_val( 2, rx_errors);
	set_val( 3, rx_drops);
	set_val( 8, tx_bytes);
	set_val(-1, tx_mc_packets);
	set_val(-1, tx_bc_packets);
	set_val( 9, tx_packets);
	set_val(10, tx_errors);
	set_val(11, tx_drops);

	/* we can avoid parsing values from the dev file if there is no fallback counter */
	if (fallback) {
		field->prefix = g_interface_list[intf];
		field->len    = 12;
	}
	free(stats);

	return 0;
}

#endif /* CONFIG_ENABLE_ETHTOOL */
#endif /* __linux__ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
