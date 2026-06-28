/* .conf parser
 *
 * Copyright (C) 2018-2026  Joachim Wiberg <troglobit@gmail.com>
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
#include <errno.h>
#include <confuse.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "ethtool-conf.h"
#include "mini-snmpd.h"

static cfg_t *cfg = NULL;

static void conf_errfunc(cfg_t *cfg, const char *format, va_list args)
{
	char fmt[80];
	char buf[256];

	if (cfg && cfg->filename && cfg->line)
		snprintf(fmt, sizeof(fmt), "%s:%d: %s\n", cfg->filename, cfg->line, format);
	else if (cfg && cfg->filename)
		snprintf(fmt, sizeof(fmt), "%s: %s\n", cfg->filename, format);
	else
		snprintf(fmt, sizeof(fmt), "%s\n", format);
	vsnprintf(buf, sizeof(buf), fmt, args);

	logit(LOG_ERR, 0, "%s", buf);
}

static char *get_string(cfg_t *cfg, const char *key)
{
	char *str;

	str = cfg_getstr(cfg, key);
	if (str)
		return strdup(str);

	return NULL;
}

/* Replace *dst with val when the file set the key (val != NULL), freeing
 * the baseline copy; otherwise keep the command-line value. */
static void set_string(char **dst, char *val)
{
	if (val) {
		free(*dst);
		*dst = val;
	}
}

/* Append the values of list-key @key to @list, after the @pos entries it
 * already holds (e.g. from the command line), and return the new length. */
static size_t get_list(cfg_t *cfg, const char *key, char **list, size_t len, size_t pos)
{
	size_t i;

	for (i = 0; i < cfg_size(cfg, key) && pos < len; i++) {
		char *str;

		str = cfg_getnstr(cfg, key, i);
		if (str)
			list[pos++] = strdup(str);
	}

	return pos;
}

/*
 * The values given on the command line, snapshot before the first file
 * parse.  read_config() can then recompute the effective config as the
 * baseline plus the file on every (re)load, instead of layering each
 * reload onto the previous result -- so a key deleted from the file
 * reverts to its command-line value, and lists do not keep growing.
 *
 * The baseline holds the original argv/strdup pointers, which live for
 * the lifetime of the process; it is never freed.  The effective globals,
 * in contrast, are always heap copies owned here and freed on each reload.
 */
static struct baseline {
	int         captured;
	char       *location, *contact, *description, *community, *vendor;
	int         auth, timeout;
	char       *disk[MAX_NR_DISKS];        size_t ndisk;
	char       *iface[MAX_NR_INTERFACES];  size_t niface;
	inet_addr_t trap[MAX_NR_TRAPS];        size_t ntrap;
} base;
static int applied;

static void capture_baseline(void)
{
	size_t i;

	base.location    = g_location;
	base.contact     = g_contact;
	base.description = g_description;
	base.community   = g_community;
	base.vendor      = g_vendor;
	base.auth        = g_auth;
	base.timeout     = g_timeout;

	for (i = 0; i < g_disk_list_length; i++)
		base.disk[i] = g_disk_list[i];
	base.ndisk = g_disk_list_length;

	for (i = 0; i < g_interface_list_length; i++)
		base.iface[i] = g_interface_list[i];
	base.niface = g_interface_list_length;

	for (i = 0; i < g_trap_dst_len; i++)
		base.trap[i] = g_trap_dst[i];
	base.ntrap = g_trap_dst_len;

	base.captured = 1;
}

static char *dup_or_null(const char *str)
{
	return str ? strdup(str) : NULL;
}

/* Reset the effective config to the command-line baseline, freeing the
 * heap copies left by the previous (re)load. */
static void apply_baseline(void)
{
	size_t i;

	if (applied) {
		free(g_location);
		free(g_contact);
		free(g_description);
		free(g_community);
		free(g_vendor);
		for (i = 0; i < g_disk_list_length; i++)
			free(g_disk_list[i]);
		for (i = 0; i < g_interface_list_length; i++)
			free(g_interface_list[i]);
	}

	g_location    = dup_or_null(base.location);
	g_contact     = dup_or_null(base.contact);
	g_description = dup_or_null(base.description);
	g_community   = dup_or_null(base.community);
	g_vendor      = dup_or_null(base.vendor);
	g_auth        = base.auth;
	g_timeout     = base.timeout;

	for (i = 0; i < base.ndisk; i++)
		g_disk_list[i] = strdup(base.disk[i]);
	g_disk_list_length = base.ndisk;

	for (i = 0; i < base.niface; i++)
		g_interface_list[i] = strdup(base.iface[i]);
	g_interface_list_length = base.niface;

	for (i = 0; i < base.ntrap; i++)
		g_trap_dst[i] = base.trap[i];
	g_trap_dst_len = base.ntrap;

	applied = 1;
}

int read_config(char *file)
{
	unsigned int i;
	char *str;
	int rc = 0;

	/* Effective config always starts from the command-line baseline; the
	 * file is then overlaid.  This makes the function idempotent, so a
	 * SIGHUP reload recomputes from scratch instead of stacking onto the
	 * previous result. */
	if (!base.captured)
		capture_baseline();
	apply_baseline();

	if (access(file, F_OK))
		return 0;		/* no file: the baseline stands */

	{
	cfg_opt_t ethtool_opts[] = {
		CFG_STR("rx_bytes", NULL, CFGF_NONE),
		CFG_STR("rx_mc_packets", NULL, CFGF_NONE),
		CFG_STR("rx_bc_packets", NULL, CFGF_NONE),
		CFG_STR("rx_packets", NULL, CFGF_NONE),
		CFG_STR("rx_errors", NULL, CFGF_NONE),
		CFG_STR("rx_drops", NULL, CFGF_NONE),
		CFG_STR("tx_bytes", NULL, CFGF_NONE),
		CFG_STR("tx_mc_packets", NULL, CFGF_NONE),
		CFG_STR("tx_bc_packets", NULL, CFGF_NONE),
		CFG_STR("tx_packets", NULL, CFGF_NONE),
		CFG_STR("tx_errors", NULL, CFGF_NONE),
		CFG_STR("tx_drops", NULL, CFGF_NONE),
		CFG_END()
	};
	/* authentication and timeout default to the baseline value just
	 * restored above, so an unset key keeps the command-line value. */
	cfg_opt_t opts[] = {
		CFG_STR ("location", NULL, CFGF_NONE),
		CFG_STR ("contact", NULL, CFGF_NONE),
		CFG_STR ("description", NULL, CFGF_NONE),
		CFG_BOOL("authentication", g_auth, CFGF_NONE),
		CFG_STR ("community", NULL, CFGF_NONE),
		CFG_INT ("timeout", g_timeout, CFGF_NONE),
		CFG_STR ("vendor", NULL, CFGF_NONE),
		CFG_STR_LIST("disk-table", NULL, CFGF_NONE),
		CFG_STR_LIST("iface-table", NULL, CFGF_NONE),
		CFG_STR_LIST("trap-table", NULL, CFGF_NONE),
		CFG_SEC("ethtool", ethtool_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
		CFG_END()
	};

	cfg = cfg_init(opts, CFGF_NONE);
	if (!cfg) {
		logit(LOG_ERR, errno, "Failed initializing configuration file parser");
		return 1;
	}

	/* Custom logging, rather than default Confuse stderr logging */
	cfg_set_error_function(cfg, conf_errfunc);

	rc = cfg_parse(cfg, file);
	switch (rc) {
	case CFG_FILE_ERROR:
		logit(LOG_ERR, 0, "Cannot read configuration file %s", file);
		goto error;

	case CFG_PARSE_ERROR:
		logit(LOG_ERR, 0, "Parse error in %s", file);
		goto error;

	case CFG_SUCCESS:
		break;
	}

	/* Scalars: a key present in the file overrides the baseline. */
	set_string(&g_location,    get_string(cfg, "location"));
	set_string(&g_contact,     get_string(cfg, "contact"));
	set_string(&g_description, get_string(cfg, "description"));
	set_string(&g_community,   get_string(cfg, "community"));
	set_string(&g_vendor,      get_string(cfg, "vendor"));

	g_auth        = cfg_getbool(cfg, "authentication");
	g_timeout     = cfg_getint(cfg, "timeout");

	/* Lists combine: append the file's entries to those from the command
	 * line (-d/-i/-T), rather than replacing them. */
	g_disk_list_length      = get_list(cfg, "disk-table",  g_disk_list,      NELEMS(g_disk_list),      g_disk_list_length);
	g_interface_list_length = get_list(cfg, "iface-table", g_interface_list, NELEMS(g_interface_list), g_interface_list_length);

	for (i = 0; i < cfg_size(cfg, "trap-table") && g_trap_dst_len < MAX_NR_TRAPS; i++) {
		str = cfg_getnstr(cfg, "trap-table", i);

		if (str && inet_pton2(str, 162, &g_trap_dst[g_trap_dst_len]) == 0)
			g_trap_dst_len++;
		else if (str)
			logit(LOG_ERR, 0, "Invalid trap address '%s'", str);
	}

	ethtool_xlate_cfg(cfg);

error:
	cfg_free(cfg);
	}

	return rc;
}
