/* .conf parser
 *
 * Copyright (C) 2018-2020  Joachim Nilsson <troglobit@gmail.com>
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

static size_t get_list(cfg_t *cfg, const char *key, char **list, size_t len)
{
	size_t i = 0;

	while (i < cfg_size(cfg, key)) {
		char *str;

		str = cfg_getnstr(cfg, key, i);
		if (str && i < len)
			list[i++] = strdup(str);
	}

	return i;
}

int read_config(char *file)
{
	int rc = 0;
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
	cfg_opt_t opts[] = {
		CFG_STR ("location", NULL, CFGF_NONE),
		CFG_STR ("contact", NULL, CFGF_NONE),
		CFG_STR ("description", NULL, CFGF_NONE),
		CFG_BOOL("authentication", g_auth, CFGF_NONE),
		CFG_STR ("community", NULL, CFGF_NONE),
		CFG_INT ("timeout", g_timeout, CFGF_NONE),
		CFG_STR ("vendor", VENDOR, CFGF_NONE),
		CFG_STR_LIST("disk-table", "/", CFGF_NONE),
		CFG_STR_LIST("iface-table", NULL, CFGF_NONE),
		CFG_SEC("ethtool", ethtool_opts, CFGF_MULTI | CFGF_TITLE | CFGF_NO_TITLE_DUPES),
		CFG_END()
	};

	if (access(file, F_OK))
		return 0;

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

	g_location    = get_string(cfg, "location");
	g_contact     = get_string(cfg, "contact");
	g_description = get_string(cfg, "description");

	g_disk_list_length = get_list(cfg, "disk-table", g_disk_list, NELEMS(g_disk_list));
	g_interface_list_length = get_list(cfg, "iface-table", g_interface_list, NELEMS(g_interface_list));

	g_auth        = cfg_getbool(cfg, "authentication");
	g_community   = get_string(cfg, "community");
	g_timeout     = cfg_getint(cfg, "timeout");

	g_vendor      = get_string(cfg, "vendor");

	ethtool_xlate_cfg(cfg);

error:
	cfg_free(cfg);
	return rc;
}
