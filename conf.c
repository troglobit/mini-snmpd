#include <errno.h>
#include <confuse.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "mini_snmpd.h"

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

	lprintf(LOG_ERR, "%s", buf);
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
	cfg_opt_t opts[] = {
		CFG_STR ("location", NULL, CFGF_NONE),
		CFG_STR ("contact", NULL, CFGF_NONE),
		CFG_STR ("description", NULL, CFGF_NONE),
		CFG_BOOL("authentication", g_auth, CFGF_NONE),
		CFG_STR ("community", NULL, CFGF_NONE),
		CFG_INT ("timeout", g_timeout, CFGF_NONE),
		CFG_STR ("vendor", VENDOR, CFGF_NONE),
		CFG_STR_LIST("disk-table", "/", CFGF_NONE),
		CFG_END()
	};

	if (access(file, F_OK))
		return 0;

	cfg = cfg_init(opts, CFGF_NONE);
	if (!cfg) {
		syslog(LOG_ERR, "Failed initializing configuration file parser: %s", strerror(errno));
		return 1;
	}

	/* Custom logging, rather than default Confuse stderr logging */
	cfg_set_error_function(cfg, conf_errfunc);

	rc = cfg_parse(cfg, file);
	switch (rc) {
	case CFG_FILE_ERROR:
		lprintf(LOG_ERR, "Cannot read configuration file %s\n", file);
		goto error;

	case CFG_PARSE_ERROR:
		lprintf(LOG_ERR, "Parse error in %s\n", file);
		goto error;

	case CFG_SUCCESS:
		break;
	}

	g_location    = get_string(cfg, "location");
	g_contact     = get_string(cfg, "contact");
	g_description = get_string(cfg, "description");

	g_disk_list_length = get_list(cfg, "disk-table", g_disk_list, NELEMS(g_disk_list));

	g_auth        = cfg_getbool(cfg, "authentication");
	g_community   = get_string(cfg, "community");
	g_timeout     = cfg_getint(cfg, "timeout");

	g_vendor      = get_string(cfg, "vendor");

error:
	cfg_free(cfg);
	return rc;
}
