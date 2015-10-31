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



#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

#include "mini_snmpd.h"



int read_file(const char *filename, char *buffer, size_t size)
{
	FILE *fp;
	size_t rv;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		lprintf(LOG_WARNING, "could not open %s: %m\n", filename);
		return -1;
	}
	rv = fread(buffer, 1, size - 1, fp);
	if (rv == 0) {
		lprintf(LOG_WARNING, "could not read %s: %m\n", filename);
		fclose(fp);
		return -1;
	}
	buffer[rv] = '\0';
	if (fclose(fp) == -1) {
		lprintf(LOG_WARNING, "could not close %s: %m\n", filename);
	}
	return 0;
}

unsigned int read_value(const char *buffer, const char *prefix)
{
	buffer = strstr(buffer, prefix);
	if (buffer != NULL) {
		buffer += strlen(prefix);
		while (isspace(*buffer)) {
			buffer++;
		}
		return (*buffer != '\0') ? strtoul(buffer, NULL, 0) : 0;
	} else {
		return 0;
	}
}

void read_values(const char *buffer, const char *prefix, unsigned int *values, int count)
{
	int i;

	buffer = strstr(buffer, prefix);
	if (buffer != NULL) {
		buffer += strlen(prefix);
		for (i = 0; i < count; i++) {
			while (isspace(*buffer)) {
				buffer++;
			}
			if (*buffer != '\0') {
				values[i] = strtoul(buffer, (char **)&buffer, 0);
			} else {
				values[i] = 0;
			}
		}
	} else {
		memset(values, 0, count * sizeof (unsigned int));
	}
}

int ticks_since(const struct timeval *tv_last, struct timeval *tv_now)
{
	float ticks;

	if (gettimeofday(tv_now, NULL) == -1) {
		lprintf(LOG_WARNING, "could not get ticks: %m\n");
		return -1;
	} else if (tv_now->tv_sec < tv_last->tv_sec
		|| (tv_now->tv_sec == tv_last->tv_sec && tv_now->tv_usec < tv_last->tv_usec)) {
		lprintf(LOG_WARNING, "could not get ticks: time running backwards\n");
		return -1;
	} else {
		ticks = (float)(tv_now->tv_sec - 1 - tv_last->tv_sec) * 100.0
			+ (float)((tv_now->tv_usec + 1000000 - tv_last->tv_usec) / 10000);
#ifdef DEBUG
		lprintf(LOG_DEBUG, "seconds since last update: %.2f\n", ticks / 100);
#endif
		if (ticks < INT_MIN) {
			return INT_MIN;
		} else if (ticks > INT_MAX) {
			return INT_MAX;
		} else {
			return ticks;
		}
	}
}

void dump_packet(const client_t *client)
{
	struct in6_addr client_addr;
	char straddr[INET6_ADDRSTRLEN];
	char buffer[BUFSIZ];
	int len;
	int i;

	client_addr = client->addr;
	len = 0;
	for (i = 0; i < client->size; i++) {
		len += snprintf(buffer + len, sizeof (buffer) - len,
			i ? " %02X" : "%02X", client->packet[i]);
		if (len >= sizeof (buffer)) {
			break;
		}
	}
	inet_ntop(AF_INET6, &client_addr, straddr, sizeof(straddr));
	lprintf(LOG_DEBUG, "%s %u bytes %s %s:%d (%s)\n",
		client->outgoing ? "transmitted" : "received", (int) client->size,
		client->outgoing ? "to" : "from", straddr,
		ntohs(client->port), buffer);
}

void dump_mib(const value_t *value, int size)
{
	char buffer[BUFSIZ];
	int i;

	for (i = 0; i < size; i++) {
		if (snmp_element_as_string(&value[i].data, buffer, sizeof (buffer)) == -1) {
			strcpy(buffer, "?");
		}
		lprintf(LOG_DEBUG, "mib entry[%d]: oid='%s', max_length=%d, data='%s'\n",
			i, oid_ntoa(&value[i].oid), value[i].data.max_length, buffer);
	}
}

void dump_response(const response_t *response)
{
	char buffer[MAX_PACKET_SIZE];
	int i;

	lprintf(LOG_DEBUG, "response: status=%d, index=%d, nr_entries=%d\n",
		response->error_status, response->error_index, response->value_list_length);
	for (i = 0; i < response->value_list_length; i++) {
		if (snmp_element_as_string(&response->value_list[i].data, buffer, sizeof (buffer)) == -1) {
			strcpy(buffer, "?");
		}
		lprintf(LOG_DEBUG, "response: entry[%d]='%s','%s'\n", i, oid_ntoa(&response->value_list[i].oid), buffer);
	}
}

char *oid_ntoa(const oid_t *oid)
{
	static char buffer[MAX_NR_SUBIDS * 10 + 2];
	int len;
	int i;

	buffer[0] = '\0';
	len = 0;
	for (i = 0; i < oid->subid_list_length; i++) {
		len += snprintf(buffer + len, sizeof (buffer) - len, ".%d", oid->subid_list[i]);
		if (len >= sizeof (buffer)) {
			break;
		}
	}
	return buffer;
}

oid_t *oid_aton(const char *str)
{
	static oid_t oid;
	char *ptr;

	oid.subid_list_length = 0;
	ptr = (char *)str;
	while (*ptr != '\0') {
		if (oid.subid_list_length >= MAX_NR_SUBIDS) {
			return NULL;
		}
		if (*ptr != '.') {
			return NULL;
		}
		ptr++;
		if (*ptr == '\0') {
			return NULL;
		}
		oid.subid_list[oid.subid_list_length++] = strtoul(ptr, &ptr, 0);
	}
	if (oid.subid_list_length < 2
		|| (oid.subid_list[0] * 40 + oid.subid_list[1]) > 0xFF) {
		return NULL;
	}
	return &oid;
}

int oid_cmp(const oid_t *oid1, const oid_t *oid2)
{
	int subid1;
	int subid2;
	int i;

	for (i = 0; i < MAX_NR_OIDS; i++) {
		subid1 = (oid1->subid_list_length > i) ? oid1->subid_list[i] : -1;
		subid2 = (oid2->subid_list_length > i) ? oid2->subid_list[i] : -1;
		if (subid1 == -1 && subid2 == -1) {
			return 0;
		} else if (subid1 > subid2) {
			return 1;
		} else if (subid1 < subid2) {
			return -1;
		}
	}
	return 0;
}

int split(const char *str, char *delim, char **list, int max_list_length)
{
	char buffer[BUFSIZ];
	int list_length;
	char *ptr;

	snprintf(buffer, sizeof (buffer), "%s", str);
	list_length = 0;
	for (ptr = strtok(buffer, delim); ptr != NULL; ptr = strtok(NULL, delim)) {
		if (list_length < max_list_length) {
			list[list_length++] = strdup(ptr);
		}
	}
	return list_length;
}

client_t *find_oldest_client(void)
{
	time_t timestamp;
	int pos;
	int i;

	timestamp = (time_t)LONG_MAX;
	pos = -1;
	for (i = 0; i < g_tcp_client_list_length; i++) {
		if (timestamp > g_tcp_client_list[i]->timestamp) {
			timestamp = g_tcp_client_list[i]->timestamp;
			pos = i;
		}
	}
	return (pos != -1) ? g_tcp_client_list[i] : NULL;
}

#ifdef __DEMO__
void get_demoinfo(demoinfo_t *demoinfo)
{
	static int did_init = 0;

	if (did_init == 0) {
		srand(time(NULL));
		did_init = 1;
	}
	demoinfo->random_value_1 = rand();
	demoinfo->random_value_2 = rand();
}
#endif



/* vim: ts=4 sts=4 sw=4 nowrap
 */
