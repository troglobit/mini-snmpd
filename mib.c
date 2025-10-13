/*
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 * Copyright (C) 2011       Javier Palacios <javiplx@gmail.com>
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

#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>		/* intptr_t/uintptr_t */
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>

#include "mini_snmpd.h"

/*
 * Module variables
 *
 * To extend the MIB, add the definition of the SNMP table here. Note that the
 * variables use OIDs that have two subids more, which both are specified in the
 * mib_build_entry() and mib_build_entries() function calls. For example, the
 * system table uses the OID .1.3.6.1.2.1.1, the first system table variable,
 * system.sysDescr.0 (using OID .1.3.6.1.2.1.1.1.0) is appended to the MIB using
 * the function call mib_build_entry(&m_system_oid, 1, 0, ...).
 *
 * The first parameter is the array containing the list of subids (up to 14 here),
 * the next is the number of subids. The last parameter is the length that this
 * OID will need encoded in SNMP packets (including the BER type and length fields).
 */

static const oid_t m_system_oid         = { { 1, 3, 6, 1, 2, 1, 1               },  7, 8  };
static const oid_t m_if_1_oid           = { { 1, 3, 6, 1, 2, 1, 2               },  7, 8  };
static const oid_t m_if_2_oid           = { { 1, 3, 6, 1, 2, 1, 2, 2, 1         },  9, 10 };
static const oid_t m_ip_oid             = { { 1, 3, 6, 1, 2, 1, 4               },  7, 8  };
static const oid_t m_tcp_oid            = { { 1, 3, 6, 1, 2, 1, 6               },  7, 8  };
static const oid_t m_udp_oid            = { { 1, 3, 6, 1, 2, 1, 7               },  7, 8  };
static const oid_t m_host_oid           = { { 1, 3, 6, 1, 2, 1, 25, 1           },  8, 9  };
static const oid_t m_if_ext_oid         = { { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1     }, 10, 11 };
static const oid_t m_entity_oid         = { { 1, 3, 6, 1, 2, 1, 47, 1, 1, 1     }, 10, 11 }; 
static const oid_t m_wan_3g_oid         = { { 1, 3, 6, 1, 4, 1, 9, 9, 661, 1, 3, 4, 1, 1 }, 14, 15 };
static const oid_t m_wan_cell_oid       = { { 1, 3, 6, 1, 4, 1, 9, 9, 817, 1, 1, 1, 1, 1 }, 14, 15 };
static const oid_t m_memory_oid         = { { 1, 3, 6, 1, 4, 1, 2021, 4,        },  8, 10 };
static const oid_t m_disk_oid           = { { 1, 3, 6, 1, 4, 1, 2021, 9, 1      },  9, 11 };
static const oid_t m_load_oid           = { { 1, 3, 6, 1, 4, 1, 2021, 10, 1     },  9, 11 };
static const oid_t m_cpu_oid            = { { 1, 3, 6, 1, 4, 1, 2021, 11        },  8, 10 };

#ifdef CONFIG_ENABLE_DEMO
static const oid_t m_demo_oid           = { { 1, 3, 6, 1, 4, 1, 99999           },  7, 10 };
#endif

static const int m_load_avg_times[3] = { 1, 5, 15 };

static int oid_build  (oid_t *oid, const oid_t *prefix, int column, int row);
static int encode_oid_len (oid_t *oid);

static int data_alloc (data_t *data, int type);
static int data_set   (data_t *data, int type, const void *arg);


static int encode_integer(data_t *data, int integer_value)
{
	unsigned char *buffer;
	int length;

	buffer = data->buffer;
	if (integer_value < -8388608 || integer_value > 8388607)
		length = 4;
	else if (integer_value < -32768 || integer_value > 32767)
		length = 3;
	else if (integer_value < -128 || integer_value > 127)
		length = 2;
	else
		length = 1;

	*buffer++ = BER_TYPE_INTEGER;
	*buffer++ = length;
	while (length--)
		*buffer++ = ((unsigned int)integer_value >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_ipaddress(data_t *data, int ipaddress)
{
	unsigned char *buffer;
	int length = 4;

	buffer = data->buffer;

	*buffer++ = BER_TYPE_IP_ADDRESS;
	*buffer++ = length;
	while (length--)
		*buffer++ = (ipaddress >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_string(data_t *data, const char *string)
{
	size_t len;
	unsigned char *buffer;

	if (!string)
		return 2;

	len = strlen(string);
	if ((len + 4) > data->max_length) {
		data->max_length = len + 4;
		data->buffer = realloc(data->buffer, data->max_length);
		if (!data->buffer)
			return 2;
	}

	if (len > 0xFFFF) {
		lprintf(LOG_ERR, "Failed encoding '%s': string overflow\n", string);
		return -1;
	}

	buffer    = data->buffer;
	*buffer++ = BER_TYPE_OCTET_STRING;
	if (len > 255) {
		*buffer++ = 0x82;
		*buffer++ = (len >> 8) & 0xFF;
		*buffer++ = len & 0xFF;
	} else if (len > 127) {
		*buffer++ = 0x81;
		*buffer++ = len & 0xFF;
	} else {
		*buffer++ = len & 0x7F;
	}

	while (*string)
		*buffer++ = (unsigned char)(*string++);

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_string_mac(data_t *data, const char *string)
{
	const size_t len = 6; // length of MAC
	int ctr = len;
	unsigned char *buffer;

	if (!string)
		return 2;

	if ((len + 4) > data->max_length) {
		data->max_length = len + 4;
		data->buffer = realloc(data->buffer, data->max_length);
		if (!data->buffer)
			return 2;
	}

	buffer    = data->buffer;
	*buffer++ = BER_TYPE_OCTET_STRING;
	*buffer++ = len & 0x7F;

	while (--ctr >= 0)
		*buffer++ = (unsigned char)(*string++);

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_oid(data_t *data, const oid_t *oid)
{
	size_t i, len = 1;
	unsigned char *buffer = data->buffer;

	if (!oid)
		return 2;

	for (i = 2; i < oid->subid_list_length; i++) {
		if (oid->subid_list[i] >= (1 << 28))
			len += 5;
		else if (oid->subid_list[i] >= (1 << 21))
			len += 4;
		else if (oid->subid_list[i] >= (1 << 14))
			len += 3;
		else if (oid->subid_list[i] >= (1 << 7))
			len += 2;
		else
			len += 1;
	}

	if (len > 0xFFFF) {
		lprintf(LOG_ERR, "Failed encoding '%s': OID overflow\n", oid_ntoa(oid));
		return -1;
	}

	*buffer++ = BER_TYPE_OID;
	if (len > 0xFF) {
		*buffer++ = 0x82;
		*buffer++ = (len >> 8) & 0xFF;
		*buffer++ = len & 0xFF;
	} else if (len > 0x7F) {
		*buffer++ = 0x81;
		*buffer++ = len & 0xFF;
	} else {
		*buffer++ = len & 0x7F;
	}

	*buffer++ = oid->subid_list[0] * 40 + oid->subid_list[1];
	for (i = 2; i < oid->subid_list_length; i++) {
		if (oid->subid_list[i] >= (1 << 28))
			len = 5;
		else if (oid->subid_list[i] >= (1 << 21))
			len = 4;
		else if (oid->subid_list[i] >= (1 << 14))
			len = 3;
		else if (oid->subid_list[i] >= (1 << 7))
			len = 2;
		else
			len = 1;

		while (len--) {
			if (len)
				*buffer++ = ((oid->subid_list[i] >> (7 * len)) & 0x7F) | 0x80;
			else
				*buffer++ = (oid->subid_list[i] >> (7 * len)) & 0x7F;
		}
	}

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_unsigned(data_t *data, int type, unsigned int ticks_value)
{
	unsigned char *buffer;
	int length;

	buffer = data->buffer;
	if (ticks_value & 0xFF800000)
		length = 4;
	else if (ticks_value & 0x007F8000)
		length = 3;
	else if (ticks_value & 0x00007F80)
		length = 2;
	else
		length = 1;

	/* check if the integer could be interpreted negative during a signed decode and prepend a zero-byte if necessary */
	if ((ticks_value >> (8 * (length - 1))) & 0x80) {
		length++;
	}

	*buffer++ = type;
	*buffer++ = length;

	if (length == 5) {
		length--;
		*buffer++ = 0;
	}

	while (length--)
		*buffer++ = (ticks_value >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int encode_unsigned64(data_t *data, int type, uint64_t ticks_value)
{
	unsigned char *buffer;
	int length;

	buffer = data->buffer;
	if (ticks_value & 0xFF80000000000000ULL)
		length = 8;
	else if (ticks_value & 0x007F800000000000ULL)
		length = 7;
	else if (ticks_value & 0x00007F8000000000ULL)
		length = 6;
	else if (ticks_value & 0x0000007F80000000ULL)
		length = 5;
	else if (ticks_value & 0x000000007F800000ULL)
		length = 4;
	else if (ticks_value & 0x00000000007F8000ULL)
		length = 3;
	else if (ticks_value & 0x0000000000007F80ULL)
		length = 2;
	else
		length = 1;

	/* check if the integer could be interpreted negative during a signed decode and prepend a zero-byte if necessary */
	if ((ticks_value >> (8 * (length - 1))) & 0x80) {
		length++;
	}

	*buffer++ = type;
	*buffer++ = length;

	if (length == 9) {
		length--;
		*buffer++ = 0;
	}

	while (length--)
		*buffer++ = (ticks_value >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

	return 0;
}

static int mib_build_ip_entry(const oid_t *prefix, int type, const void *arg)
{
	int ret;
	value_t *value;
	const char *msg = "Failed creating MIB entry";
	const char *msg2 = "Failed assigning value to OID";

	/* Create a new entry in the MIB table */
	if (g_mib_length >= MAX_NR_VALUES) {
		lprintf(LOG_ERR, "%s '%s': table overflow\n", msg, oid_ntoa(prefix));
		return -1;
	}

	value = &g_mib[g_mib_length++];
	memcpy(&value->oid, prefix, sizeof(value->oid));

	ret  = encode_oid_len(&value->oid);
	ret += data_alloc(&value->data, type);
	if (ret) {
		lprintf(LOG_ERR, "%s '%s': unsupported type %d\n", msg,
			oid_ntoa(&value->oid), type);
		return -1;
	}

	ret = data_set(&value->data, type, arg);
	if (ret) {
		if (ret == 1)
			lprintf(LOG_ERR, "%s '%s': unsupported type %d\n", msg2, oid_ntoa(&value->oid), type);
		else if (ret == 2)
			lprintf(LOG_ERR, "%s '%s': invalid default value\n", msg2, oid_ntoa(&value->oid));

		return -1;
	}

	return 0;
}

static value_t *mib_alloc_entry(const oid_t *prefix, int column, int row, int type)
{
	int ret;
	value_t *value;
	const char *msg = "Failed creating MIB entry";

	/* Create a new entry in the MIB table */
	if (g_mib_length >= MAX_NR_VALUES) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': table overflow\n", msg, oid_ntoa(prefix), column, row);
		return NULL;
	}

	value = &g_mib[g_mib_length++];
	memcpy(&value->oid, prefix, sizeof(value->oid));

	/* Create the OID from the prefix, the column and the row */
	if (oid_build(&value->oid, prefix, column, row)) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': oid overflow\n", msg, oid_ntoa(prefix), column, row);
		return NULL;
	}

	ret  = encode_oid_len(&value->oid);
	ret += data_alloc(&value->data, type);
	if (ret) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': unsupported type %d\n", msg,
			oid_ntoa(&value->oid), column, row, type);
		return NULL;
	}

	return value;
}

static int mib_data_set(const oid_t *oid, data_t *data, int column, int row, int type, const void *arg);

static int mib_build_entry(const oid_t *prefix, int column, int row, int type, const void *arg)
{
	value_t *value;

	value = mib_alloc_entry(prefix, column, row, type);
	if (!value)
		return -1;

	return mib_data_set(&value->oid, &value->data, column, row, type, arg);
}

static int mib_data_set(const oid_t *oid, data_t *data, int column, int row, int type, const void *arg)
{
	int ret;
	const char *msg = "Failed assigning value to OID";

	ret = data_set(data, type, arg);
	if (ret) {
		if (ret == 1)
			lprintf(LOG_ERR, "%s '%s.%d.%d': unsupported type %d\n", msg, oid_ntoa(oid), column, row, type);
		else if (ret == 2)
			lprintf(LOG_ERR, "%s '%s.%d.%d': invalid default value\n", msg, oid_ntoa(oid), column, row);

		return -1;
	}

	return 0;
}

/* Create OID from the given prefix, column, and row */
static int oid_build(oid_t *oid, const oid_t *prefix, int column, int row)
{
	memcpy(oid, prefix, sizeof(*oid));

	if (oid->subid_list_length >= MAX_NR_SUBIDS)
		return -1;

	oid->subid_list[oid->subid_list_length++] = column;

	if (oid->subid_list_length >= MAX_NR_SUBIDS)
		return -1;

	oid->subid_list[oid->subid_list_length++] = row;

	return 0;
 }

/*
 * Calculate the encoded length of the created OID (note: first the length
 * of the subid list, then the length of the length/type header!)
 */
static int encode_oid_len(oid_t *oid)
{
	uint32_t len = 1;
	size_t i;

	for (i = 2; i < oid->subid_list_length; i++) {
		if (oid->subid_list[i] >= (1 << 28))
			len += 5;
		else if (oid->subid_list[i] >= (1 << 21))
			len += 4;
		else if (oid->subid_list[i] >= (1 << 14))
			len += 3;
		else if (oid->subid_list[i] >= (1 << 7))
			len += 2;
		else
			len += 1;
	}

	if (len > 0xFFFF) {
		lprintf(LOG_ERR, "Failed encoding '%s': OID overflow\n", oid_ntoa(oid));
		oid->encoded_length = -1;
		return -1;
	}

	if (len > 0xFF)
		len += 4;
	else if (len > 0x7F)
		len += 3;
	else
		len += 2;

	oid->encoded_length = (short)len;

	return 0;
}

/* Create a data buffer for the value depending on the type:
 *
 * - strings and oids are assumed to be static or have the maximum allowed length
 * - integers are assumed to be dynamic and don't have more than 32 bits
 */
static int data_alloc(data_t *data, int type)
{
	switch (type) {
		case BER_TYPE_INTEGER:
			data->max_length = sizeof(int) + 2;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_IP_ADDRESS:
			data->max_length = sizeof(uint32_t) + 2;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_OCTET_STRING:
			data->max_length = 16;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_OCTET_STRING_MAC:
			data->max_length = 10;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_OID:
			data->max_length = MAX_NR_SUBIDS * 5 + 4;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_COUNTER64:
			data->max_length = sizeof(uint64_t) + 3;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_COUNTER:
		case BER_TYPE_GAUGE:
		case BER_TYPE_TIME_TICKS:
			data->max_length = sizeof(unsigned int) + 3;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		default:
			return -1;
	}

	if (!data->buffer)
		return -1;

	data->buffer[0] = type;
	data->buffer[1] = 0;
	data->buffer[2] = 0;
	data->encoded_length = 3;

	return 0;
}

/*
 * Set data buffer to its new value, depending on the type.
 *
 * Note: we assume the buffer was allocated to hold the maximum possible
 *       value when the MIB was built.
 */
static int data_set(data_t *data, int type, const void *arg)
{
	/* Make sure to always initialize the buffer, in case of error below. */
	memset(data->buffer, 0, data->max_length);

	switch (type) {
		case BER_TYPE_INTEGER:
			return encode_integer(data, (intptr_t)arg);

		case BER_TYPE_IP_ADDRESS:
			return encode_ipaddress(data, (uintptr_t)arg);

		case BER_TYPE_OCTET_STRING:
			return encode_string(data, (const char *)arg);

		case BER_TYPE_OCTET_STRING_MAC:
			return encode_string_mac(data, (const char *)arg);

		case BER_TYPE_OID:
			return encode_oid(data, oid_aton((const char *)arg));

		case BER_TYPE_COUNTER64:
			return encode_unsigned64(data, type, *((uint64_t *)arg));

		case BER_TYPE_COUNTER:
		case BER_TYPE_GAUGE:
		case BER_TYPE_TIME_TICKS:
			return encode_unsigned(data, type, (uintptr_t)arg);

		default:
			break;	/* Fall through */
	}

	return 1;
}

static int mib_build_entries(const oid_t *prefix, int column, int row_from, int row_to, int type)
{
	int row;

	if (row_from > row_to)
		return 0;

	for (row = row_from; row <= row_to; row++) {
		if (!mib_alloc_entry(prefix, column, row, type))
			return -1;
	}

	return 0;
}

static int mib_update_entry(const oid_t *prefix, int column, int row, size_t *pos, int type, const void *arg)
{
	oid_t oid;
	value_t *value;
	const char *msg = "Failed updating OID";

	memcpy(&oid, prefix, sizeof(oid));

	/* Create the OID from the prefix, the column and the row */
	if (oid_build(&oid, prefix, column, row)) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': OID overflow\n", msg, oid_ntoa(prefix), column, row);
		return -1;
	}

	/* Search the MIB for the given OID beginning at the given position */
	value = mib_find(&oid, pos);
	if (!value) {
		lprintf(LOG_ERR, "%s '%s.%d.%d': OID not found\n", msg, oid_ntoa(prefix), column, row);
		return -1;
	}

	return mib_data_set(prefix, &value->data, column, row, type, arg);
}

struct in_sort {
	int pos;
	int idx;
	uint32_t addr;
} sorted_interface_list[MAX_NR_INTERFACES];
static size_t sorted_interface_list_size = 0;

int in_cmp(const void *p1, const void *p2)
{
	struct in_sort *a = (struct in_sort *)p1;
	struct in_sort *b = (struct in_sort *)p2;

	return (int)(a->addr - b->addr);
}

static void sort_addrs(void)
{
	size_t i, ctr = 0;

	for (i = 0; i < g_interface_list_length; i++) {
		if (g_ifaces_list[i].ip_address == 0 || g_ifaces_list[i].ip_mask == 0)
			continue;

		sorted_interface_list[ctr].pos  = i;
		sorted_interface_list[ctr].idx  = g_ifaces_list[i].index;
		sorted_interface_list[ctr].addr = g_ifaces_list[i].ip_address;
		ctr++;
	}

	sorted_interface_list_size = ctr;

	qsort(sorted_interface_list, ctr, sizeof(struct in_sort), in_cmp);
}

struct idx_sort {
	int pos;
	int idx;
} sorted_idx_interface_list[MAX_NR_INTERFACES];
static size_t sorted_idx_interface_list_size = 0;

int idx_cmp(const void *p1, const void *p2)
{
	struct idx_sort *a = (struct idx_sort *)p1;
	struct idx_sort *b = (struct idx_sort *)p2;

	return (int)(a->idx - b->idx);
}

static void sort_idxs(void)
{
	size_t i, ctr = 0;

	for (i = 0; i < g_interface_list_length; i++) {
		sorted_idx_interface_list[ctr].pos  = i;
		sorted_idx_interface_list[ctr].idx = g_ifaces_list[i].index;
		ctr++;
	}

	sorted_idx_interface_list_size = ctr;

	qsort(sorted_idx_interface_list, ctr, sizeof(struct idx_sort), idx_cmp);
}

static int mib_build_entries_sorted_idx(const oid_t *prefix,
	int column, int row_from, int row_to, int type)
{
	int row;

	if (row_from > row_to)
		return 0;

	for (row = row_from; row <= row_to; row++) {
		if (!mib_alloc_entry(prefix, column, sorted_idx_interface_list[row - 1].idx, type))
			return -1;
	}

	return 0;
}

static int mib_build_view(void)
{
	if ((g_ndmresp = ndm_core_request(g_ndmcore,
			NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
			"show snmp view")) == NULL) {
		lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));

		return -1;
	}

	if (!ndm_core_response_is_ok(g_ndmresp)) {
		ndm_core_response_free(&g_ndmresp);
		lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);

		return -1;
	}

	const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

	if (root == NULL) {
		ndm_core_response_free(&g_ndmresp);
		lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);

		return -1;
	}

	if (ndm_xml_node_type(root) == NDM_XML_NODE_TYPE_ELEMENT) {
		if (!strcmp(ndm_xml_node_name(root), "response")) {
			const struct ndm_xml_node_t* node = ndm_xml_node_first_child(root, NULL);

			while (node != NULL) {
				if (strcmp(ndm_xml_node_name(node), "view")) {
					node = ndm_xml_node_next_sibling(node, NULL);
					continue;
				}

				const struct ndm_xml_node_t* cnode = ndm_xml_node_first_child(node, NULL);
				bool filled = false;
				view_t* v = &g_view[g_view_length];

				while (cnode != NULL) {
					const char *cn = ndm_xml_node_name(cnode);
					const char *cv = ndm_xml_node_value(cnode);

					if (!strcmp(cn, "id")) {
						filled = true;
						strcpy(v->community, cv);
						cnode = ndm_xml_node_next_sibling(cnode, NULL);
						continue;
					}

					if (!strcmp(cn, "include")) {
						oid_t* oid = oid_aton(cv);

						if (oid == NULL) {
							ndm_core_response_free(&g_ndmresp);
							lprintf(LOG_ERR, "(%s:%d) invalid OID", __FILE__, __LINE__);

							return -1;
						}

						memcpy(&v->include_oid_list[v->include_oid_list_length], oid, sizeof(*oid));
						++v->include_oid_list_length;
						cnode = ndm_xml_node_next_sibling(cnode, NULL);
						continue;
					}

					if (!strcmp(cn, "exclude")) {
						oid_t* oid = oid_aton(cv);

						if (oid == NULL) {
							ndm_core_response_free(&g_ndmresp);
							lprintf(LOG_ERR, "(%s:%d) invalid OID", __FILE__, __LINE__);

							return -1;
						}

						memcpy(&v->exclude_oid_list[v->exclude_oid_list_length], oid, sizeof(*oid));
						++v->exclude_oid_list_length;
						cnode = ndm_xml_node_next_sibling(cnode, NULL);
						continue;
					}

					cnode = ndm_xml_node_next_sibling(cnode, NULL);
				}

				if (filled)
					++g_view_length;

				node = ndm_xml_node_next_sibling(node, NULL);
			}
		}
	}

	ndm_core_response_free(&g_ndmresp);

	return 0;
}

static int mib_build_system(void)
{
	char hostname[MAX_STRING_SIZE];
	int sysServices;

	if ((g_ndmresp = ndm_core_request(g_ndmcore,
			NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
			"show system")) == NULL) {
		lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));

		return -1;
	}

	if (!ndm_core_response_is_ok(g_ndmresp)) {
		ndm_core_response_free(&g_ndmresp);
		lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);

		return -1;
	}

	const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

	if (root == NULL) {
		ndm_core_response_free(&g_ndmresp);
		lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);

		return -1;
	}

	if (ndm_xml_node_type(root) == NDM_XML_NODE_TYPE_ELEMENT) {
		if (!strcmp(ndm_xml_node_name(root), "response")) {
			const struct ndm_xml_node_t* node = ndm_xml_node_first_child(root, NULL);

			while (node != NULL) {
				if (!strcmp(ndm_xml_node_name(node), "hostname")) {
					strncpy(hostname, ndm_xml_node_value(node), sizeof(hostname) - 2);
					hostname[sizeof(hostname) - 1] = '\0';

					break;
				}

				node = ndm_xml_node_next_sibling(node, NULL);
			}
		}
	}

	ndm_core_response_free(&g_ndmresp);

	/*
	 * The system MIB: basic info about the host (SNMPv2-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	sysServices = 1 /* Physical layer */ + 
				(1 << 1) /* L2 Datalink layer */ +
				(1 << 2) /* L3 IP Layer */ +
				(1 << 3) /* L4 TCP/UDP Layer */ +
				(1 << 6) /* Applications layer */;
	
	if (mib_build_entry(&m_system_oid, 1, 0, BER_TYPE_OCTET_STRING, g_description ?: "") == -1 ||
	    mib_build_entry(&m_system_oid, 2, 0, BER_TYPE_OID,          g_vendor )           == -1 ||
	   !mib_alloc_entry(&m_system_oid, 3, 0, BER_TYPE_TIME_TICKS)                              ||
	    mib_build_entry(&m_system_oid, 4, 0, BER_TYPE_OCTET_STRING, g_contact ?: "")     == -1 ||
	    mib_build_entry(&m_system_oid, 5, 0, BER_TYPE_OCTET_STRING, hostname)            == -1 ||
	    mib_build_entry(&m_system_oid, 6, 0, BER_TYPE_OCTET_STRING, g_location ?: "")    == -1 ||
	    mib_build_entry(&m_system_oid, 7, 0, BER_TYPE_INTEGER, (const void *)(intptr_t)sysServices) == -1)
		return -1;

	return 0;
}

static int mib_build_ifmib_ndmreq()
{
	if ((g_ndmresp = ndm_core_request(g_ndmcore,
			NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
			"show interface")) == NULL)
	{
		lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));
		ndm_core_response_free(&g_ndmresp);

		return -1;
	}

	if (!ndm_core_response_is_ok(g_ndmresp)) {
		lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);
		ndm_core_response_free(&g_ndmresp);

		return -1;
	}

	const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

	if (root == NULL) {
		lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);
		ndm_core_response_free(&g_ndmresp);

		return -1;
	}

	if (ndm_xml_node_type(root) != NDM_XML_NODE_TYPE_ELEMENT ||
		strcmp(ndm_xml_node_name(root), "response")) {
		lprintf(LOG_ERR, "(%s:%d) invalid ndm response", __FILE__, __LINE__);
		ndm_core_response_free(&g_ndmresp);

		return -1;
	}

	const struct ndm_xml_node_t* node = ndm_xml_node_first_child(root, NULL);

	while (node != NULL) {
		if (strcmp(ndm_xml_node_name(node), "interface")) {
			node = ndm_xml_node_next_sibling(node, NULL);

			continue;
		}

		g_interface_list_length++;

		if (ndm_xml_node_type(node) != NDM_XML_NODE_TYPE_ELEMENT) {
			node = ndm_xml_node_next_sibling(node, NULL);

			continue;
		}

		const struct ndm_xml_node_t* cnode = ndm_xml_node_first_child(node, NULL);
		int has_mac = 0;
		int has_ip = 0;
		int has_mask = 0;
		size_t j = g_interface_list_length - 1;

		g_ifaces_list[j].mtu = NDM_MIN_MTU_;
		g_ifaces_list[j].is_cellular = 0;

		const struct ndm_xml_attr_t* nameattr =  ndm_xml_node_first_attr(node, "name");

		if (nameattr != NULL &&
			!strcmp(ndm_xml_attr_name(nameattr), "name") &&
			strlen(ndm_xml_attr_value(nameattr)) > 0 )
			g_ifaces_list[j].name = strdup(ndm_xml_attr_value(nameattr));
		else
			g_ifaces_list[j].name = NULL;

		while (cnode != NULL) {
			const char *cn = ndm_xml_node_name(cnode);
			const char *cv = ndm_xml_node_value(cnode);

			if (!strcmp(cn, "id")) {
				g_ifaces_list[j].iface = strdup(cv);
				cnode = ndm_xml_node_next_sibling(cnode, NULL);
				continue;
			}

			if (!strcmp(cn, "description")) {
				g_ifaces_list[j].descr = strdup(cv);
				cnode = ndm_xml_node_next_sibling(cnode, NULL);
				continue;
			}

			if (!strcmp(cn, "type")) {
				if (!strcmp(cv, "Yota") ||
					!strcmp(cv, "UsbLte") ||
					!strcmp(cv, "UsbQmi")) {
					g_ifaces_list[j].is_cellular = 1;
				}

				if (!strcmp(cv, "FastEthernet") ||
					!strcmp(cv, "GigabitEthernet") ||
					!strcmp(cv, "AccessPoint") ||
					!strcmp(cv, "WifiStation") ||
					!strcmp(cv, "Port") ||
					!strcmp(cv, "AsixEthernet") ||
					!strcmp(cv, "Davicom") ||
					!strcmp(cv, "UsbLte") ||
					!strcmp(cv, "Yota") ||
					!strcmp(cv, "CdcEthernet") ||
					!strcmp(cv, "SSTPEthernet") ||
					!strcmp(cv, "RealtekEthernet") ||
					!strcmp(cv, "OpenVPN") )
				{
					g_ifaces_list[j].type = 6; // ethernetCsmacd(6),

					if (!strcmp(cv, "Port"))
						g_ifaces_list[j].mtu = NDM_ETH_MTU_;

				} else
				if (!strcmp(cv, "L2TP") ||
					!strcmp(cv, "PPTP") || 
					!strcmp(cv, "PPPoE") ||
					!strcmp(cv, "SSTP"))
				{
					g_ifaces_list[j].type = 23; // ppp(23),
				} else
				if (!strcmp(cv, "WiMax"))
				{
					g_ifaces_list[j].type = 237; // ieee80216WMAN (237),
				} else
				if (!strcmp(cv, "UsbDsl") ||
					!strcmp(cv, "Adsl") ||
					!strcmp(cv, "Dsl"))
				{
					g_ifaces_list[j].type = 238; // adsl2plus (238),
				} else
				if (!strcmp(cv, "Bridge"))
				{
					g_ifaces_list[j].type = 209; // bridge (209),
				} else
				if (!strcmp(cv, "Vlan"))
				{
					g_ifaces_list[j].type = 135; // l2vlan (135),
				} else
				if (!strcmp(cv, "WifiMaster"))
				{
					g_ifaces_list[j].type = 253; //capwapDot11Bss (253),
				} else
				{
					g_ifaces_list[j].type = 1; //other(1),
				}

				cnode = ndm_xml_node_next_sibling(cnode, NULL);
				continue;
			}

			if (!strcmp(cn, "mtu") &&
				g_ifaces_list[j].mtu == NDM_MIN_MTU_) {
				const int imtu = atoi(cv);

				if (imtu >= NDM_MIN_MTU_ && imtu <= NDM_MAX_MTU_)
					g_ifaces_list[j].mtu = imtu;

				cnode = ndm_xml_node_next_sibling(cnode, NULL);
				continue;
			}

			if (!strcmp(cn, "mac")) {
				has_mac = 1;
				g_ifaces_list[j].mac = strdup(cv);
				cnode = ndm_xml_node_next_sibling(cnode, NULL);
				continue;
			}

			if (!strcmp(cn, "address")) {
				struct in_addr addr;

				if (inet_pton(AF_INET, cv, &addr)) {
					has_ip = 1;
					g_ifaces_list[j].ip_address = ntohl(addr.s_addr);
				}

				cnode = ndm_xml_node_next_sibling(cnode, NULL);
				continue;
			}

			if (!strcmp(cn, "mask")) {
				struct in_addr mask;

				if (inet_pton(AF_INET, cv, &mask)) {
					has_mask = 1;
					g_ifaces_list[j].ip_mask = ntohl(mask.s_addr);
				}

				cnode = ndm_xml_node_next_sibling(cnode, NULL);
				continue;
			}

			cnode = ndm_xml_node_next_sibling(cnode, NULL);
		}

		if (has_mac == 0)
			g_ifaces_list[j].mac = strdup(NDM_EMPTY_MAC_);

		if (has_ip == 0)
			g_ifaces_list[j].ip_address = 0;

		if (has_mask == 0)
			g_ifaces_list[j].ip_mask = 0;

		node = ndm_xml_node_next_sibling(node, NULL);
	}

	ndm_core_response_free(&g_ndmresp);

	return 0;
}

#define SLI(i) (sorted_idx_interface_list[(i)].idx)
#define SLIP(i) (sorted_idx_interface_list[(i)].pos)
#define SLP(i) (g_ifaces_list[sorted_idx_interface_list[(i)].pos])

static int mib_build_ifmib(void)
{
	size_t i;

	/*
	 * The interface MIB: network interfaces (IF-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */

	for(i = 0; i < MAX_NR_INTERFACES; ++i) {
		g_ifaces_list[i].name = NULL;
		g_ifaces_list[i].iface = NULL;
		g_ifaces_list[i].descr = NULL;
		g_ifaces_list[i].index = 0;
	}

	g_interface_list_length = 1;
	g_ifaces_list[NDM_LOOPBACK_INDEX_].iface = strdup(NDM_LOOPBACK_IFACE_);
	g_ifaces_list[NDM_LOOPBACK_INDEX_].name = strdup("");
	g_ifaces_list[NDM_LOOPBACK_INDEX_].descr = strdup("");
	g_ifaces_list[NDM_LOOPBACK_INDEX_].type = 24; // softwareLoopback(24)
	g_ifaces_list[NDM_LOOPBACK_INDEX_].mtu = NDM_LOOPBACK_MTU_;
	g_ifaces_list[NDM_LOOPBACK_INDEX_].mac = strdup(NDM_EMPTY_MAC_);
	g_ifaces_list[NDM_LOOPBACK_INDEX_].ip_address = 0x7F000001;
	g_ifaces_list[NDM_LOOPBACK_INDEX_].ip_mask = 0xFF000000;

	if (mib_build_ifmib_ndmreq())
		return -1;

	if( g_interface_list_length == 0 ) {
		lprintf(LOG_ERR, "unable to acquire any interface");

		return -1;
	}

	for (i = 0; i < g_interface_list_length; ++i) {
		if (g_ifaces_list[i].iface == NULL) {
			lprintf(LOG_ERR, "unable to acquire interface %zu", i);

			return -1;
		}
	}

	if (g_ifmap != NULL) {
		char *token, *p, *copy;

		copy = p = strdup(g_ifmap);

		if (p == NULL) {
			lprintf(LOG_ERR, "unable to allocate memory");

			return -1;
		}

		while ((token = strsep(&p, ";"))) {
			char *t, *ifname = NULL, *idx = NULL;
			size_t ctr = 0;

			while ((t = strsep(&token, ":"))) {
				if (ctr > 1) {
					free(copy);
					lprintf(LOG_ERR, "invalid subnet format");

					return -1;
				}

				if (ctr == 0)
					ifname = t;
				else
					idx = t;

				ctr++;
			}

			if (ctr != 2) {
				free(copy);
				lprintf(LOG_ERR, "invalid format");

				return -1;
			}

			unsigned int ifidx = atol(idx);

			if (ifidx < 1) {
				free(copy);
				lprintf(LOG_ERR, "invalid index");

				return -1;
			}

			for (i = 0; i < g_interface_list_length; ++i) {
				if (!strcmp(g_ifaces_list[i].iface, ifname)) {
					g_ifaces_list[i].index = ifidx;
					break;
				}
			}
		}

		free(copy);
	}

	for (i = 0; i < g_interface_list_length; ++i) {
		if (g_ifaces_list[i].index > 0)
			continue;

		for (size_t j = i + 1; j < 3 * g_interface_list_length; ++j) {
			bool found = false;

			for (size_t k = 0; k < g_interface_list_length; ++k) {
				if (g_ifaces_list[k].index == j) {
					found = true;
					break;
				}
			}

			if (!found) {
				g_ifaces_list[i].index = j;
				break;
			}
		}
	}

	sort_idxs();

	lprintf(LOG_INFO, "build IF-MIB for %zu interfaces", g_interface_list_length);

	if (mib_build_entry(&m_if_1_oid, 1, 0, BER_TYPE_INTEGER, (const void *)(intptr_t)g_interface_list_length) == -1)
		return -1;

	/* ifIndex -- XXX: Should be system ifindex! */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 1, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)SLI(i)) == -1)
			return -1;
	}

	/* ifDescription */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 2, SLI(i), BER_TYPE_OCTET_STRING, SLP(i).iface) == -1)
			return -1;
	}

	/* ifType: ENUM  */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 3, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)SLP(i).type) == -1)
			return -1;
	}

	/* ifMtu */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 4, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)SLP(i).mtu) == -1)
			return -1;
	}

	/* ifSpeed (in bps) */
	for (i = 0; i < g_interface_list_length; i++) {
		const size_t type = SLP(i).type;

		if (type == 6 /* ethernet */)
		{
			/* 100 Mbps by default */
			if (mib_build_entry(&m_if_2_oid, 5, SLI(i), BER_TYPE_GAUGE, (const void *)(intptr_t)100000000) == -1)
				return -1;
		} else
		if( type == 23 /* ppp */ ||
			type == 237 /* wimax */ ||
			type == 238 /* adsl */ ||
			type == 209 /* bridge */ ||
			type == 135 /* vlan */ ||
			type == 253 /* wifimaster */ ||
			type == 24 /* softwareLoopback(24) */ ||
			type == 1 /* other */ )
		{
			/* unspecified */
			if (mib_build_entry(&m_if_2_oid, 5, SLI(i), BER_TYPE_GAUGE, (const void *)(intptr_t)0) == -1)
				return -1;
		} else
		{
			if (mib_build_entry(&m_if_2_oid, 5, SLI(i), BER_TYPE_GAUGE, (const void *)(intptr_t)0) == -1)
				return -1;
		}
	}

	/* ifPhysAddress */
	for (i = 0; i < g_interface_list_length; i++) {
		unsigned char mac[7] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		char *saveptr, *res, *ptr = SLP(i).mac;
		size_t j = 0;

		while( (res = strtok_r(ptr, ":", &saveptr)) && (j < 6) )
		{
			ptr = NULL;
			long int val = strtol(res, NULL, 16);

			if( val > 255 )
			{
				lprintf(LOG_ERR, "incorrect mac address: %s", SLP(i).mac);
			} else
			{
				mac[j] = val & 0xFF;
				++j;
			} 
		}

		if( j < 6 )
		{
			lprintf(LOG_ERR, "too short mac address: %s", SLP(i).mac);
		}

		if (mib_build_entry(&m_if_2_oid, 6, SLI(i), BER_TYPE_OCTET_STRING_MAC, mac) == -1)
			return -1;
	}

	/* ifAdminStatus: up(1), down(2), testing(3) */
	for (i = 0; i < g_interface_list_length; i++) {
		/* Down by default */
		if (mib_build_entry(&m_if_2_oid, 7, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)2) == -1)
			return -1;
	}

	/* ifOperStatus: up(1), down(2), testing(3), unknown(4), dormant(5), notPresent(6), lowerLayerDown(7) */
	for (i = 0; i < g_interface_list_length; i++) {
		/* Down by default */
		if (mib_build_entry(&m_if_2_oid, 8, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)2) == -1)
			return -1;
	}

	/* ifLastChange */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_2_oid, 9, SLI(i), BER_TYPE_TIME_TICKS, (const void *)(intptr_t)0) == -1)
			return -1;
	}

	if (mib_build_entries_sorted_idx(&m_if_2_oid, 10, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries_sorted_idx(&m_if_2_oid, 11, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries_sorted_idx(&m_if_2_oid, 13, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries_sorted_idx(&m_if_2_oid, 14, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries_sorted_idx(&m_if_2_oid, 16, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries_sorted_idx(&m_if_2_oid, 17, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries_sorted_idx(&m_if_2_oid, 19, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
	    mib_build_entries_sorted_idx(&m_if_2_oid, 20, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1)
		return -1;

	return 0;
}

#define SIPP(i) (g_ifaces_list[sorted_interface_list[(i)].pos])

static int mib_build_ip(void)
{
	size_t i;

	/*
	 * The IP-MIB.
	 */

	sort_addrs();

	if (!mib_alloc_entry(&m_ip_oid,  1, 0, BER_TYPE_INTEGER)   ||
	    !mib_alloc_entry(&m_ip_oid,  2, 0, BER_TYPE_INTEGER)   ||
	    !mib_alloc_entry(&m_ip_oid, 13, 0, BER_TYPE_INTEGER) )
		return -1;

	size_t j;
	oid_t m_ip_adentryaddr_oid    = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 0, 0, 0, 0 },  14, 15  };
	oid_t m_ip_adentryifidx_oid   = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 2, 0, 0, 0, 0 },  14, 15  };
	oid_t m_ip_adentrynetmask_oid = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 3, 0, 0, 0, 0 },  14, 15  };
	oid_t m_ip_adentrybcaddr_oid  = { { 1, 3, 6, 1, 2, 1, 4, 20, 1, 4, 0, 0, 0, 0 },  14, 15  };

	for (i = 0; i < sorted_interface_list_size; ++i) {
		const uint32_t ip = sorted_interface_list[i].addr;

		for (j = 0; j < 4; ++j) 
			m_ip_adentryaddr_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));

		if (mib_build_ip_entry(&m_ip_adentryaddr_oid, BER_TYPE_IP_ADDRESS,
			(const void *)(intptr_t)(SIPP(i).ip_address)) == -1) {
			return -1;
		}
	}

	for (i = 0; i < sorted_interface_list_size; ++i) {
		const uint32_t ip = sorted_interface_list[i].addr;

		for (j = 0; j < 4; ++j)
			m_ip_adentryifidx_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));

		if (mib_build_ip_entry(&m_ip_adentryifidx_oid, BER_TYPE_INTEGER,
			(const void *)(intptr_t)(sorted_interface_list[i].idx)) == -1) {
			return -1;
		}
	}

	for (i = 0; i < sorted_interface_list_size; ++i) {
		const uint32_t ip = sorted_interface_list[i].addr;

		for (j = 0; j < 4; ++j)
			m_ip_adentrynetmask_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));

		if (mib_build_ip_entry(&m_ip_adentrynetmask_oid, BER_TYPE_IP_ADDRESS,
			(const void *)(intptr_t)(SIPP(i).ip_mask)) == -1) {
			return -1;
		}
	}

	for (i = 0; i < sorted_interface_list_size; ++i) {
		const uint32_t ip = sorted_interface_list[i].addr;

		for (j = 0; j < 4; ++j)
			m_ip_adentrybcaddr_oid.subid_list[10 + j] = ((ip & (0xFF << ((3 - j) * 8))) >> ((3 - j) * 8));

		if (mib_build_ip_entry(&m_ip_adentrybcaddr_oid, BER_TYPE_INTEGER,
			(const void *)(intptr_t)(1)) == -1) {
			return -1;
		}
	}

	return 0;
}

static int mib_build_cell(void)
{
	size_t i;

	/*
	 * The CISCO-WAN-CELL-EXT-MIB and CISCO-WAN-3G-MIB.
	 */

	/* RSSI values */
	for (i = 0; i < g_interface_list_length; i++) {
		if (!SLP(i).is_cellular)
			continue;

		if (mib_build_entry(&m_wan_3g_oid, 1, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)-254) == -1) {
			return -1;
		}
	}

	/* RSRP values */
	for (i = 0; i < g_interface_list_length; i++) {
		if (!SLP(i).is_cellular)
			continue;

		if (mib_build_entry(&m_wan_cell_oid, 1, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)-254) == -1)
			return -1;
	}

	/* RSRQ values */
	for (i = 0; i < g_interface_list_length; i++) {
		if (!SLP(i).is_cellular)
			continue;

		if (mib_build_entry(&m_wan_cell_oid, 2, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)-254) == -1)
			return -1;
	}

	/* SNR values */
	for (i = 0; i < g_interface_list_length; i++) {
		if (!SLP(i).is_cellular)
			continue;

		if (mib_build_entry(&m_wan_cell_oid, 3, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)-254) == -1)
			return -1;
	}

	/* SINR values */
	for (i = 0; i < g_interface_list_length; i++) {
		if (!SLP(i).is_cellular)
			continue;

		if (mib_build_entry(&m_wan_cell_oid, 4, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)-254) == -1)
			return -1;
	}

	return 0;
}

static int mib_build_tcp(void)
{
	/*
	 * The TCP-MIB.
	 */

	if (!mib_alloc_entry(&m_tcp_oid,  1, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  2, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  3, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  4, 0, BER_TYPE_INTEGER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  5, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  6, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  7, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  8, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid,  9, 0, BER_TYPE_GAUGE)    ||
	    !mib_alloc_entry(&m_tcp_oid, 10, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 11, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 12, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 14, 0, BER_TYPE_COUNTER)  ||
	    !mib_alloc_entry(&m_tcp_oid, 15, 0, BER_TYPE_COUNTER) )
		return -1;

	return 0;
}

static int mib_build_udp(void)
{
	/*
	 * The UDP-MIB.
	 */

	if (!mib_alloc_entry(&m_udp_oid,  1, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  2, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  3, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  4, 0, BER_TYPE_COUNTER)   ||
	    !mib_alloc_entry(&m_udp_oid,  8, 0, BER_TYPE_COUNTER64) ||
	    !mib_alloc_entry(&m_udp_oid,  9, 0, BER_TYPE_COUNTER64) )
		return -1;

	return 0;
}

static int mib_build_ifxmib(void)
{
	size_t i;

	/*
	 * IF-MIB continuation
	 * ifXTable
	 */

	if (g_interface_list_length == 0)
		return 0;


	/* ifName */
	for (i = 0; i < g_interface_list_length; i++) {
		const char *ifname = NULL;

		if (SLP(i).name == NULL || !strcmp(SLP(i).name, "")) {
			ifname = SLP(i).iface;
		} else {
			ifname = SLP(i).name;
		}

		if (mib_build_entry(&m_if_ext_oid, 1, SLI(i), BER_TYPE_OCTET_STRING, ifname) == -1)
			return -1;
	}

	/* Just a counters */

	if (mib_build_entries_sorted_idx(&m_if_ext_oid, 2, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 3, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 4, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 5, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 6, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 7, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 8, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 9, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 10, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 11, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 12, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1 ||
		mib_build_entries_sorted_idx(&m_if_ext_oid, 13, 1, g_interface_list_length, BER_TYPE_COUNTER64) == -1)
		return -1;

	/* ifLinkUpDownTrapEnable */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_ext_oid, 14, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)2 /* disabled */) == -1)
			return -1;
	}

	/* ifHighSpeed */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_ext_oid, 15, SLI(i), BER_TYPE_GAUGE, (const void *)(intptr_t)0) == -1) {
			return -1;
		}
	}

	/* ifPromiscuousMode */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_ext_oid, 16, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)2 /* false */) == -1)
			return -1;
	}

	/* ifConnectorPresent */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_ext_oid, 17, SLI(i), BER_TYPE_INTEGER, (const void *)(intptr_t)1 /* true */) == -1)
			return -1;
	}

	/* ifAlias */
	for (i = 0; i < g_interface_list_length; i++) {
		const char *ifname = NULL;

		if (SLP(i).descr == NULL || !strcmp(SLP(i).descr, "")) {
			if (SLP(i).name == NULL || !strcmp(SLP(i).name, "")) {
				ifname = SLP(i).iface;
			} else {
				ifname = SLP(i).name;
			}
		} else {
			ifname = SLP(i).descr;
		}

		if (mib_build_entry(&m_if_ext_oid, 18, SLI(i), BER_TYPE_OCTET_STRING, ifname) == -1)
			return -1;
	}

	/* ifCounterDiscontinuityTime */
	for (i = 0; i < g_interface_list_length; i++) {
		if (mib_build_entry(&m_if_ext_oid, 19, SLI(i), BER_TYPE_TIME_TICKS, (const void *)(intptr_t)0) == -1)
			return -1;
	}

	return 0;
}

static int mib_build_disk(void)
{
	size_t i;

	/*
	 * The disk MIB: mounted partitions (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */

	/* Dynamically populate mounted disks list */
	g_disk_list_length = 0;

	{
		DIR* dirp = opendir(NDM_MOUNT_PATH_);

		if( dirp != NULL )
		{
			struct dirent* dire = NULL;
			while( (dire = readdir(dirp)) )
			{
				struct stat st;
				char pathbuf[512];

				if (dire->d_name[0] == '.') {
					continue;
				}

				snprintf(pathbuf, sizeof(pathbuf), NDM_MOUNT_PATH_ "/%s/", dire->d_name);

				if ( !stat(pathbuf, &st) )
				{
					if( S_ISDIR(st.st_mode) )
					{
						++g_disk_list_length;
						g_disk_list[g_disk_list_length - 1] = strdup(pathbuf);
					}
				}
			}

			closedir(dirp);
		}
	}

	if (g_disk_list_length > 0) {
		lprintf(LOG_INFO, "build UCD-SNMP-MIB for %zu disks", g_disk_list_length);

		for (i = 0; i < g_disk_list_length; i++) {
			if (mib_build_entry(&m_disk_oid, 1, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)(i + 1)) == -1)
				return -1;
		}

		for (i = 0; i < g_disk_list_length; i++) {
			if (mib_build_entry(&m_disk_oid, 2, i + 1, BER_TYPE_OCTET_STRING, g_disk_list[i]) == -1)
				return -1;
		}

		if (mib_build_entries(&m_disk_oid,  6, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid,  7, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid,  8, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid,  9, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1 ||
		    mib_build_entries(&m_disk_oid, 10, 1, g_disk_list_length, BER_TYPE_INTEGER) == -1)
			return -1;
	}

	return 0;
}

static int mib_build_load(void)
{
	char name[16];
	size_t i;

	/*
	 * The load MIB: CPU load averages (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	for (i = 0; i < 3; i++) {
		if (mib_build_entry(&m_load_oid, 1, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)(i + 1)) == -1)
			return -1;
	}

	for (i = 0; i < 3; i++) {
		snprintf(name, sizeof(name), "Load-%d", m_load_avg_times[i]);
		if (mib_build_entry(&m_load_oid, 2, i + 1, BER_TYPE_OCTET_STRING, name) == -1)
			return -1;
	}

	if (mib_build_entries(&m_load_oid, 3, 1, 3, BER_TYPE_OCTET_STRING) == -1)
		return -1;

	for (i = 0; i < 3; i++) {
		snprintf(name, sizeof(name), "%d", m_load_avg_times[i]);
		if (mib_build_entry(&m_load_oid, 4, i + 1, BER_TYPE_OCTET_STRING, name) == -1)
			return -1;
	}

	if (mib_build_entries(&m_load_oid, 5, 1, 3, BER_TYPE_INTEGER) == -1)
		return -1;

	/* The CPU MIB: CPU statistics (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (!mib_alloc_entry(&m_cpu_oid, 50, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 51, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 52, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 53, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 59, 0, BER_TYPE_COUNTER) ||
	    !mib_alloc_entry(&m_cpu_oid, 60, 0, BER_TYPE_COUNTER))
		return -1;

	return 0;
}


/* -----------------------------------------------------------------------------
 * Interface functions
 *
 * To extend the MIB, add the relevant mib_build_entry() calls (to add one MIB
 * variable) or mib_build_entries() calls (to add a column of a MIB table) in
 * the mib_build() function. Note that building the MIB must be done strictly in
 * ascending OID order or the SNMP getnext/getbulk functions will not work as
 * expected!
 *
 * To extend the MIB, add the relevant mib_update_entry() calls (to update one
 * MIB variable or one cell in a MIB table) in the mib_update() function. Note
 * that the MIB variables must be added in the correct order (i.e. ascending).
 * How to get the value for that variable is up to you, but bear in mind that
 * the mib_update() function is called between receiving the request from the
 * client and sending back the response; thus you should avoid time-consuming
 * actions!
 *
 * The variable types supported up to now are OCTET_STRING, INTEGER (32 bit
 * signed), COUNTER (32 bit unsigned), TIME_TICKS (32 bit unsigned, in 1/10s)
 * and OID.
 *
 * Note that the maximum number of MIB variables is restricted by the length of
 * the MIB array, (see mini_snmpd.h for the value of MAX_NR_VALUES).
 */

int mib_build(void)
{
	if (mib_build_view())
		return -1;

	if (mib_build_system())
		return -1;

	if (mib_build_ifmib())
		return -1;

	if (mib_build_ip())
		return -1;

	if (mib_build_tcp())
		return -1;

	if (mib_build_udp())
		return -1;

	/*
	 * The host MIB: additional host info (HOST-RESOURCES-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (!mib_alloc_entry(&m_host_oid, 1, 0, BER_TYPE_TIME_TICKS))
		return -1;

	if (mib_build_ifxmib())
		return -1;

	if (mib_build_entry(&m_entity_oid, 1, 11, BER_TYPE_OCTET_STRING, g_serial ?: "") == -1 ||
	    mib_build_entry(&m_entity_oid, 1, 12, BER_TYPE_OCTET_STRING, g_mfg ?: "") == -1 ||
	    mib_build_entry(&m_entity_oid, 1, 13, BER_TYPE_OCTET_STRING, g_model ?: "") == -1 ||
	    mib_build_entry(&m_entity_oid, 1, 19, BER_TYPE_OCTET_STRING, g_cid ?: "") == -1) {
		return -1;
	}

	if (mib_build_cell())
		return -1;

	/*
	 * The memory MIB: total/free memory (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (!mib_alloc_entry(&m_memory_oid,  5, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid,  6, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid, 13, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid, 14, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_memory_oid, 15, 0, BER_TYPE_INTEGER))
		return -1;

	if (mib_build_disk())
		return -1;

	if (mib_build_load())
		return -1;

	return 0;
}

int mib_update(int full)
{
	size_t i, pos;
	union {
		diskinfo_t diskinfo;
		loadinfo_t loadinfo;
		meminfo_t meminfo;
		ipinfo_t ipinfo;
		tcpinfo_t tcpinfo;
		udpinfo_t udpinfo;
		cpuinfo_t cpuinfo;
#ifdef CONFIG_ENABLE_DEMO
		demoinfo_t demoinfo;
#endif
	} u;
	netinfo_t netinfo;

	/* Begin searching at the first MIB entry */
	pos = 0;

	/*
	 * The system MIB: basic info about the host (SNMPv2-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (mib_update_entry(&m_system_oid, 3, 0, &pos, BER_TYPE_TIME_TICKS, (const void *)(uintptr_t)get_process_uptime()) == -1)
		return -1;

	/*
	 * The interface MIB: network interfaces (IF-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		if (g_interface_list_length > 0) {

			get_netinfo(&netinfo);

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 4, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)netinfo.mtu[SLIP(i)]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 5, SLI(i), &pos, BER_TYPE_GAUGE, (const void *)(intptr_t)netinfo.speed[SLIP(i)]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 7, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)netinfo.admin_status[SLIP(i)]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 8, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)netinfo.status[SLIP(i)]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 9, SLI(i), &pos, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)netinfo.last_change[SLIP(i)]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 10, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_bytes[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 11, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_packets[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 13, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_drops[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 14, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.rx_errors[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 16, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_bytes[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 17, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_packets[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 19, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_drops[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 20, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(netinfo.tx_errors[SLIP(i)] % UINT_MAX)) == -1)
					return -1;
			}
		}
	}

	/*
	 * IP-MIB
	 */

	if (full) {
		get_ipinfo(&u.ipinfo);

		if (mib_update_entry(&m_ip_oid,  1, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.ipinfo.ipForwarding)      == -1 ||
		    mib_update_entry(&m_ip_oid,  2, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.ipinfo.ipDefaultTTL)      == -1 ||
		    mib_update_entry(&m_ip_oid,  13, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.ipinfo.ipReasmTimeout)   == -1 )
		{
			return -1;
		}

	}

	/*
	 * TCP-MIB
	 */

	if (full) {
		get_tcpinfo(&u.tcpinfo);

		if (mib_update_entry(&m_tcp_oid,  1, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpRtoAlgorithm)   == -1 ||
		    mib_update_entry(&m_tcp_oid,  2, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpRtoMin)         == -1 ||
		    mib_update_entry(&m_tcp_oid,  3, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpRtoMax)         == -1 ||
		    mib_update_entry(&m_tcp_oid,  4, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.tcpinfo.tcpMaxConn)        == -1 ||
		    mib_update_entry(&m_tcp_oid,  5, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpActiveOpens)   == -1 ||
		    mib_update_entry(&m_tcp_oid,  6, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpPassiveOpens)  == -1 ||
		    mib_update_entry(&m_tcp_oid,  7, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpAttemptFails)  == -1 ||
		    mib_update_entry(&m_tcp_oid,  8, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpEstabResets)   == -1 ||
		    mib_update_entry(&m_tcp_oid,  9, 0, &pos, BER_TYPE_GAUGE, (const void *)(intptr_t)u.tcpinfo.tcpCurrEstab)        == -1 ||
		    mib_update_entry(&m_tcp_oid, 10, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpInSegs)        == -1 ||
		    mib_update_entry(&m_tcp_oid, 11, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpOutSegs)       == -1 ||
		    mib_update_entry(&m_tcp_oid, 12, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpRetransSegs)   == -1 ||
		    mib_update_entry(&m_tcp_oid, 14, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpInErrs)        == -1 ||
		    mib_update_entry(&m_tcp_oid, 15, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.tcpinfo.tcpOutRsts)       == -1)
			return -1;
	}

	/*
	 * UDP-MIB
	 */

	if (full) {
		get_udpinfo(&u.udpinfo);

		if (mib_update_entry(&m_udp_oid,  1, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(u.udpinfo.udpInDatagrams & 0xFFFFFFFF))   == -1 ||
		    mib_update_entry(&m_udp_oid,  2, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.udpinfo.udpNoPorts)                      == -1 ||
		    mib_update_entry(&m_udp_oid,  3, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.udpinfo.udpInErrors)                     == -1 ||
		    mib_update_entry(&m_udp_oid,  4, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)(u.udpinfo.udpOutDatagrams & 0xFFFFFFFF))  == -1 ||
		    mib_update_entry(&m_udp_oid,  8, 0, &pos, BER_TYPE_COUNTER64, (const void *)(&u.udpinfo.udpInDatagrams))                        == -1 ||
		    mib_update_entry(&m_udp_oid,  9, 0, &pos, BER_TYPE_COUNTER64, (const void *)(&u.udpinfo.udpOutDatagrams))                       == -1  )
			return -1;
	}

	/*
	 * The host MIB: additional host info (HOST-RESOURCES-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (mib_update_entry(&m_host_oid, 1, 0, &pos, BER_TYPE_TIME_TICKS, (const void *)(uintptr_t)get_system_uptime()) == -1)
		return -1;

	/*
	 * IF-MIB
	 * ifXTable
	 */

	if (full) {
		if (g_interface_list_length > 0) {
			uint64_t val = 0;

			for (i = 0; i < g_interface_list_length; i++) {
				const char *ifname = NULL;

				if (SLP(i).name == NULL || !strcmp(SLP(i).name, "")) {
					ifname = SLP(i).iface;
				} else {
					ifname = SLP(i).name;
				}

				if (mib_update_entry(&m_if_ext_oid, 1, SLI(i), &pos, BER_TYPE_OCTET_STRING, ifname) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.rx_mc_packets[SLIP(i)] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 2, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.rx_bc_packets[SLIP(i)] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 3, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.tx_mc_packets[SLIP(i)] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 4, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				unsigned int packets = netinfo.tx_bc_packets[SLIP(i)] % UINT_MAX;
				if (mib_update_entry(&m_if_ext_oid, 5, SLI(i), &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)packets) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_bytes[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 6, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_packets[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 7, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_mc_packets[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 8, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.rx_bc_packets[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 9, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_bytes[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 10, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_packets[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 11, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_mc_packets[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 12, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				val = (netinfo.tx_bc_packets[SLIP(i)] & 0xBFFFFFFFFFFFFFFFULL);
				if (mib_update_entry(&m_if_ext_oid, 13, SLI(i), &pos, BER_TYPE_COUNTER64, (const void *)(&val)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_ext_oid, 15, SLI(i), &pos, BER_TYPE_GAUGE, (const void *)(intptr_t)(netinfo.speed[SLIP(i)] / 1000000)) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				const int ifConnectorPresent = (netinfo.is_port[SLIP(i)] == 1 && netinfo.status[SLIP(i)] == 1) ? 1 : 2;

				if (mib_update_entry(&m_if_ext_oid, 17, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)ifConnectorPresent) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				const char *ifname = NULL;

				if (SLP(i).descr == NULL || !strcmp(SLP(i).descr, "")) {
					if (SLP(i).name == NULL || !strcmp(SLP(i).name, "")) {
						ifname = SLP(i).iface;
					} else {
						ifname = SLP(i).name;
					}
				} else {
					ifname = SLP(i).descr;
				}

				if (mib_update_entry(&m_if_ext_oid, 18, SLI(i), &pos, BER_TYPE_OCTET_STRING, ifname) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_ext_oid, 19, SLI(i), &pos, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)netinfo.discont_time[SLIP(i)]) == -1)
					return -1;
			}
		}
	}

	if (full && g_interface_list_length > 0) {
			for (i = 0; i < g_interface_list_length; i++) {
				if (!SLP(i).is_cellular)
					continue;

				if (mib_update_entry(&m_wan_3g_oid, 1, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)(netinfo.rssi[SLIP(i)])) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (!SLP(i).is_cellular)
					continue;

				if (mib_update_entry(&m_wan_cell_oid, 1, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)(netinfo.rsrp[SLIP(i)])) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (!SLP(i).is_cellular)
					continue;

				if (mib_update_entry(&m_wan_cell_oid, 2, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)(netinfo.rsrq[SLIP(i)])) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (!SLP(i).is_cellular)
					continue;

				if (mib_update_entry(&m_wan_cell_oid, 3, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)(netinfo.sinr[SLIP(i)])) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (!SLP(i).is_cellular)
					continue;

				if (mib_update_entry(&m_wan_cell_oid, 4, SLI(i), &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)(netinfo.sinr[SLIP(i)])) == -1)
					return -1;
			}
	}


	/*
	 * The memory MIB: total/free memory (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		get_meminfo(&u.meminfo);
		if (mib_update_entry(&m_memory_oid,  5, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.total)   == -1 ||
		    mib_update_entry(&m_memory_oid,  6, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.free)    == -1 ||
		    mib_update_entry(&m_memory_oid, 13, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.shared)  == -1 ||
		    mib_update_entry(&m_memory_oid, 14, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.buffers) == -1 ||
		    mib_update_entry(&m_memory_oid, 15, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.meminfo.cached)  == -1)
			return -1;
	}

	/*
	 * The disk MIB: mounted partitions (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		if (g_disk_list_length > 0) {
			get_diskinfo(&u.diskinfo);
			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 6, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.total[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 7, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.free[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 8, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.used[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 9, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.blocks_used_percent[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_disk_list_length; i++) {
				if (mib_update_entry(&m_disk_oid, 10, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.diskinfo.inodes_used_percent[i]) == -1)
					return -1;
			}
		}
	}

	/*
	 * The load MIB: CPU load averages (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		char nr[16];

		get_loadinfo(&u.loadinfo);
		for (i = 0; i < 3; i++) {
			snprintf(nr, sizeof(nr), "%u.%02u", u.loadinfo.avg[i] / 100, u.loadinfo.avg[i] % 100);
			if (mib_update_entry(&m_load_oid, 3, i + 1, &pos, BER_TYPE_OCTET_STRING, nr) == -1)
				return -1;
		}

		for (i = 0; i < 3; i++) {
			if (mib_update_entry(&m_load_oid, 5, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.loadinfo.avg[i]) == -1)
				return -1;
		}
	}

	/*
	 * The cpu MIB: CPU statistics (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (full) {
		get_cpuinfo(&u.cpuinfo);
		if (mib_update_entry(&m_cpu_oid, 50, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.user)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 51, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.nice)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 52, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.system) == -1 ||
		    mib_update_entry(&m_cpu_oid, 53, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.idle)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 59, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.irqs)   == -1 ||
		    mib_update_entry(&m_cpu_oid, 60, 0, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.cpuinfo.cntxts) == -1)
			return -1;
	}

	/*
	 * The demo MIB: two random integers (note: the random number is only
	 * updated every "g_timeout" seconds; if you want it updated every SNMP
	 * request, remove the enclosing "if" block).
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
#ifdef CONFIG_ENABLE_DEMO
	if (full) {
		get_demoinfo(&u.demoinfo);
		if (mib_update_entry(&m_demo_oid, 1, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.demoinfo.random_value_1) == -1 ||
		    mib_update_entry(&m_demo_oid, 2, 0, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.demoinfo.random_value_2) == -1)
			return -1;
	}
#endif

	return 0;
}

/* Find the OID in the MIB that is exactly the given one or a subid */
value_t *mib_find(const oid_t *oid, size_t *pos)
{
	while (*pos < g_mib_length) {
		value_t *curr = &g_mib[*pos];
		size_t len = oid->subid_list_length * sizeof(oid->subid_list[0]);

		if (curr->oid.subid_list_length >= oid->subid_list_length &&
		    !memcmp(curr->oid.subid_list, oid->subid_list, len))
			return curr;
		*pos = *pos + 1;
	}

	return NULL;
}

/* Find the OID in the MIB that is the one after the given one */
value_t *mib_findnext(const oid_t *oid)
{
	size_t pos;

	for (pos = 0; pos < g_mib_length; pos++) {
		if (oid_cmp(&g_mib[pos].oid, oid) > 0)
			return &g_mib[pos];
	}

	return NULL;
}

/* vim: ts=4 sts=4 sw=4 nowrap
 */
