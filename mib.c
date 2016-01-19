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
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>		/* intptr_t/uintptr_t */
#include <errno.h>
#include <time.h>

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

static const oid_t m_system_oid         = { { 1, 3, 6, 1, 2, 1, 1               }, 7, 8  };
static const oid_t m_if_1_oid           = { { 1, 3, 6, 1, 2, 1, 2               }, 7, 8  };
static const oid_t m_if_2_oid           = { { 1, 3, 6, 1, 2, 1, 2, 2, 1         }, 9, 10 };
static const oid_t m_host_oid           = { { 1, 3, 6, 1, 2, 1, 25, 1           }, 8, 9  };
static const oid_t m_memory_oid         = { { 1, 3, 6, 1, 4, 1, 2021, 4,        }, 8, 10 };
static const oid_t m_disk_oid           = { { 1, 3, 6, 1, 4, 1, 2021, 9, 1      }, 9, 11 };
static const oid_t m_load_oid           = { { 1, 3, 6, 1, 4, 1, 2021, 10, 1     }, 9, 11 };
static const oid_t m_cpu_oid            = { { 1, 3, 6, 1, 4, 1, 2021, 11        }, 8, 10 };
#ifdef CONFIG_ENABLE_DEMO
static const oid_t m_demo_oid           = { { 1, 3, 6, 1, 4, 1, 99999           }, 7, 10 };
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
	if (ticks_value & 0xFF000000)
		length = 4;
	else if (ticks_value & 0x00FF0000)
		length = 3;
	else if (ticks_value & 0x0000FF00)
		length = 2;
	else
		length = 1;

	*buffer++ = type;
	*buffer++ = length;
	while (length--)
		*buffer++ = (ticks_value >> (8 * length)) & 0xFF;

	data->encoded_length = buffer - data->buffer;

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

		case BER_TYPE_OCTET_STRING:
			data->max_length = 4;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_OID:
			data->max_length = MAX_NR_SUBIDS * 5 + 4;
			data->encoded_length = 0;
			data->buffer = allocate(data->max_length);
			break;

		case BER_TYPE_COUNTER:
		case BER_TYPE_GAUGE:
		case BER_TYPE_TIME_TICKS:
			data->max_length = sizeof(unsigned int) + 2;
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

		case BER_TYPE_OCTET_STRING:
			return encode_string(data, (const char *)arg);

		case BER_TYPE_OID:
			return encode_oid(data, oid_aton((const char *)arg));

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
	char hostname[MAX_STRING_SIZE];
	char name[16];
	size_t i;

	/* Determine some static values that are not known at compile-time */
	if (gethostname(hostname, sizeof(hostname)) == -1)
		hostname[0] = '\0';
	else if (hostname[sizeof(hostname) - 1] != '\0')
		hostname[sizeof(hostname) - 1] = '\0';

	/*
	 * The system MIB: basic info about the host (SNMPv2-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (mib_build_entry(&m_system_oid, 1, 0, BER_TYPE_OCTET_STRING, g_description ?: "") == -1 ||
	    mib_build_entry(&m_system_oid, 2, 0, BER_TYPE_OID,          g_vendor )           == -1 ||
	   !mib_alloc_entry(&m_system_oid, 3, 0, BER_TYPE_TIME_TICKS)                              ||
	    mib_build_entry(&m_system_oid, 4, 0, BER_TYPE_OCTET_STRING, g_contact ?: "")     == -1 ||
	    mib_build_entry(&m_system_oid, 5, 0, BER_TYPE_OCTET_STRING, hostname)            == -1 ||
	    mib_build_entry(&m_system_oid, 6, 0, BER_TYPE_OCTET_STRING, g_location ?: "")    == -1)
		return -1;

	/*
	 * The interface MIB: network interfaces (IF-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (g_interface_list_length > 0) {
		if (mib_build_entry(&m_if_1_oid, 1, 0, BER_TYPE_INTEGER, (const void *)(intptr_t)g_interface_list_length) == -1)
			return -1;

		/* ifIndex -- XXX: Should be system ifindex! */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 1, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)(i + 1)) == -1)
				return -1;
		}

		/* ifDescription */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 2, i + 1, BER_TYPE_OCTET_STRING, g_interface_list[i]) == -1)
				return -1;
		}

		/* ifType: ENUM, ethernetCsmacd(6) <-- recommended for all types of Ethernets */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 3, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)6) == -1)
				return -1;
		}

		/* ifMtu */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 4, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)1500) == -1)
				return -1;
		}

		/* ifSpeed (in bps) */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 5, i + 1, BER_TYPE_GAUGE, (const void *)(intptr_t)1000000000) == -1)
				return -1;
		}

		/* ifPhysAddress */
		for (i = 0; i < g_interface_list_length; i++) {
			unsigned char mac[] = { 0xc0, 0xff, 0xee, 0xde, 0xad, i + 1, 0x00 };

			if (mib_build_entry(&m_if_2_oid, 6, i + 1, BER_TYPE_OCTET_STRING, mac) == -1)
				return -1;
		}

		/* ifAdminStatus: up(1), down(2), testing(3) */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 7, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)1) == -1)
				return -1;
		}

		/* ifOperStatus: up(1), down(2), testing(3), unknown(4), dormant(5), notPresent(6), lowerLayerDown(7) */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 8, i + 1, BER_TYPE_INTEGER, (const void *)(intptr_t)1) == -1)
				return -1;
		}

		/* ifLastChange */
		for (i = 0; i < g_interface_list_length; i++) {
			if (mib_build_entry(&m_if_2_oid, 9, i + 1, BER_TYPE_TIME_TICKS, (const void *)(intptr_t)0) == -1)
				return -1;
		}

		if (mib_build_entries(&m_if_2_oid, 10, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 11, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 13, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 14, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 16, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 17, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 19, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1 ||
		    mib_build_entries(&m_if_2_oid, 20, 1, g_interface_list_length, BER_TYPE_COUNTER) == -1)
			return -1;
	}

	/*
	 * The host MIB: additional host info (HOST-RESOURCES-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (!mib_alloc_entry(&m_host_oid, 1, 0, BER_TYPE_TIME_TICKS))
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

	/*
	 * The disk MIB: mounted partitions (UCD-SNMP-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
	if (g_disk_list_length > 0) {
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

	/* The demo MIB: two random integers
	 * Caution: on changes, adapt the corresponding mib_update() section too!
	 */
#ifdef CONFIG_ENABLE_DEMO
	if (!mib_alloc_entry(&m_demo_oid, 1, 0, BER_TYPE_INTEGER) ||
	    !mib_alloc_entry(&m_demo_oid, 2, 0, BER_TYPE_INTEGER))
		return -1;
#endif

	return 0;
}

int mib_update(int full)
{
	char nr[16];
	size_t i, pos;
	union {
		diskinfo_t diskinfo;
		loadinfo_t loadinfo;
		meminfo_t meminfo;
		cpuinfo_t cpuinfo;
		netinfo_t netinfo;
#ifdef CONFIG_ENABLE_DEMO
		demoinfo_t demoinfo;
#endif
	} u;

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
			get_netinfo(&u.netinfo);
			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 8, i + 1, &pos, BER_TYPE_INTEGER, (const void *)(intptr_t)u.netinfo.status[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 10, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.rx_bytes[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 11, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.rx_packets[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 13, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.rx_drops[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 14, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.rx_errors[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 16, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.tx_bytes[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 17, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.tx_packets[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 19, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.tx_drops[i]) == -1)
					return -1;
			}

			for (i = 0; i < g_interface_list_length; i++) {
				if (mib_update_entry(&m_if_2_oid, 20, i + 1, &pos, BER_TYPE_COUNTER, (const void *)(uintptr_t)u.netinfo.tx_errors[i]) == -1)
					return -1;
			}
		}
	}

	/*
	 * The host MIB: additional host info (HOST-RESOURCES-MIB.txt)
	 * Caution: on changes, adapt the corresponding mib_build() section too!
	 */
	if (mib_update_entry(&m_host_oid, 1, 0, &pos, BER_TYPE_TIME_TICKS, (const void *)(uintptr_t)get_system_uptime()) == -1)
		return -1;

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
		get_loadinfo(&u.loadinfo);
		for (i = 0; i < 3; i++) {
			snprintf(nr, sizeof(nr), "%d.%02d", u.loadinfo.avg[i] / 100, u.loadinfo.avg[i] % 100);
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
