/* SNMP protocol
 *
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 * Copyright (C) 2011       Javier Palacios <javiplx@gmail.com>
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

#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "mini-snmpd.h"

#define SNMP_VERSION_1_ERROR(resp, code, index) {			\
	(resp)->error_status = code;					\
	(resp)->error_index  = index;					\
	return 0;							\
}

#define SNMP_VERSION_2_ERROR(resp, req, index, err) {			\
	size_t len = (resp)->value_list_length;				\
	memcpy(&(resp)->value_list[len].oid, &(req)->oid_list[index],	\
	       sizeof((req)->oid_list[index]));				\
	memcpy(&(resp)->value_list[len].data, &err, sizeof(err));	\
	(resp)->value_list_length++;					\
	continue;							\
}

#define SNMP_GET_ERROR(resp, req, index, code, err, msg) {		\
	if ((req)->version == SNMP_VERSION_1)				\
		SNMP_VERSION_1_ERROR((resp), (code), (index));		\
									\
	if ((resp)->value_list_length < MAX_NR_VALUES)			\
		SNMP_VERSION_2_ERROR((resp), (req), (index), err); 	\
									\
	logit(LOG_ERR, 0, "%s", msg);					\
	return -1;							\
}

static const data_t m_null              = { (unsigned char *)"\x05\x00", 2, 2 };
static const data_t m_no_such_object    = { (unsigned char *)"\x80\x00", 2, 2 };
static const data_t m_no_such_instance  = { (unsigned char *)"\x81\x00", 2, 2 };
static const data_t m_end_of_mib_view   = { (unsigned char *)"\x82\x00", 2, 2 };


static int decode_len(const unsigned char *packet, size_t size, size_t *pos, int *type, size_t *len)
{
	size_t length_of_len;

	if (*pos >= size) {
		logit(LOG_DEBUG, 0, "underflow for element type");
		errno = EINVAL;
		return -1;
	}

	/* Fetch the ASN.1 element type (only subset of universal tags supported) */
	switch (packet[*pos]) {
	case BER_TYPE_BOOLEAN:
	case BER_TYPE_INTEGER:
	case BER_TYPE_BIT_STRING:
	case BER_TYPE_OCTET_STRING:
	case BER_TYPE_NULL:
	case BER_TYPE_OID:
	case BER_TYPE_SEQUENCE:
	case BER_TYPE_COUNTER:
	case BER_TYPE_GAUGE:
	case BER_TYPE_TIME_TICKS:
	case BER_TYPE_NO_SUCH_OBJECT:
	case BER_TYPE_NO_SUCH_INSTANCE:
	case BER_TYPE_END_OF_MIB_VIEW:
	case BER_TYPE_SNMP_GET:
	case BER_TYPE_SNMP_GETNEXT:
	case BER_TYPE_SNMP_RESPONSE:
	case BER_TYPE_SNMP_SET:
	case BER_TYPE_SNMP_GETBULK:
	case BER_TYPE_SNMP_INFORM:
	case BER_TYPE_SNMP_TRAP:
		*type = packet[*pos];
		*pos = *pos + 1;
		break;

	default:
		logit(LOG_DEBUG, 0, "unsupported element type %02X", packet[*pos]);
		errno = EINVAL;
		return -1;
	}

	if (*pos >= size) {
		logit(LOG_DEBUG, 0, "underflow for element length");
		errno = EINVAL;
		return -1;
	}

	/* Fetch the ASN.1 element length (only lengths up to 16 bit supported) */
	if (!(packet[*pos] & 0x80)) {
		*len = packet[*pos];
		*pos = *pos + 1;
	} else {
		length_of_len = packet[*pos] & 0x7F;
		if (length_of_len > 2) {
			logit(LOG_DEBUG, 0, "overflow for element length");
			errno = EINVAL;
			return -1;
		}

		*pos = *pos + 1;
		*len = 0;
		while (length_of_len--) {
			if (*pos >= size) {
				logit(LOG_DEBUG, 0, "underflow for element length");
				errno = EINVAL;
				return -1;
			}

			*len = (*len << 8) + packet[*pos];
			*pos = *pos + 1;
		}
	}

	return 0;
}

/* Fetch the value as unsigned integer (copy sign bit into all bytes first) */
static int decode_int(const unsigned char *packet, size_t size, size_t *pos, size_t len, int *value)
{
	unsigned int tmp;

	if (len > size || *pos >= (size - len + 1)) {
		logit(LOG_DEBUG, 0, "underflow for integer");
		errno = EINVAL;
		return -1;
	}

	memset(&tmp, (packet[*pos] & 0x80) ? 0xFF : 0x00, sizeof(tmp));
	while (len--) {
		tmp = (tmp << 8) | packet[*pos];
		*pos = *pos + 1;
	}
	*(int *)value = tmp;

	return 0;
}

/* Fetch the value as unsigned integer (copy sign bit into all bytes first) */
static int decode_cnt(const unsigned char *packet, size_t size, size_t *pos, size_t len, uint32_t *value)
{
	if (len > size || *pos >= (size - len + 1)) {
		logit(LOG_DEBUG, 0, "underflow for unsigned");
		errno = EINVAL;
		return -1;
	}

	*value = 0;
	while (len--) {
		*value = (*value << 8) | packet[*pos];
		*pos = *pos + 1;
	}

	return 0;
}

/* Fetch the value as C string (user must have made sure the length is ok) */
static int decode_str(const unsigned char *packet, size_t size, size_t *pos, size_t len, char *str, size_t str_len)
{
	if (*pos >= (size - len + 1)) {
		logit(LOG_DEBUG, 0, "underflow for string");
		errno = EINVAL;
		return -1;
	}

	snprintf(str, str_len, "%.*s", (int)len, &packet[*pos]);
	*pos = *pos + len;

	return 0;
}

/* Fetch the value as C string (user must have made sure the length is ok) */
static int decode_oid(const unsigned char *packet, size_t size, size_t *pos, size_t len, oid_t *value)
{
	if (*pos >= (size - len + 1)) {
		logit(LOG_DEBUG, 0, "underflow for oid");
		errno = EINVAL;
		return -1;
	}

	value->encoded_length = len;
	if (len > 0xFFFF) {
		logit(LOG_ERR, 0, "could not decode: internal error");
		return -1;
	}

	if (len > 0xFF)
		value->encoded_length += 4;
	else if (len > 0x7F)
		value->encoded_length += 3;
	else
		value->encoded_length += 2;

	value->subid_list_length = 0;
	if (!len) {
		logit(LOG_DEBUG, 0, "underflow for OID startbyte");
		errno = EINVAL;
		return -1;
	}

	if (packet[*pos] & 0x80) {
		logit(LOG_DEBUG, 0, "unsupported OID startbyte %02X", packet[*pos]);
		errno = EINVAL;
		return -1;
	}

	value->subid_list[value->subid_list_length++] = packet[*pos] / 40;
	value->subid_list[value->subid_list_length++] = packet[*pos] % 40;
	*pos = *pos + 1;
	len--;

	while (len) {
		if (value->subid_list_length >= MAX_NR_SUBIDS) {
			logit(LOG_DEBUG, 0, "overflow for OID byte");
			errno = EFAULT;
			return -1;
		}

		value->subid_list[value->subid_list_length] = 0;
		while (len--) {
			value->subid_list[value->subid_list_length]
				= (value->subid_list[value->subid_list_length] << 7) + (packet[*pos] & 0x7F);
			if (packet[*pos] & 0x80) {
				if (!len) {
					logit(LOG_DEBUG, 0, "underflow for OID byte");
					errno = EINVAL;
					return -1;
				}
				*pos = *pos + 1;
			} else {
				*pos = *pos + 1;
				break;
			}
		}
		value->subid_list_length++;
	}

	return 0;
}

/* Fetch the value as pointer (user must make sure not to overwrite packet) */
static int decode_ptr(const unsigned char UNUSED(*packet), size_t size, size_t *pos, int len)
{
	if (*pos >= (size - len + 1)) {
		logit(LOG_DEBUG, 0, "underflow for ptr");
		errno = EINVAL;
		return -1;
	}

	*pos = *pos + len;

	return 0;
}

static int decode_snmp_request(request_t *request, client_t *client)
{
	int type;
	size_t pos = 0, len = 0;
	const char *header_msg  = "Unexpected SNMP header";
	const char *error_msg   = "Unexpected SNMP error";
	const char *request_msg = "Unexpected SNMP request";
	const char *varbind_msg = "Unexpected SNMP varbindings";
	const char *commun_msg  = "SNMP community";
	const char *version_msg = "SNMP version";

	/* The SNMP message is enclosed in a sequence */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_SEQUENCE || len != (client->size - pos)) {
		logit(LOG_DEBUG, 0, "%s type %02X length %zu", header_msg, type, len);
		errno = EINVAL;
		return -1;
	}

	/* The first element of the sequence is the version */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_INTEGER || len != 1) {
		logit(LOG_DEBUG, 0, "Unexpected %s type %02X length %zu", version_msg, type, len);
		errno = EINVAL;
		return -1;
	}

	if (decode_int(client->packet, client->size, &pos, len, &request->version) == -1)
		return -1;

	if (request->version != SNMP_VERSION_1 && request->version != SNMP_VERSION_2C) {
		logit(LOG_DEBUG, 0, "Unsupported %s %d", version_msg, request->version);
		errno = EINVAL;
		return -1;
	}

	/* The second element of the sequence is the community string */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_OCTET_STRING || len >= sizeof(request->community)) {
		logit(LOG_DEBUG, 0, "Unexpected %s type %02X length %zu", commun_msg, type, len);
		errno = EINVAL;
		return -1;
	}

	if (decode_str(client->packet, client->size, &pos, len, request->community, sizeof(request->community)) == -1)
		return -1;

	if (strlen(request->community) < 1) {
		logit(LOG_DEBUG, 0, "unsupported %s '%s'", commun_msg, request->community);
		errno = EINVAL;
		return -1;
	}

	/* The third element of the sequence is the SNMP request */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (len != (client->size - pos)) {
		logit(LOG_DEBUG, 0, "%s type type %02X length %zu", request_msg, type, len);
		errno = EINVAL;
		return -1;
	}
	request->type = type;

	/* The first element of the SNMP request is the request ID */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_INTEGER || len < 1) {
		logit(LOG_DEBUG, 0, "%s id type %02X length %zu", request_msg, type, len);
		errno = EINVAL;
		return -1;
	}

	if (decode_int(client->packet, client->size, &pos, len, &request->id) == -1)
		return -1;

	/* The second element of the SNMP request is the error state / non repeaters (0..2147483647) */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_INTEGER || len < 1) {
		logit(LOG_DEBUG, 0, "%s state type %02X length %zu", error_msg, type, len);
		errno = EINVAL;
		return -1;
	}

	if (decode_cnt(client->packet, client->size, &pos, len, &request->non_repeaters) == -1)
		return -1;

	/* The third element of the SNMP request is the error index / max repetitions (0..2147483647) */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_INTEGER || len < 1) {
		logit(LOG_DEBUG, 0, "%s index type %02X length %zu", error_msg, type, len);
		errno = EINVAL;
		return -1;
	}

	if (decode_cnt(client->packet, client->size, &pos, len, &request->max_repetitions) == -1)
		return -1;

	/* The fourth element of the SNMP request are the variable bindings */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_SEQUENCE || len != (client->size - pos)) {
		logit(LOG_DEBUG, 0, "%s type %02X length %zu", varbind_msg, type, len);
		errno = EINVAL;
		return -1;
	}

	/* Loop through the variable bindings */
	request->oid_list_length = 0;
	while (pos < client->size) {
		/* If there is not enough room in the OID list, bail out now */
		if (request->oid_list_length >= MAX_NR_OIDS) {
			logit(LOG_DEBUG, 0, "Overflow in OID list");
			errno = EFAULT;
			return -1;
		}

		/* Each variable binding is a sequence describing the variable */
		if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
			return -1;

		if (type != BER_TYPE_SEQUENCE || len < 1) {
			logit(LOG_DEBUG, 0, "%s type %02X length %zu", varbind_msg, type, len);
			errno = EINVAL;
			return -1;
		}

		/* The first element of the variable binding is the OID */
		if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
			return -1;

		if (type != BER_TYPE_OID || len < 1) {
			logit(LOG_DEBUG, 0, "%s OID type %02X length %zu", varbind_msg, type, len);
			errno = EINVAL;
			return -1;
		}

		if (decode_oid(client->packet, client->size, &pos, len, &request->oid_list[request->oid_list_length]) == -1)
			return -1;

		/* The second element of the variable binding is the new type and value */
		if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
			return -1;

		if ((type == BER_TYPE_NULL && len) || (type != BER_TYPE_NULL && !len)) {
			logit(LOG_DEBUG, 0, "%s value type %02X length %zu", varbind_msg, type, len);
			errno = EINVAL;
			return -1;
		}

		if (decode_ptr(client->packet, client->size, &pos, len) == -1)
			return -1;

		/* Now the OID list has one more entry */
		request->oid_list_length++;
	}

	return 0;
}


static size_t get_intlen(int val)
{
	if (val < -8388608 || val > 8388607)
		return 6;
	if (val < -32768 || val > 32767)
		return 5;
	if (val < -128 || val > 127)
		return 4;

	return 3;
}

static size_t get_strlen(const char *str)
{
	size_t len = strlen(str);

	if (len > 0xFFFF)
		return MAX_PACKET_SIZE;
	if (len > 0xFF)
		return len + 4;
	if (len > 0x7F)
		return len + 3;

	return len + 2;
}

static size_t get_hdrlen(size_t len)
{
	if (len > 0xFFFF)
		return MAX_PACKET_SIZE;
	if (len > 0xFF)
		return 4;
	if (len > 0x7F)
		return 3;

	return 2;
}

static int encode_snmp_integer(unsigned char *buf, int val)
{
	size_t len;

	if (val < -8388608 || val > 8388607)
		len = 4;
	else if (val < -32768 || val > 32767)
		len = 3;
	else if (val < -128 || val > 127)
		len = 2;
	else
		len = 1;

	*buf++ = BER_TYPE_INTEGER;
	*buf++ = len;
	while (len--)
		*buf++ = ((unsigned int)val >> (8 * len)) & 0xFF;

	return 0;
}

static int encode_snmp_string(unsigned char *buf, const char *str)
{
	size_t len;

	len = strlen(str);
	if (len > 0xFFFF)
		return -1;

	*buf++ = BER_TYPE_OCTET_STRING;
	if (len > 0xFF) {
		*buf++ = 0x82;
		*buf++ = (len >> 8) & 0xFF;
		*buf++ = len & 0xFF;
	} else if (len > 0x7F) {
		*buf++= 0x81;
		*buf++ = len & 0xFF;
	} else {
		*buf++ = len & 0x7F;
	}
	memcpy(buf, str, len);

	return 0;
}

static int encode_snmp_sequence_header(unsigned char *buf, size_t len, int type)
{
	if (len > 0xFFFF)
		return -1;

	*buf++ = type;
	if (len > 0xFF) {
		*buf++ = 0x82;
		*buf++ = (len >> 8) & 0xFF;
		*buf++ = len & 0xFF;
	} else if (len > 0x7F) {
		*buf++= 0x81;
		*buf++ = len & 0xFF;
	} else {
		*buf++ = len & 0x7F;
	}

	return 0;
}

static int encode_snmp_oid(unsigned char *buf, const oid_t *oid)
{
	size_t i, len;

	len = 1;
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

	*buf++ = BER_TYPE_OID;
	if (len > 0xFFFF) {
		logit(LOG_ERR, 0, "could not encode '%s': OID overflow", oid_ntoa(oid));
		return -1;
	}

	if (len > 0xFF) {
		*buf++ = 0x82;
		*buf++ = (len >> 8) & 0xFF;
		*buf++ = len & 0xFF;
	} else if (len > 0x7F) {
		*buf++ = 0x81;
		*buf++ = len & 0xFF;
	} else {
		*buf++ = len & 0x7F;
	}

	*buf++ = oid->subid_list[0] * 40 + oid->subid_list[1];
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
				*buf++ = ((oid->subid_list[i] >> (7 * len)) & 0x7F) | 0x80;
			else
				*buf++ = (oid->subid_list[i] >> (7 * len)) & 0x7F;
		}
	}

	return 0;
}

static int log_encoding_error(const char *what, const char *why)
{
	logit(LOG_ERR, 0, "Failed encoding %s: %s", what, why);
	return -1;
}

static int encode_snmp_varbind(unsigned char *buf, size_t *pos, const value_t *value)
{
	size_t len;

	/* The value of the variable binding (NULL for error responses) */
	len = value->data.encoded_length;
	if (*pos < len)
		return log_encoding_error(oid_ntoa(&value->oid), "DATA overflow");

	memcpy(&buf[*pos - len], value->data.buffer, len);
	*pos = *pos - len;

	/* The OID of the variable binding */
	len = value->oid.encoded_length;
	if (*pos < len)
		return log_encoding_error(oid_ntoa(&value->oid), "OID overflow");

	encode_snmp_oid(&buf[*pos - len], &value->oid);
	*pos = *pos - len;

	/* The sequence header (type and length) of the variable binding */
	len = get_hdrlen(value->oid.encoded_length + value->data.encoded_length);
	if (*pos < len)
		return log_encoding_error(oid_ntoa(&value->oid), "VARBIND overflow");

	encode_snmp_sequence_header(&buf[*pos - len], value->oid.encoded_length + value->data.encoded_length, BER_TYPE_SEQUENCE);
	*pos = *pos - len;

	return 0;
}

static int encode_snmp_response(request_t *request, response_t *response, client_t *client)
{
	size_t i, len, pos;

	/* If there was an error, we have to encode the original varbind list, but
	 * omit any varbind values (replace them with NULL values)
	 */
	if (response->error_status != SNMP_STATUS_OK) {
		if (request->oid_list_length > MAX_NR_VALUES)
			return log_encoding_error("SNMP response", "value list overflow");

		for (i = 0; i < request->oid_list_length && i < NELEMS(request->oid_list); i++) {
			memcpy(&response->value_list[i].oid, &request->oid_list[i], sizeof(request->oid_list[i]));
			memcpy(&response->value_list[i].data, &m_null, sizeof(m_null));
		}
		response->value_list_length = request->oid_list_length;
	}

	/* Dump the response for debugging purposes */
#ifdef DEBUG
	dump_response(response);
#endif

	/* To make the code more compact and save processing time, we are encoding the
	 * data beginning at the last byte of the buffer backwards. Thus, the encoded
	 * packet will not be positioned at offset 0..(size-1) of the client's packet
	 * buffer, but at offset (bufsize-size..bufsize-1)!
	 */
	pos = MAX_PACKET_SIZE;
	for (i = response->value_list_length; i > 0; i--) {
		if (encode_snmp_varbind(client->packet, &pos, &response->value_list[i-1]) == -1)
			return -1;
	}

	len = get_hdrlen(MAX_PACKET_SIZE - pos);
	if (pos < len)
		return log_encoding_error("SNMP response", "VARBINDS overflow");

	encode_snmp_sequence_header(&client->packet[pos - len], MAX_PACKET_SIZE - pos, BER_TYPE_SEQUENCE);
	pos = pos - len;

	len = get_intlen(response->error_index);
	if (pos < len)
		return log_encoding_error("SNMP response", "ERROR INDEX overflow");

	encode_snmp_integer(&client->packet[pos - len], response->error_index);
	pos = pos - len;

	len = get_intlen(response->error_status);
	if (pos < len)
		return log_encoding_error("SNMP response", "ERROR STATUS overflow");

	encode_snmp_integer(&client->packet[pos - len], response->error_status);
	pos = pos - len;

	len = get_intlen(request->id);
	if (pos < len)
		return log_encoding_error("SNMP response", "ID overflow");

	encode_snmp_integer(&client->packet[pos - len], request->id);
	pos = pos - len;

	len = get_hdrlen(MAX_PACKET_SIZE - pos);
	if (pos < len)
		return log_encoding_error("SNMP response", "PDU overflow");

	encode_snmp_sequence_header(&client->packet[pos - len], MAX_PACKET_SIZE - pos, BER_TYPE_SNMP_RESPONSE);
	pos = pos - len;

	len = get_strlen(request->community);
	if (pos < len)
		return log_encoding_error("SNMP response", "COMMUNITY overflow");

	encode_snmp_string(&client->packet[pos - len], request->community);
	pos = pos - len;

	len = get_intlen(request->version);
	if (pos < len)
		return log_encoding_error("SNMP response", "VERSION overflow");

	encode_snmp_integer(&client->packet[pos - len], request->version);
	pos = pos - len;

	len = get_hdrlen(MAX_PACKET_SIZE - pos);
	if (pos < len)
		return log_encoding_error("SNMP response", "RESPONSE overflow");

	encode_snmp_sequence_header(&client->packet[pos - len], MAX_PACKET_SIZE - pos, BER_TYPE_SEQUENCE);
	pos = pos - len;

	/*
	 * Now move the packet to the start of the buffer so that the caller does not have
	 * to deal with this messy detail (the CPU cycles needed are worth their money!)
	 * and set up the packet size.
	 */
	if (pos > 0)
		memmove(&client->packet[0], &client->packet[pos], MAX_PACKET_SIZE - pos);
	client->size = MAX_PACKET_SIZE - pos;

	return 0;
}

static int handle_snmp_get(request_t *request, response_t *response, client_t *UNUSED(client))
{
	size_t i, pos;
	value_t *value;
	const char *msg = "Failed handling SNMP GET: value list overflow\n";

	/*
	 * Search each varbinding of the request and append the value to the
	 * response. Note that if the length does not match, we might have found a
	 * subid of the requested one (table cell of table column)!
	 */
	for (i = 0; i < request->oid_list_length; i++) {
		pos = 0;
		value = mib_find(&request->oid_list[i], &pos);
		if (!value)
			SNMP_GET_ERROR(response, request, i, SNMP_STATUS_NO_SUCH_NAME, m_no_such_object, msg);

		if (pos >= g_mib_length)
			SNMP_GET_ERROR(response, request, i, SNMP_STATUS_NO_SUCH_NAME, m_no_such_object, msg);

		if (value->oid.subid_list_length == (request->oid_list[i].subid_list_length + 1))
			SNMP_GET_ERROR(response, request, i, SNMP_STATUS_NO_SUCH_NAME, m_no_such_instance, msg);

		if (value->oid.subid_list_length != request->oid_list[i].subid_list_length)
			SNMP_GET_ERROR(response, request, i, SNMP_STATUS_NO_SUCH_NAME, m_no_such_object, msg);

		if (response->value_list_length < MAX_NR_VALUES) {
			memcpy(&response->value_list[response->value_list_length], value, sizeof(*value));
			response->value_list_length++;
			continue;
		}

		logit(LOG_ERR, 0, "%s", msg);
		return -1;
	}

	return 0;
}

static int handle_snmp_getnext(request_t *request, response_t *response, client_t *UNUSED(client))
{
	size_t i;
	value_t *value;
	const char *msg = "Failed handling SNMP GETNEXT: value list overflow\n";

	/*
	 * Search each varbinding of the request and append the value to the
	 * response. Note that if the length does not match, we might have found a
	 * subid of the requested one (table cell of table column)!
	 */
	for (i = 0; i < request->oid_list_length; i++) {
		value = mib_findnext(&request->oid_list[i]);
		if (!value)
			SNMP_GET_ERROR(response, request, i, SNMP_STATUS_NO_SUCH_NAME, m_end_of_mib_view, msg);

		if (response->value_list_length < MAX_NR_VALUES) {
			memcpy(&response->value_list[response->value_list_length], value, sizeof(*value));
			response->value_list_length++;
			continue;
		}

		logit(LOG_ERR, 0, "%s", msg);
		return -1;
	}

	return 0;
}

static int handle_snmp_set(request_t *request, response_t *response, client_t *UNUSED(client))
{
	SNMP_VERSION_1_ERROR(response, (request->version == SNMP_VERSION_1)
			     ? SNMP_STATUS_NO_SUCH_NAME : SNMP_STATUS_NO_ACCESS, 0);
}

static int handle_snmp_getbulk(request_t *request, response_t *response, client_t *UNUSED(client))
{
	size_t i, j;
	oid_t oid_list[MAX_NR_OIDS];
	value_t *value;
	const char *msg = "Failed handling SNMP GETBULK: value list overflow\n";

	/* Make a local copy of the OID list since we are going to modify it */
	memcpy(oid_list, request->oid_list, sizeof(request->oid_list));

	/* The non-repeaters are handled like with the GETNEXT request */
	for (i = 0; i < request->oid_list_length; i++) {
		if (i >= request->non_repeaters)
			break;

		value = mib_findnext(&oid_list[i]);
		if (!value)
			SNMP_GET_ERROR(response, request, i, SNMP_STATUS_NO_SUCH_NAME, m_end_of_mib_view, msg);

		if (response->value_list_length < MAX_NR_VALUES) {
			memcpy(&response->value_list[response->value_list_length], value, sizeof(*value));
			response->value_list_length++;
			continue;
		}

		logit(LOG_ERR, 0, "%s", msg);
		return -1;
	}

	/*
	 * The repeaters are handled like with the GETNEXT request, except that:
	 *
	 * - the access is interleaved (i.e. first repetition of all varbinds,
	 *   then second repetition of all varbinds, then third,...)
	 * - the repetitions are aborted as soon as there is no successor found
	 *   for all of the varbinds
	 * - other than with getnext, the last variable in the MIB is named if
	 *   the variable queried is not after the end of the MIB
	 */
	for (j = 0; j < request->max_repetitions; j++) {
		int found_repeater = 0;

		for (i = request->non_repeaters; i < request->oid_list_length; i++) {
			value = mib_findnext(&oid_list[i]);
			if (!value)
				SNMP_GET_ERROR(response, request, i, SNMP_STATUS_NO_SUCH_NAME, m_end_of_mib_view, msg);

			if (response->value_list_length < MAX_NR_VALUES) {
				memcpy(&response->value_list[response->value_list_length], value, sizeof(*value));
				response->value_list_length++;
				memcpy(&oid_list[i], &value->oid, sizeof(value->oid));
				found_repeater++;
				continue;
			}

			logit(LOG_ERR, 0, "%s", msg);
			return -1;
		}

		if (found_repeater == 0)
			break;
	}

	return 0;
}


int snmp_packet_complete(const client_t *client)
{
	int type;
	size_t pos = 0, len = 0;

	/*
	 * The SNMP message must be at least have a header containing sequence,
	 * version, community, sequence, request id, 2 integers, sequence, oid
	 * and null value.
	 */
	if (client->size < 25)
		return 0;

	/* The SNMP message is enclosed in a sequence */
	if (decode_len(client->packet, client->size, &pos, &type, &len) == -1)
		return -1;

	if (type != BER_TYPE_SEQUENCE || len < 1 || len > (client->size - pos)) {
		logit(LOG_DEBUG, 0, "Unexpected SNMP header type %02X length %zu", type, len);
		errno = EINVAL;
		return -1;
	}

	/* Return whether we received the whole packet */
	return ((client->size - pos) == len) ? 1 : 0;
}

int snmp(client_t *client)
{
	response_t response;
	request_t request;

	/* Setup request and response (other code only changes non-defaults) */
	memset(&request, 0, sizeof(request));
	memset(&response, 0, sizeof(response));

	/* Decode the request (only checks for syntax of the packet) */
	if (decode_snmp_request(&request, client) == -1)
		return -1;

	/*
	 * If we are using SNMP v2c or require authentication, check the community
	 * string for length and validity.
	 */
	if (request.version == SNMP_VERSION_2C) {
		if (strcmp(g_community, request.community)) {
			response.error_status = (request.version == SNMP_VERSION_2C) ? SNMP_STATUS_NO_ACCESS : SNMP_STATUS_GEN_ERR;
			response.error_index = 0;
			goto done;
		}
	} else if (g_auth) {
		response.error_status = SNMP_STATUS_GEN_ERR;
		response.error_index = 0;
		goto done;
	}

	/* Now handle the SNMP requests depending on their type */
	switch (request.type) {
	case BER_TYPE_SNMP_GET:
		if (handle_snmp_get(&request, &response, client) == -1)
			return -1;
		break;

	case BER_TYPE_SNMP_GETNEXT:
		if (handle_snmp_getnext(&request, &response, client) == -1)
			return -1;
		break;

	case BER_TYPE_SNMP_SET:
		if (handle_snmp_set(&request, &response, client) == -1)
			return -1;
		break;

	case BER_TYPE_SNMP_GETBULK:
		if (handle_snmp_getbulk(&request, &response, client) == -1)
			return -1;
		break;

	default:
		logit(LOG_ERR, 0, "UNHANDLED REQUEST TYPE %d", request.type);
		client->size = 0;
		return 0;
	}

done:
	/* Encode the request (depending on error status and encode flags) */
	if (encode_snmp_response(&request, &response, client) == -1)
		return -1;

	return 0;
}

#ifdef DEBUG
int snmp_element_as_string(const data_t *data, char *buf, size_t size)
{
	size_t i, len, pos = 0;
	int type, val;
	oid_t oid;
	unsigned int cnt;

	/* Decode the element type and length */
	if (decode_len(data->buffer, data->encoded_length, &pos, &type, &len) == -1)
		return -1;

	/* Depending on type and length, decode the data */
	switch (type) {
	case BER_TYPE_INTEGER:
		if (decode_int(data->buffer, data->encoded_length, &pos, len, &val) == -1)
			return -1;
		snprintf(buf, size, "%d", val);
		break;

	case BER_TYPE_OCTET_STRING:
		snprintf(buf, size, "%.*s", (int)len, &data->buffer[pos]);
		break;

	case BER_TYPE_OID:
		if (decode_oid(data->buffer, data->encoded_length, &pos, len, &oid) == -1)
			return -1;
		snprintf(buf, size, "%s", oid_ntoa(&oid));
		break;

	case BER_TYPE_COUNTER:
	case BER_TYPE_GAUGE:
	case BER_TYPE_TIME_TICKS:
		if (decode_cnt(data->buffer, data->encoded_length, &pos, len, &cnt) == -1)
			return -1;
		snprintf(buf, size, "%u", cnt);
		break;

	case BER_TYPE_NO_SUCH_OBJECT:
		snprintf(buf, size, "noSuchObject");
		break;

	case BER_TYPE_NO_SUCH_INSTANCE:
		snprintf(buf, size, "noSuchInstance");
		break;

	case BER_TYPE_END_OF_MIB_VIEW:
		snprintf(buf, size, "endOfMibView");
		break;

	default:
		for (i = 0; i < len && i < ((size - 1) / 3); i++)
			snprintf(buf + 3 * i, 4, "%02X ", data->buffer[pos + i]);

		if (len > 0)
			buf[len * 3 - 1] = '\0';
		else
			buf[0] = '\0';
		break;
	}

	return 0;
}
#endif /* DEBUG */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
