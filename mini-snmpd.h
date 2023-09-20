/*
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

#ifndef MINI_SNMPD_H_
#define MINI_SNMPD_H_

#include "config.h"
#include <errno.h>
#include <stdint.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "compat.h"

/*
 * Project dependent defines
 */

#define EXIT_OK                                         0
#define EXIT_ARGS                                       1
#define EXIT_SYSCALL                                    2

#define MAX_NR_CLIENTS                                  16
#define MAX_NR_OIDS                                     20
#define MAX_NR_SUBIDS                                   20
#define MAX_NR_DISKS                                    4
#define MAX_NR_VALUES                                   2048

#define MAX_PACKET_SIZE                                 2048
#define MAX_STRING_SIZE                                 64

/*
 * SNMP dependent defines
 */

#define BER_TYPE_BOOLEAN                                0x01
#define BER_TYPE_INTEGER                                0x02
#define BER_TYPE_BIT_STRING                             0x03
#define BER_TYPE_OCTET_STRING                           0x04
#define BER_TYPE_NULL                                   0x05
#define BER_TYPE_OID                                    0x06
#define BER_TYPE_SEQUENCE                               0x30
#define BER_TYPE_IP_ADDRESS                             0x40
#define BER_TYPE_COUNTER                                0x41
#define BER_TYPE_GAUGE                                  0x42
#define BER_TYPE_TIME_TICKS                             0x43
#define BER_TYPE_COUNTER64                              0x46 
#define BER_TYPE_NO_SUCH_OBJECT                         0x80
#define BER_TYPE_NO_SUCH_INSTANCE                       0x81
#define BER_TYPE_END_OF_MIB_VIEW                        0x82
#define BER_TYPE_SNMP_GET                               0xA0
#define BER_TYPE_SNMP_GETNEXT                           0xA1
#define BER_TYPE_SNMP_RESPONSE                          0xA2
#define BER_TYPE_SNMP_SET                               0xA3
#define BER_TYPE_SNMP_GETBULK                           0xA5
#define BER_TYPE_SNMP_INFORM                            0xA6
#define BER_TYPE_SNMP_TRAP                              0xA7
#define BER_TYPE_SNMP_REPORT                            0xA8

#define SNMP_VERSION_1                                  0
#define SNMP_VERSION_2C                                 1
#define SNMP_VERSION_3                                  3

#define SNMP_STATUS_OK                                  0
#define SNMP_STATUS_TOO_BIG                             1
#define SNMP_STATUS_NO_SUCH_NAME                        2
#define SNMP_STATUS_BAD_VALUE                           3
#define SNMP_STATUS_READ_ONLY                           4
#define SNMP_STATUS_GEN_ERR                             5
#define SNMP_STATUS_NO_ACCESS                           6
#define SNMP_STATUS_WRONG_TYPE                          7
#define SNMP_STATUS_WRONG_LENGTH                        8
#define SNMP_STATUS_WRONG_ENCODING                      9
#define SNMP_STATUS_WRONG_VALUE                         10
#define SNMP_STATUS_NO_CREATION                         11
#define SNMP_STATUS_INCONSISTENT_VALUE                  12
#define SNMP_STATUS_RESOURCE_UNAVAILABLE                13
#define SNMP_STATUS_COMMIT_FAILED                       14
#define SNMP_STATUS_UNDO_FAILED                         15
#define SNMP_STATUS_AUTHORIZATION_ERROR                 16
#define SNMP_STATUS_NOT_WRITABLE                        17
#define SNMP_STATUS_INCONSISTENT_NAME                   18

#define PROGRAM_IDENT PACKAGE_NAME " v" PACKAGE_VERSION

#ifndef CONFIG_ENABLE_IPV6
#define my_sockaddr_t           struct sockaddr_in
#define my_socklen_t            socklen_t
#define my_sin_addr             sin_addr
#define my_sin_port             sin_port
#define my_sin_family           sin_family
#define my_af_inet              AF_INET
#define my_pf_inet              PF_INET
#define my_in_addr_t            struct in_addr
#define my_in_port_t            in_port_t
#define my_inet_addrstrlen      INET_ADDRSTRLEN

#else /* IPv6 */

#define my_sockaddr_t           struct sockaddr_in6
#define my_socklen_t            socklen_t
#define my_sin_addr             sin6_addr
#define my_sin_port             sin6_port
#define my_sin_family           sin6_family
#define my_af_inet              AF_INET6
#define my_pf_inet              PF_INET6
#define my_in_addr_t            struct in6_addr
#define my_in_port_t            in_port_t
#define my_inet_addrstrlen      INET6_ADDRSTRLEN
#endif/* CONFIG_ENABLE_IPV6 */


/*
 * Data types
 */

typedef struct client_s {
	time_t              timestamp;
	int                 sockfd;
	my_in_addr_t        addr;
	my_in_port_t        port;
	unsigned char       packet[MAX_PACKET_SIZE];
	size_t              size;
	int                 outgoing;
} client_t;

typedef struct oid_s {
	unsigned int subid_list[MAX_NR_SUBIDS];
	size_t       subid_list_length;
	short        encoded_length;
} oid_t;

typedef struct data_s {
	unsigned char *buffer;
	size_t         max_length;
	short          encoded_length;
} data_t;

typedef struct value_s {
	oid_t  oid;
	data_t data;
} value_t;

typedef struct field_s {
	char         *prefix;

	size_t        len;
	long long    *value[24];
} field_t;

typedef struct request_s {
	char      community[MAX_STRING_SIZE];
	int       type;
	int       version;
	int       id;
	uint32_t  non_repeaters;
	uint32_t  max_repetitions;
	oid_t     oid_list[MAX_NR_OIDS];
	size_t    oid_list_length;
} request_t;

typedef struct response_s {
	int     error_status;
	int     error_index;
	value_t value_list[MAX_NR_VALUES];
	size_t  value_list_length;
} response_t;

typedef struct loadinfo_s {
	unsigned int avg[3];
} loadinfo_t;

typedef struct meminfo_s {
	long long total;
	long long free;
	long long shared;
	long long buffers;
	long long cached;
} meminfo_t;

typedef struct cpuinfo_s {
	long long user;
	long long nice;
	long long system;
	long long idle;
	long long irqs;
	long long cntxts;
} cpuinfo_t;

typedef struct diskinfo_s {
	unsigned int total[MAX_NR_DISKS];
	unsigned int free[MAX_NR_DISKS];
	unsigned int used[MAX_NR_DISKS];
	unsigned int blocks_used_percent[MAX_NR_DISKS];
	unsigned int inodes_used_percent[MAX_NR_DISKS];
} diskinfo_t;

typedef struct netinfo_s {
	unsigned int in_addr[MAX_NR_INTERFACES];
	unsigned int in_mask[MAX_NR_INTERFACES];
	unsigned int in_bcaddr[MAX_NR_INTERFACES];
	unsigned int in_bcent[MAX_NR_INTERFACES];
	unsigned int if_type[MAX_NR_INTERFACES];
	unsigned int if_mtu[MAX_NR_INTERFACES];
	unsigned int if_speed[MAX_NR_INTERFACES];
	unsigned int ifindex[MAX_NR_INTERFACES];
	unsigned int status[MAX_NR_INTERFACES];
	unsigned int lastchange[MAX_NR_INTERFACES];
	unsigned int stats[MAX_NR_INTERFACES];		/* Sentinel for backends */
	long long rx_bytes[MAX_NR_INTERFACES];
	long long rx_mc_packets[MAX_NR_INTERFACES];
	long long rx_bc_packets[MAX_NR_INTERFACES];
	long long rx_packets[MAX_NR_INTERFACES];
	long long rx_errors[MAX_NR_INTERFACES];
	long long rx_drops[MAX_NR_INTERFACES];
	long long tx_bytes[MAX_NR_INTERFACES];
	long long tx_mc_packets[MAX_NR_INTERFACES];
	long long tx_bc_packets[MAX_NR_INTERFACES];
	long long tx_packets[MAX_NR_INTERFACES];
	long long tx_errors[MAX_NR_INTERFACES];
	long long tx_drops[MAX_NR_INTERFACES];
	char mac_addr[MAX_NR_INTERFACES][6];
} netinfo_t;

 
typedef struct ipinfo_s {
	long long ipForwarding;
	long long ipDefaultTTL;
	long long ipReasmTimeout;
} ipinfo_t;

typedef struct tcpinfo_s {
	long long tcpRtoAlgorithm;
	long long tcpRtoMin;
	long long tcpRtoMax;
	long long tcpMaxConn;
	long long tcpActiveOpens;
	long long tcpPassiveOpens;
	long long tcpAttemptFails;
	long long tcpEstabResets;
	long long tcpCurrEstab;
	long long tcpInSegs;
	long long tcpOutSegs;
	long long tcpRetransSegs;
	long long tcpInErrs;
	long long tcpOutRsts;
} tcpinfo_t;

typedef struct udpinfo_s {
	long long udpInDatagrams;
	long long udpNoPorts;
	long long udpInErrors;
	long long udpOutDatagrams;
} udpinfo_t;

#ifdef CONFIG_ENABLE_DEMO
typedef struct demoinfo_s {
	unsigned int random_value_1;
	unsigned int random_value_2;
} demoinfo_t;
#endif


/*
 * Global variables
 */

extern const struct in_addr inaddr_any;

extern int       g_family;
extern int       g_timeout;
extern int       g_auth;
extern int       g_daemon;
extern int       g_syslog;
extern int       g_level;
extern volatile sig_atomic_t g_quit;

extern char     *g_prognm;
extern char     *g_community;
extern char     *g_description;
extern char     *g_vendor;
extern char     *g_location;
extern char     *g_contact;
extern char     *g_bind_to_device;
extern char     *g_user;

extern char     *g_disk_list[MAX_NR_DISKS];
extern size_t    g_disk_list_length;

extern char     *g_interface_list[MAX_NR_INTERFACES];
extern size_t    g_interface_list_length;

extern in_port_t g_udp_port;
extern in_port_t g_tcp_port;

extern client_t  g_udp_client;
extern client_t *g_tcp_client_list[MAX_NR_CLIENTS];
extern size_t    g_tcp_client_list_length;

extern int       g_udp_sockfd;
extern int       g_tcp_sockfd;

extern value_t   g_mib[MAX_NR_VALUES];
extern size_t    g_mib_length;

/*
 * Functions
 */

void         dump_packet   (const client_t   *client);
void         dump_mib      (const value_t    *value, int size);
void         dump_response (const response_t *response);

char        *oid_ntoa (const oid_t *oid);
oid_t       *oid_aton (const char  *str);
int          oid_cmp  (const oid_t *oid1, const oid_t *oid2);

int          split(const char *str, char *delim, char **list, int max_list_length);

client_t    *find_oldest_client(void);
int          find_ifname(char *ifname);

void        *allocate    (size_t len);

int          read_config (char *file);

int          parse_file  (char *file, field_t fields[], size_t limit, size_t skip_prefix);
int          read_file   (const char *filename, char *buffer, size_t size);

unsigned int read_value  (const char *buffer, const char *prefix);
void         read_values (const char *buffer, const char *prefix, unsigned int *values, int count);

int          read_file_value(unsigned int *val, const char *fmt, ...);

int          ticks_since (const struct timeval *tv_last, struct timeval *tv_now);

unsigned int get_process_uptime (void);
unsigned int get_system_uptime  (void);

void         get_loadinfo       (loadinfo_t *loadinfo);
void         get_meminfo        (meminfo_t *meminfo);
void         get_cpuinfo        (cpuinfo_t *cpuinfo);
void         get_ipinfo         (ipinfo_t *ipinfo);
void         get_tcpinfo        (tcpinfo_t *tcpinfo);
void         get_udpinfo        (udpinfo_t *udpinfo);
void         get_diskinfo       (diskinfo_t *diskinfo);
void         get_netinfo        (netinfo_t *netinfo);
#ifdef CONFIG_ENABLE_DEMO
void         get_demoinfo       (demoinfo_t *demoinfo);
#endif
int          logit              (int priority, int syserr, const char *fmt, ...);

int snmp_packet_complete   (const client_t *client);
int snmp                   (      client_t *client);
int snmp_element_as_string (const data_t *data, char *buffer, size_t size);

int mib_build    (void);
int mib_update   (int full);

value_t *mib_find     (const oid_t *oid, size_t *pos);
value_t *mib_findnext (const oid_t *oid);

#ifdef CONFIG_ENABLE_ETHTOOL
int ethtool_gstats(int intf, netinfo_t *netinfo, field_t *field);
#else
#define ethtool_gstats(intf, netinfo, field) (-1)
#endif

#endif /* MINI_SNMPD_H_ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
