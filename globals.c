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



#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "mini_snmpd.h"



/* -----------------------------------------------------------------------------
 * Global variables
 */

in_port_t g_udp_port = 161;
in_port_t g_tcp_port = 161;
int g_timeout = 100;
int g_auth = 0;
int g_verbose = 0;
int g_quit = 0;
char *g_community = "public";
char *g_vendor = VENDOR;
char *g_description = "";
char *g_location = "";
char *g_contact = "";
char *g_disk_list[MAX_NR_DISKS];
int g_disk_list_length = 0;
char *g_interface_list[MAX_NR_INTERFACES];
int g_interface_list_length = 0;
client_t g_udp_client = { 0, };
client_t *g_tcp_client_list[MAX_NR_CLIENTS];
int g_tcp_client_list_length = 0;
int g_udp_sockfd = -1;
int g_tcp_sockfd = -1;
value_t g_mib[MAX_NR_VALUES];
int g_mib_length = 0;



/* vim: ts=4 sts=4 sw=4 nowrap
 */
