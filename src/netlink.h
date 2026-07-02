/* Netlink interface monitor for Linux
 *
 * Copyright (C) 2026  Joachim Wiberg <troglobit@gmail.com>
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

#ifndef MINI_SNMPD_NETLINK_H_
#define MINI_SNMPD_NETLINK_H_

#ifdef __linux__

int  netlink_init(void);
int  netlink_read(int sd);
void netlink_exit(int sd);

#else /* non-Linux stubs, so the caller needs no #ifdef */

static inline int  netlink_init(void)        { return -1; }
static inline int  netlink_read(int sd)      { (void)sd; return 0; }
static inline void netlink_exit(int sd)      { (void)sd; }

#endif /* __linux__ */
#endif /* MINI_SNMPD_NETLINK_H_ */
