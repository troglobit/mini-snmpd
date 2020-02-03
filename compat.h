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

#ifndef MINI_SNMPD_COMPAT_H_
#define MINI_SNMPD_COMPAT_H_

#include "config.h"
#include <stdlib.h>
#include <sys/stat.h>

#ifndef UNUSED
#define UNUSED(x) x __attribute__((unused))
#endif

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

#ifndef HAVE_PIDFILE
int pidfile(const char *basename);
#endif

#ifndef HAVE_UTIMENSAT
int utimensat(int dirfd, const char *pathname, const struct timespec ts[2], int flags);
#endif

#ifndef HAVE_GETPROGNAME
static inline char *getprogname(void)
{
	extern char *g_prognm;
	return g_prognm;
}
#endif

#endif /* MINI_SNMPD_COMPAT_H_ */
