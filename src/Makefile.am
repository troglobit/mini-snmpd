EXEC                  = mini-snmpd
sbin_PROGRAMS         = $(EXEC)
AM_CPPFLAGS           = -DSYSCONFDIR=\"@sysconfdir@\" -DRUNSTATEDIR=\"@runstatedir@\"

mini_snmpd_SOURCES    = mini-snmpd.c mini-snmpd.h linux.c freebsd.c mib.c	\
			globals.c protocol.c utils.c compat.h inet.c inet.h	\
			netlink.c netlink.h
if HAVE_CONFUSE
mini_snmpd_SOURCES   += conf.c linux_ethtool.c ethtool-conf.h
endif
mini_snmpd_CPPFLAGS   = $(AM_CPPFLAGS)
mini_snmpd_CFLAGS     = -W -Wall -Wextra -std=gnu99
mini_snmpd_LDADD      = $(LIBS) $(LIBOBJS)
mini_snmpd_CFLAGS    += $(confuse_CFLAGS)
mini_snmpd_LDADD     += $(confuse_LIBS)

if HAVE_CONFUSE
dist_sysconf_DATA     = mini-snmpd.conf
endif

if HAVE_SYSTEMD
systemd_DATA          = mini-snmpd.service
endif
