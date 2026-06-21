EXEC                  = mini-snmpd
SUBDIRS               = .
if ENABLE_TEST
SUBDIRS              += test
endif
EXTRA_DIST            = README.md COPYING ChangeLog.md
doc_DATA              = README.md COPYING
dist_man8_MANS        = $(EXEC).8
sbin_PROGRAMS         = $(EXEC)
AM_CPPFLAGS           = -DSYSCONFDIR=\"@sysconfdir@\" -DRUNSTATEDIR=\"@runstatedir@\"

mini_snmpd_SOURCES    = mini-snmpd.c mini-snmpd.h linux.c freebsd.c mib.c	\
			globals.c protocol.c utils.c compat.h
if HAVE_CONFUSE
mini_snmpd_SOURCES   += conf.c linux_ethtool.c
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

# Build a Debian/Ubuntu package, for local testing only.  Not part of
# the release; the GitHub release ships the distribution tarball only.
# lintian --profile debian -i -I --show-overrides ../$PKG.changes
package build-deb:
	@dpkg-buildpackage -uc -us -B

## Build and verify the distribution tarball.  distcheck also runs the
## test suite, see DISTCHECK_CONFIGURE_FLAGS, before the tarball is
## considered good.  The release workflow runs this when a tag is pushed.
release: distcheck
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do					\
		printf "%-32s Distribution tarball\n" $$file;			\
	done

# Workaround for systemd unit file duing distcheck
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd) --enable-test
DISTCLEANFILES = lib/.libs/* *~ *.bak *.map .*.d *.d DEADJOE semantic.cache *.gdb *.elf core core.*
