EXEC                  = mini-snmpd
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

## Generate MD5 checksum file
MD5 = md5sum
md5-dist:
	@for file in $(DIST_ARCHIVES); do	\
		$(MD5) $$file > ../$$file.md5;	\
	done

## Check if tagged in git
release-hook:
	@if [ ! `git tag | grep $(PACKAGE_VERSION)` ]; then				\
		echo;									\
		printf "\e[1m\e[41mCannot find release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[5mDo release anyway?\e[0m "; read yorn;			\
		if [ "$$yorn" != "y" -a "$$yorn" != "Y" ]; then				\
			printf "OK, aborting release.\n";				\
			exit 1;								\
		fi;									\
		echo;									\
	else										\
		echo;									\
		printf "\e[1m\e[42mFound GIT release tag $(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[44m>>Remember to push tags!\e[0m\n";			\
		echo;									\
	fi

# lintian --profile debian -i -I --show-overrides ../$PKG.changes
package build-deb:
	@dpkg-buildpackage -uc -us -B

## Target to run when building a release
release: release-hook distcheck package md5-dist
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do					\
		printf "%-32s Distribution tarball\n" $$file;			\
		printf "%-32s " $$file.md5; cat ../$$file.md5 | cut -f1 -d' ';	\
	done
	@for file in `cd ..; ls $(PACKAGE)_$(VERSION)*`; do			\
		printf "%-32s Debian/Ubuntu package\n" $$file;			\
	done

# Workaround for systemd unit file duing distcheck
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd)
DISTCLEANFILES = lib/.libs/* *~ *.bak *.map .*.d *.d DEADJOE semantic.cache *.gdb *.elf core core.*
