EXEC                  = mini_snmpd
EXTRA_DIST            = configure README.md COPYING ChangeLog.md TODO
doc_DATA              = README.md COPYING
DISTCLEANFILES        = *~ *.bak *.map .*.d *.d DEADJOE semantic.cache *.gdb *.elf core core.*
dist_man8_MANS        = $(EXEC).8
sbin_PROGRAMS         = $(EXEC)
mini_snmpd_SOURCES    = mini_snmpd.c mini_snmpd.h linux.c freebsd.c mib.c	\
			globals.c protocol.c utils.c
if HAVE_CONFUSE
mini_snmpd_SOURCES   += conf.c
endif
mini_snmpd_CPPFLAGS   = -DCONFDIR='"$(sysconfdir)"'
mini_snmpd_CFLAGS     = -W -Wall -Wextra -std=gnu99
mini_snmpd_CFLAGS    += $(confuse_CFLAGS)
mini_snmpd_LDADD      = $(confuse_LIBS)

if HAVE_CONFUSE
dist_sysconf_DATA     = mini-snmpd.conf
endif

## Generate MD5 checksum file
MD5 = md5sum
md5-dist:
	@for file in $(DIST_ARCHIVES); do	\
		$(MD5) $$file > ../$$file.md5;	\
	done

## Check if tagged in git
release-hook:
	if [ ! `git tag | grep $(PACKAGE_VERSION)` ]; then				\
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

## Target to run when building a release
release: distcheck release-hook md5-dist
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files:"
	@echo "================================================================"
	@for file in $(DIST_ARCHIVES); do						\
		printf "$$file    \tDistribution tarball\n";				\
		printf "$$file.md5\t"; cat ../$$file.md5 | cut -f1 -d' ';		\
	done
