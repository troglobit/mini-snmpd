EXEC                  = mini_snmpd
EXTRA_DIST            = configure README.md COPYING ChangeLog.md TODO
doc_DATA              = README.md COPYING
DISTCLEANFILES        = *~ *.bak *.map .*.d *.d DEADJOE semantic.cache *.gdb *.elf core core.*
dist_man8_MANS        = $(EXEC).8
bin_PROGRAMS          = $(EXEC)
mini_snmpd_SOURCES    = mini_snmpd.c mini_snmpd.h linux.c freebsd.c mib.c	\
			globals.c protocol.c utils.c

## Target to run when building a release
release: dist
	@for file in $(DIST_ARCHIVES); do	\
		md5sum $$file > ../$$file.md5;	\
	done
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do					\
		printf "$$file    \tDistribution tarball\n";			\
		printf "$$file.md5\t"; cat ../$$file.md5 | cut -f1 -d' ';	\
	done
