SUBDIRS               = src doc
if ENABLE_TEST
SUBDIRS              += test
endif

doc_DATA              = README.md COPYING
EXTRA_DIST            = README.md COPYING

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
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/$(systemd) --enable-test --with-config --enable-ethtool
DISTCLEANFILES = *~ *.bak *.map .*.d *.d DEADJOE semantic.cache *.gdb *.elf core core.*
