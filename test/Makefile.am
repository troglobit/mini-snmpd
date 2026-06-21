EXTRA_DIST         = lib.sh sanity.sh basic.sh iface.sh
CLEANFILES         = *~ *.trs *.log

TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun --map-auto

TESTS              = sanity.sh
TESTS             += basic.sh
TESTS             += iface.sh
