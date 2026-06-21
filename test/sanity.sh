#!/bin/sh
# Smoke test: the daemon binary starts and prints help/version.
#
# Cheap canary that catches link errors and gross startup breakage
# without needing any network setup.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Checking --version ..."
$SNMPD -v || FAIL "mini-snmpd -v exited non-zero"

print "Checking --help ..."
$SNMPD -h || FAIL "mini-snmpd -h exited non-zero"

OK
