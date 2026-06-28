#!/bin/sh
# Smoke test: configuration file (libConfuse) support.
#
# Starts mini-snmpd with -f pointing at a generated .conf and verifies
# that the system group values defined in the file round-trip back over
# SNMP.  Skipped when the daemon is built without libConfuse.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

# The -f/--file option only exists in a libConfuse build
$SNMPD -h 2>&1 | grep -q -- '--file' || SKIP "built without libConfuse (.conf) support"

CONF="/tmp/$NM/test.conf"
DESC="conf-file description"
CONTACT="conf@example.com"
LOCATION="conf-file location"

# .1.3.6.1.2.1.1 -- the system group
sysDescr=.1.3.6.1.2.1.1.1.0
sysContact=.1.3.6.1.2.1.1.4.0
sysLocation=.1.3.6.1.2.1.1.6.0

cat > "$CONF" <<EOF
community   = "$COMMUNITY"
description = "$DESC"
contact     = "$CONTACT"
location    = "$LOCATION"
EOF

start_snmpd -f "$CONF"

print "Verifying values from the .conf round-trip ..."
expect $sysDescr    "$DESC"
expect $sysContact  "$CONTACT"
expect $sysLocation "$LOCATION"

OK
