#!/bin/sh
# Smoke test: default sysDescr from os-release(5).
#
# When no description is given, mini-snmpd falls back to PRETTY_NAME from
# /etc/os-release.  We mask that file with a known value (bind mount,
# isolated to this test's private mount namespace) and verify:
#  - no -D    -> sysDescr is the PRETTY_NAME from os-release
#  - -D STR   -> the explicit description wins over os-release
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

OSREL="/tmp/$NM/os-release"
PRETTY="Test Linux 9.9 (regression)"
OVERRIDE="Explicit Description"

sysDescr=.1.3.6.1.2.1.1.1.0

[ -e /etc/os-release ] || SKIP "no /etc/os-release to mask"

cat > "$OSREL" <<EOF
NAME="Test Linux"
PRETTY_NAME="$PRETTY"
EOF

print "Masking /etc/os-release with a known PRETTY_NAME ..."
mount --bind "$OSREL" /etc/os-release || SKIP "cannot bind-mount /etc/os-release"

print "Default sysDescr should come from os-release PRETTY_NAME ..."
start_snmpd
expect $sysDescr "$PRETTY"
stop_snmpd

print "Explicit -D should override os-release ..."
start_snmpd -D "$OVERRIDE"
expect $sysDescr "$OVERRIDE"
got=$(snmp_get $sysDescr)
echo "$got" | grep -qF "$PRETTY" && FAIL "-D did not override os-release: $got"
stop_snmpd

OK
