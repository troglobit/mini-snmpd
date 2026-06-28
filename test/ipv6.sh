#!/bin/sh
# Smoke test: simultaneous dual-stack (IPv4 + IPv6).
#
# Starts mini-snmpd with no -4/-6, i.e. the default dual-stack mode, and
# verifies that the same OID answers over BOTH IPv4 (127.0.0.1) and IPv6
# ([::1]) from the one running daemon.  Skipped when the daemon is built
# without IPv6 support.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

# The -6/--use-ipv6 option only exists in an IPv6-enabled build
$SNMPD -h 2>&1 | grep -q -- '--use-ipv6' || SKIP "built without IPv6 support"

sysUpTime=.1.3.6.1.2.1.1.3.0

start_snmpd

print "Querying sysUpTime over IPv4 ..."
snmpget -v2c -c "$COMMUNITY" -On -t 2 -r 2 127.0.0.1 $sysUpTime \
    || FAIL "no response over IPv4, daemon log:$(cat "/tmp/$NM/snmpd.log")"

print "Querying sysUpTime over IPv6 ..."
snmpget -v2c -c "$COMMUNITY" -On -t 2 -r 2 udp6:[::1] $sysUpTime \
    || FAIL "no response over IPv6, daemon log:$(cat "/tmp/$NM/snmpd.log")"

OK
