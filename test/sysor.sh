#!/bin/sh
# sysORTable: the agent advertises its implemented MIB modules (RFC 3418),
# which managers walk to decide what to poll.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

sysORLastChange=.1.3.6.1.2.1.1.8.0
sysORID=.1.3.6.1.2.1.1.9.1.2
snmpMIB=.1.3.6.1.6.3.1

start_snmpd -i lo

print "sysORLastChange answers ..."
expect $sysORLastChange "0:00:00"

print "sysORID.1 is the snmpMIB module ..."
expect $sysORID.1 "$snmpMIB"

print "sysORTable advertises six modules ..."
n=$(snmp_walk $sysORID | grep -c =)
dprint "modules: $n"
[ "$n" = 6 ] || FAIL "expected 6 sysORID rows, got $n"

OK
