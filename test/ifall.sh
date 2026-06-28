#!/bin/sh
# Smoke test: default interface monitoring.
#
# With no -i, mini-snmpd monitors all interfaces, with the loopback
# interface sorted first so it lands on ifIndex 1, like the kernel does.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

ifNumber=.1.3.6.1.2.1.2.1.0
ifDescr=.1.3.6.1.2.1.2.2.1.2
ifDescr1=.1.3.6.1.2.1.2.2.1.2.1		# first row of the ifTable

print "Creating dummy interface eth0 ..."
ip link add eth0 type dummy || SKIP "Cannot create dummy interface"
ip link set eth0 up

start_snmpd				# no -i, default is all interfaces

print "Default must monitor more than one interface ..."
got=$(snmp_get $ifNumber) || FAIL "GET ifNumber failed, daemon log:$(cat "/tmp/$NM/snmpd.log")"
dprint "$got"
echo "$got" | grep -qE "INTEGER:[[:space:]]*[1-9]" || FAIL "ifNumber should be > 0, got '$got'"

print "Loopback must be first, on ifIndex 1 ..."
expect $ifDescr1 "lo"

print "eth0 must also be monitored ..."
if ! snmp_walk $ifDescr > "/tmp/$NM/iftable.log"; then
	cat "/tmp/$NM/iftable.log"
	FAIL "walk of ifDescr column failed"
fi
cat "/tmp/$NM/iftable.log"
grep -qF eth0 "/tmp/$NM/iftable.log" || FAIL "ifDescr does not list eth0"

OK
