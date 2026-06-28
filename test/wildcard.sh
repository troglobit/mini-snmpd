#!/bin/sh
# Smoke test: interface name wildcards in -i (iptables-style trailing +).
#
# Creates a few dummy interfaces and starts mini-snmpd with -i vlan+,
# verifying that the IF-MIB ifTable lists the matching interfaces and
# excludes the non-matching one.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

# .1.3.6.1.2.1.2.2.1.2 -- ifDescr column of ifTable
ifDescr=.1.3.6.1.2.1.2.2.1.2

print "Creating dummy interfaces eth0, vlan10, vlan20 ..."
for i in eth0 vlan10 vlan20; do
	ip link add "$i" type dummy || SKIP "Cannot create dummy interface"
	ip link set "$i" up
done

start_snmpd -i vlan+

print "ifTable must list vlan10 and vlan20, but not eth0 ..."
if ! snmp_walk $ifDescr > "/tmp/$NM/iftable.log"; then
	cat "/tmp/$NM/iftable.log"
	FAIL "walk of ifDescr column failed"
fi
cat "/tmp/$NM/iftable.log"
grep -qF vlan10 "/tmp/$NM/iftable.log" || FAIL "ifDescr does not list vlan10"
grep -qF vlan20 "/tmp/$NM/iftable.log" || FAIL "ifDescr does not list vlan20"
grep -qF eth0   "/tmp/$NM/iftable.log" && FAIL "ifDescr should not list eth0"

OK
