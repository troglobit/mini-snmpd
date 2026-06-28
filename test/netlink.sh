#!/bin/sh
# Netlink: interfaces created/removed after start-up are reflected in the
# ifTable without a restart (Linux real-time interface monitoring).
#
# Starts mini-snmpd with -i 'dummy+' (matching nothing yet), then creates a
# dummy interface and checks it shows up, then removes it and checks it is
# gone -- driven by the netlink RTM_NEWLINK/RTM_DELLINK events.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

# .1.3.6.1.2.1.2.2.1.2 -- ifDescr column of ifTable
ifDescr=.1.3.6.1.2.1.2.2.1.2

start_snmpd -i 'dummy+'

print "Creating dummy0 after start-up, must appear in ifTable ..."
ip link add dummy0 type dummy || SKIP "Cannot create dummy interface"
ip link set dummy0 up

i=0
while [ "$i" -lt 5 ]; do
	snmp_walk $ifDescr 2>/dev/null | grep -qF dummy0 && break
	sleep 1
	i=$((i + 1))
done
snmp_walk $ifDescr > "/tmp/$NM/iftable.log"
cat "/tmp/$NM/iftable.log"
grep -qF dummy0 "/tmp/$NM/iftable.log" || FAIL "netlink did not pick up the new interface dummy0"

print "Removing dummy0, must disappear from ifTable ..."
ip link del dummy0

i=0
while [ "$i" -lt 5 ]; do
	snmp_walk $ifDescr 2>/dev/null | grep -qF dummy0 || break
	sleep 1
	i=$((i + 1))
done
snmp_walk $ifDescr > "/tmp/$NM/iftable.log"
cat "/tmp/$NM/iftable.log"
grep -qF dummy0 "/tmp/$NM/iftable.log" && FAIL "netlink did not drop the removed interface dummy0"

OK
