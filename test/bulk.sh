#!/bin/sh
# GETBULK: the v2c bulk PDU has its own handler in the daemon (non-repeaters
# plus a max-repetitions repeater loop).  Every other test walks with -v1,
# i.e. GETNEXT, so this is the only coverage of the GETBULK path.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

check_dep snmpbulkwalk
check_dep snmpbulkget

# .1.3.6.1.2.1.2.2.1.2 -- ifDescr, .1.3.6.1.2.1 -- the mib-2 subtree
ifDescr=.1.3.6.1.2.1.2.2.1.2
mib2=.1.3.6.1.2.1

start_snmpd -i lo

print "snmpbulkwalk returns the interface table ..."
got=$(snmpbulkwalk -v2c -c "$COMMUNITY" -On -t 2 -r 2 $HOST $ifDescr 2>&1) \
	|| FAIL "bulkwalk failed: $got"
echo "$got" | grep -qF lo || FAIL "bulkwalk ifDescr missing lo: $got"

print "GETBULK and GETNEXT enumerate the same set ..."
bulk=$(snmpbulkwalk -v2c -c "$COMMUNITY" -On -t 2 -r 2 $HOST $mib2 2>/dev/null | grep -c .)
walk=$(snmp_walk $mib2 | grep -c .)		# snmp_walk uses -v1, i.e. GETNEXT
dprint "GETBULK: $bulk entries, GETNEXT: $walk entries"
[ "$bulk" = "$walk" ] || FAIL "GETBULK ($bulk) and GETNEXT ($walk) disagree"

print "snmpbulkget honours max-repetitions ..."
# 0 non-repeaters, 4 repetitions from ifDescr -> 4 successive varbinds
got=$(snmpbulkget -v2c -c "$COMMUNITY" -On -Cn0 -Cr4 -t 2 -r 2 $HOST $ifDescr 2>&1) \
	|| FAIL "bulkget failed: $got"
n=$(echo "$got" | grep -c =)
[ "$n" -ge 4 ] || FAIL "bulkget returned $n varbinds, expected >= 4: $got"

OK
