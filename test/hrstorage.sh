#!/bin/sh
# HOST-RESOURCES-MIB: hrMemorySize and hrStorageTable (physical memory plus
# each monitored filesystem).
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

hrMemorySize=.1.3.6.1.2.1.25.2.2.0
hrStorageDescr=.1.3.6.1.2.1.25.2.3.1.3		# hrStorageDescr column
hrStorageDescr1=.1.3.6.1.2.1.25.2.3.1.3.1	# first row (physical memory)
hrStorageUsed1=.1.3.6.1.2.1.25.2.3.1.6.1	# memory used

start_snmpd -d /

print "hrMemorySize must be positive ..."
got=$(snmp_get $hrMemorySize) || FAIL "GET hrMemorySize failed, daemon log:$(cat "/tmp/$NM/snmpd.log")"
dprint "$got"
echo "$got" | grep -qE "INTEGER:[[:space:]]*[1-9]" || FAIL "hrMemorySize should be > 0, got '$got'"

print "First hrStorage row must be physical memory ..."
expect $hrStorageDescr1 "Physical memory"

print "hrStorageTable must include the / filesystem ..."
if ! snmp_walk $hrStorageDescr > "/tmp/$NM/hr.log"; then
	cat "/tmp/$NM/hr.log"
	FAIL "walk of hrStorageDescr failed"
fi
cat "/tmp/$NM/hr.log"
# net-snmp may render the value quoted ("/") or bare (/), depending on version
grep -qE 'STRING: "?/"?[[:space:]]*$' "/tmp/$NM/hr.log" || FAIL "hrStorageTable does not list the / filesystem"

print "hrStorageUsed for memory must be positive ..."
got=$(snmp_get $hrStorageUsed1) || FAIL "GET hrStorageUsed.1 failed"
dprint "$got"
echo "$got" | grep -qE "INTEGER:[[:space:]]*[1-9]" || FAIL "hrStorageUsed.1 should be > 0, got '$got'"

OK
