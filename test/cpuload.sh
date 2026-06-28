#!/bin/sh
# HOST-RESOURCES-MIB: hrProcessorTable, one row per logical CPU with a
# 0-100 hrProcessorLoad.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

hrProcessorFrwID1=.1.3.6.1.2.1.25.3.3.1.1.1	# first CPU, firmware id
hrProcessorLoad=.1.3.6.1.2.1.25.3.3.1.2		# load column
hrProcessorLoad1=.1.3.6.1.2.1.25.3.3.1.2.1	# first CPU, load

start_snmpd

print "hrProcessorTable must have at least one CPU row ..."
if ! snmp_walk $hrProcessorLoad > "/tmp/$NM/cpu.log"; then
	cat "/tmp/$NM/cpu.log"
	FAIL "walk of hrProcessorLoad failed"
fi
cat "/tmp/$NM/cpu.log"
[ "$(grep -c "INTEGER:" "/tmp/$NM/cpu.log")" -ge 1 ] || FAIL "hrProcessorTable has no rows"

print "hrProcessorLoad must be an integer percentage (0-100) ..."
got=$(snmp_get $hrProcessorLoad1) || FAIL "GET hrProcessorLoad.1 failed"
dprint "$got"
echo "$got" | grep -qE "INTEGER: ([0-9]|[1-9][0-9]|100)$" || FAIL "load not in 0-100: $got"

print "hrProcessorFrwID must be an OID ..."
got=$(snmp_get $hrProcessorFrwID1) || FAIL "GET hrProcessorFrwID.1 failed"
dprint "$got"
echo "$got" | grep -q "OID:" || FAIL "hrProcessorFrwID is not an OID: $got"

OK
