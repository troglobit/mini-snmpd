#!/bin/sh
# HOST-RESOURCES-MIB hrSystem group: date, logged-in users, process count,
# and max processes.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed; hrSystemDate is fetched with -Ox so it renders as
# raw hex regardless of whether the DateAndTime textual convention is known.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

hrSystemDate=.1.3.6.1.2.1.25.1.2.0
hrSystemNumUsers=.1.3.6.1.2.1.25.1.5.0
hrSystemProcesses=.1.3.6.1.2.1.25.1.6.0
hrSystemMaxProcesses=.1.3.6.1.2.1.25.1.7.0

start_snmpd

print "hrSystemProcesses must be positive ..."
got=$(snmp_get $hrSystemProcesses) || FAIL "GET failed, daemon log:$(cat "/tmp/$NM/snmpd.log")"
dprint "$got"
echo "$got" | grep -qE "Gauge32:[[:space:]]*[1-9]" || FAIL "hrSystemProcesses not > 0: $got"

print "hrSystemNumUsers must be a gauge ..."
expect $hrSystemNumUsers "Gauge32"

print "hrSystemMaxProcesses must be 0, no fixed limit ..."
got=$(snmp_get $hrSystemMaxProcesses)
dprint "$got"
echo "$got" | grep -qE "INTEGER:[[:space:]]*0([^0-9]|$)" || FAIL "hrSystemMaxProcesses not 0: $got"

print "hrSystemDate must carry the current year ..."
year=$(date +%Y)
hi=$(printf '%02X' $((year / 256)))
lo=$(printf '%02X' $((year % 256)))
got=$(snmp_get $hrSystemDate) || FAIL "GET hrSystemDate failed, daemon log:$(cat "/tmp/$NM/snmpd.log")"
dprint "$got"
# With the net-snmp MIBs the DateAndTime renders as a date (decimal year),
# without them as raw hex (the year high/low bytes).  Accept either.
echo "$got" | grep -qiE "$year|$hi $lo" || FAIL "hrSystemDate missing year ($year / $hi $lo): $got"

OK
