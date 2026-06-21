#!/bin/sh
# Smoke test: GET and WALK against a running daemon.
#
# Starts mini-snmpd in a private network namespace, bound to loopback on
# the standard SNMP port, and verifies that:
#  - values passed on the command line round-trip back over SNMP (GET)
#  - a full walk of the tree completes without error (WALK)
#
# Uses numeric OIDs (-On / SNMP_get) so the test does not depend on the
# net-snmp MIB files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

DESC="mini-snmpd regression test"
CONTACT="tester@example.com"
LOCATION="namespace"

# .1.3.6.1.2.1.1 -- the system group
sysDescr=.1.3.6.1.2.1.1.1.0
sysContact=.1.3.6.1.2.1.1.4.0
sysLocation=.1.3.6.1.2.1.1.6.0

start_snmpd -D "$DESC" -C "$CONTACT" -L "$LOCATION"

print "Verifying system group round-trips ..."
expect()
{
    oid=$1
    want=$2
    got=$(snmp_get "$oid") || FAIL "GET $oid failed, daemon log:$(cat "/tmp/$NM/snmpd.log")"
    dprint "$got"
    echo "$got" | grep -qF "$want" || FAIL "GET $oid: expected '$want', got '$got'"
}

expect $sysDescr    "$DESC"
expect $sysContact  "$CONTACT"
expect $sysLocation "$LOCATION"

print "Walking the full tree ..."
if ! snmp_walk .1.3.6.1.2.1 > "/tmp/$NM/walk.log"; then
    cat "/tmp/$NM/walk.log"
    FAIL "snmpwalk of the MIB tree failed"
fi
lines=$(wc -l < "/tmp/$NM/walk.log")
dprint "walk returned $lines objects"
[ "$lines" -gt 0 ] || FAIL "snmpwalk returned no objects"

OK
