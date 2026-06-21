#!/bin/sh
# Smoke test: IF-MIB interface table.
#
# Creates a dummy interface in the test's network namespace, starts
# mini-snmpd monitoring it with -i, and verifies that:
#  - ifNumber reports the one interface
#  - the interface name shows up in the ifDescr column of ifTable
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

IFACE=eth0

# .1.3.6.1.2.1.2 -- the interfaces group
ifNumber=.1.3.6.1.2.1.2.1.0
ifDescr=.1.3.6.1.2.1.2.2.1.2

print "Creating dummy interface $IFACE ..."
ip link add "$IFACE" type dummy || SKIP "Cannot create dummy interface"
ip addr add 10.0.0.1/24 dev "$IFACE"
ip link set "$IFACE" up
ip -br addr show "$IFACE"

start_snmpd -i "$IFACE"

print "Checking ifNumber ..."
got=$(snmp_get $ifNumber) || FAIL "GET ifNumber failed, daemon log:$(cat "/tmp/$NM/snmpd.log")"
dprint "$got"
echo "$got" | grep -qE "INTEGER:[[:space:]]*1$" || FAIL "ifNumber: expected 1, got '$got'"

print "Checking ifDescr lists $IFACE ..."
if ! snmp_walk $ifDescr > "/tmp/$NM/iftable.log"; then
    cat "/tmp/$NM/iftable.log"
    FAIL "walk of ifDescr column failed"
fi
cat "/tmp/$NM/iftable.log"
grep -qF "$IFACE" "/tmp/$NM/iftable.log" || FAIL "ifDescr does not list $IFACE"

OK
