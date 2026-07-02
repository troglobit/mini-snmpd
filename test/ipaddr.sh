#!/bin/sh
# IP-MIB ipAddressTable (RFC 4293): the unified address table, one row per
# IPv4/IPv6 address on the monitored interfaces.  The index encodes the
# address type, length, and octets, e.g. 127.0.0.1 -> .1.4.127.0.0.1 and
# ::1 -> .2.16.0...0.1.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

ipAddressIfIndex=.1.3.6.1.2.1.4.34.1.3
v4loop=$ipAddressIfIndex.1.4.127.0.0.1
v6loop=$ipAddressIfIndex.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1

start_snmpd -i lo

print "ipAddressTable has the IPv4 loopback row ..."
expect $v4loop "INTEGER"

if $SNMPD -h 2>&1 | grep -q -- '--use-ipv6' && [ -e /proc/net/if_inet6 ]; then
	print "... and the IPv6 loopback row ..."
	expect $v6loop "INTEGER"
fi

print "Rows agree with the interface's ifIndex ..."
ifidx=$(snmp_get .1.3.6.1.2.1.2.2.1.1.1 | sed 's/.*INTEGER: *//')
addridx=$(snmp_get $v4loop | sed 's/.*INTEGER: *//')
dprint "ifIndex: $ifidx, ipAddressIfIndex: $addridx"
[ "$ifidx" = "$addridx" ] || FAIL "ifIndex mismatch: $ifidx vs $addridx"

print "Full walk stays in order with the deep v6 index ..."
if ! snmp_walk .1 > "/tmp/$NM/walk.log" 2> "/tmp/$NM/walk.err"; then
	cat "/tmp/$NM/walk.err"
	FAIL "walk of .1 failed"
fi
[ -s "/tmp/$NM/walk.err" ] && FAIL "walk reported errors: $(cat "/tmp/$NM/walk.err")"

OK
