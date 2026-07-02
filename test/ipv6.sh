#!/bin/sh
# Smoke test: simultaneous dual-stack (IPv4 + IPv6).
#
# Starts mini-snmpd in the default dual-stack mode and verifies the same
# OID answers over IPv4 (127.0.0.1), IPv6 loopback ([::1]), and a global-
# scope IPv6 ULA on a dummy interface.  The last one matters: it exercises
# the reply-from-destination-address path over IPv6, beyond loopback.
#
# Skipped when the daemon is built without IPv6, or when the running kernel
# has no IPv6 support (embedded kernels often leave it out).
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

# The -6/--use-ipv6 option only exists in an IPv6-enabled build
$SNMPD -h 2>&1 | grep -q -- '--use-ipv6' || SKIP "built without IPv6 support"

# The kernel itself may lack IPv6; /proc/net/if_inet6 is absent then
[ -e /proc/net/if_inet6 ] || SKIP "kernel without IPv6 support"

sysUpTime=.1.3.6.1.2.1.1.3.0
ULA=fd00::1

get()
{
	snmpget -v2c -c "$COMMUNITY" -On -t 2 -r 2 "$1" $sysUpTime
}

start_snmpd

print "Querying sysUpTime over IPv4 (127.0.0.1) ..."
get 127.0.0.1     || FAIL "no response over IPv4, daemon log:$(cat "/tmp/$NM/snmpd.log")"

print "Querying sysUpTime over IPv6 loopback ([::1]) ..."
get udp6:[::1]    || FAIL "no response over IPv6 loopback, daemon log:$(cat "/tmp/$NM/snmpd.log")"

print "Adding global-scope $ULA on dummy0 and querying over it ..."
ip link add dummy0 type dummy 2>/dev/null || SKIP "cannot create dummy interface"
ip link set dummy0 up
ip -6 addr add "$ULA/64" dev dummy0 nodad 2>/dev/null \
	|| SKIP "cannot add IPv6 address (no runtime IPv6?)"

get "udp6:[$ULA]" || FAIL "no response over global IPv6 $ULA, daemon log:$(cat "/tmp/$NM/snmpd.log")"

OK
