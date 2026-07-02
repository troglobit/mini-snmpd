#!/bin/sh
# SNMPv2-MIB snmp group: the agent's own counters (RFC 3418).  Generates one
# event of each kind and checks the corresponding counter ticked:
#
#   snmpInPkts               -- any request
#   snmpInBadVersions        -- an SNMPv3 probe (unsupported version)
#   snmpInBadCommunityNames  -- a request with the wrong community
#   snmpInBadCommunityUses   -- a SET with the right community (read-only)
#   snmpEnableAuthenTraps    -- disabled(2), since no trap sink is set
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

check_dep snmpset

snmpInPkts=.1.3.6.1.2.1.11.1.0
snmpInBadVersions=.1.3.6.1.2.1.11.3.0
snmpInBadCommunityNames=.1.3.6.1.2.1.11.4.0
snmpInBadCommunityUses=.1.3.6.1.2.1.11.5.0
snmpEnableAuthenTraps=.1.3.6.1.2.1.11.30.0

# GET $1 and assert a counter value of at least $2
expect_cnt()
{
	got=$(snmp_get "$1") || FAIL "GET $1 failed, daemon log:$(cat "/tmp/$NM/snmpd.log")"
	dprint "$got"
	n=$(echo "$got" | sed -n 's/.*Counter32: *//p')
	[ -n "$n" ] && [ "$n" -ge "$2" ] || FAIL "GET $1: expected >= $2, got '$got'"
}

start_snmpd -i lo

print "Generating one event of each kind ..."
snmpget -v2c -c WRONG        -t 1 -r 0 $HOST .1.3.6.1.2.1.1.3.0 >/dev/null 2>&1
snmpset -v2c -c "$COMMUNITY" -t 1 -r 0 $HOST .1.3.6.1.2.1.1.6.0 s x >/dev/null 2>&1
snmpget -v3 -u nosuchuser -l noAuthNoPriv -t 1 -r 0 $HOST .1.3.6.1.2.1.1.3.0 >/dev/null 2>&1

print "snmpInPkts counts all of the above ..."
expect_cnt $snmpInPkts 3

print "snmpInBadVersions counts the SNMPv3 probe ..."
expect_cnt $snmpInBadVersions 1

print "snmpInBadCommunityNames counts the wrong community ..."
expect_cnt $snmpInBadCommunityNames 1

print "snmpInBadCommunityUses counts the rejected SET ..."
expect_cnt $snmpInBadCommunityUses 1

print "snmpEnableAuthenTraps is disabled without a trap sink ..."
expect $snmpEnableAuthenTraps "2"

OK
