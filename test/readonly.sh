#!/bin/sh
# Read-only: mini-snmpd does not implement SET.  A write request must be
# rejected, and the value must be left unchanged -- never silently applied.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

check_dep snmpset

# .1.3.6.1.2.1.1.4.0 -- sysContact.0
sysContact=.1.3.6.1.2.1.1.4.0

start_snmpd -C "original contact"

print "SET must be rejected, daemon is read-only ..."
before=$(snmp_get $sysContact)
if snmpset -v2c -c "$COMMUNITY" -t 2 -r 1 $HOST $sysContact s "hacked" >/dev/null 2>&1; then
	FAIL "SET unexpectedly succeeded"
fi

print "Value must be unchanged after the rejected SET ..."
after=$(snmp_get $sysContact)
dprint "before:$before after:$after"
[ "$before" = "$after" ] || FAIL "value changed by SET: '$before' -> '$after'"
echo "$after" | grep -qF "original contact" || FAIL "unexpected value: $after"

OK
