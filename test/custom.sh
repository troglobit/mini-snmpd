#!/bin/sh
# Custom static responses: a .conf 'custom "OID" { value = "..." }' section
# serves a fixed string on any OID, e.g. to emulate an HP JetDirect print
# server (issue #29).  Custom OIDs can land anywhere in the tree, so this
# also checks the getnext invariant survives the mid-tree insertion, and
# that a SIGHUP reload picks up changes.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.  Skipped when built without libConfuse.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

$SNMPD -h 2>&1 | grep -q -- '--file' || SKIP "built without libConfuse (.conf) support"

CONF="/tmp/$NM/test.conf"

# Mid-tree (sorts before UCD-SNMP .2021) and end-of-tree OIDs
jetdirect=.1.3.6.1.4.1.11.2.3.9.1.1.7.0
lastly=.1.3.6.1.4.1.32473.1.1
MODEL="MFG:Hewlett-Packard;MDL:HP LaserJet 1020;CLS:PRINTER;"

cat > "$CONF" <<EOF
community = "$COMMUNITY"
custom "$jetdirect" {
    value = "$MODEL"
}
EOF

start_snmpd -i lo -f "$CONF"

print "GET the custom OID ..."
expect $jetdirect "$MODEL"

print "GETNEXT across it must reach the UCD-SNMP tree ..."
got=$(snmpgetnext -v2c -c "$COMMUNITY" -On -t 2 -r 2 $HOST $jetdirect 2>&1) \
	|| FAIL "getnext failed: $got"
dprint "$got"
echo "$got" | grep -qF ".1.3.6.1.4.1.2021." || FAIL "getnext did not reach UCD tree: $got"

print "Full walk includes the custom OID and terminates cleanly ..."
if ! snmp_walk .1 > "/tmp/$NM/walk.log" 2> "/tmp/$NM/walk.err"; then
	cat "/tmp/$NM/walk.err"
	FAIL "walk of .1 failed"
fi
grep -qF "$MODEL" "/tmp/$NM/walk.log" || FAIL "custom OID missing from full walk"
[ -s "/tmp/$NM/walk.err" ] && FAIL "walk reported errors: $(cat "/tmp/$NM/walk.err")"

print "SIGHUP reload picks up a second custom OID ..."
cat >> "$CONF" <<EOF
custom "$lastly" {
    value = "added on reload"
}
EOF
kill -HUP "$(cat "/tmp/$NM/snmpd.pid")"

i=0
while [ "$i" -lt 10 ]; do
	snmp_get $lastly 2>/dev/null | grep -qF "added on reload" && break
	sleep 1
	i=$((i + 1))
done
expect $lastly "added on reload"
expect $jetdirect "$MODEL"		# the first one must survive the reload

OK
