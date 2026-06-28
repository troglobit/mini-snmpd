#!/bin/sh
# Traps: mini-snmpd emits SNMPv2c notifications to a -T sink.  We point it
# at a local snmptrapd and check that the four trigger conditions each show
# up in the trap log:
#
#   coldStart  -- emitted once at daemon start-up
#   linkUp     -- an interface oper status goes up
#   linkDown   -- an interface oper status leaves up
#   authFail   -- a request arrives with the wrong community
#
# snmptrapd logs numeric OIDs (-On) so the test does not depend on the
# net-snmp MIB files being installed; we grep for the trap OIDs directly.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

check_dep snmptrapd

TRAPLOG="/tmp/$NM/trapd.log"
COLDSTART=.1.3.6.1.6.3.1.1.5.1
LINKDOWN=.1.3.6.1.6.3.1.1.5.3
LINKUP=.1.3.6.1.6.3.1.1.5.4
AUTHFAIL=.1.3.6.1.6.3.1.1.5.5

# Also kill the trap sinks on teardown (lib.sh only knows about the daemon)
trap_cleanup()
{
	for p in "/tmp/$NM/trapd.pid" "/tmp/$NM/trapd2.pid"; do
		[ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null
	done
	teardown
}
trapit trap_cleanup INT TERM QUIT EXIT

# Wait up to 10s for trap OID $2 to appear in trap log $1
expect_trap()
{
	i=0
	while [ "$i" -lt 10 ]; do
		grep -qF "$2" "$1" && return 0
		sleep 1
		i=$((i + 1))
	done
	cat "$1"
	FAIL "Expected trap $3 ($2), not seen in $1"
}

# Start an snmptrapd sink: $1 log file, $2 listen port, $3 pid file
start_sink()
{
	snmptrapd -f -n -On -Lf "$1" -c /dev/null --disableAuthorization=yes \
		  "udp:127.0.0.1:$2" &
	echo $! > "$3"
	tenacious 5 grep -qsF NET-SNMP "$1"
}

setup_lo

print "Starting snmptrapd trap sink on 127.0.0.1:162 ..."
start_sink "$TRAPLOG" 162 "/tmp/$NM/trapd.pid"

# coldStart fires the moment the daemon comes up, so the sink must be
# listening first -- hence start_snmpd() only after snmptrapd is ready.
start_snmpd -i 'dummy+' -T 127.0.0.1

print "Expecting coldStart ..."
expect_trap "$TRAPLOG" "$COLDSTART" coldStart

dummy_listed()
{
	snmp_walk .1.3.6.1.2.1.2.2.1.2 2>/dev/null | grep -qF dummy0
}

print "Bringing up dummy0, expecting linkUp ..."
ip link add dummy0 type dummy || SKIP "Cannot create dummy interface"
ip link set dummy0 up
tenacious 5 dummy_listed
expect_trap "$TRAPLOG" "$LINKUP" linkUp

print "Taking down dummy0, expecting linkDown ..."
ip link set dummy0 down
expect_trap "$TRAPLOG" "$LINKDOWN" linkDown

print "Querying with the wrong community, expecting authFail ..."
snmpget -v2c -c WRONG -t 1 -r 0 $HOST .1.3.6.1.2.1.1.3.0 >/dev/null 2>&1
expect_trap "$TRAPLOG" "$AUTHFAIL" authFail

# Trap sinks combine: a -T on the command line and a trap-table in the
# .conf must both receive, not override one another.  Only when built
# with libConfuse.
if $SNMPD -h 2>&1 | grep -q -- '--file'; then
	print "Restarting with -T and a .conf trap-table, both must get coldStart ..."
	stop_snmpd
	TRAPLOG2="/tmp/$NM/trapd2.log"
	start_sink "$TRAPLOG2" 1620 "/tmp/$NM/trapd2.pid"
	: > "$TRAPLOG"			# only the new coldStart should match
	CONF="/tmp/$NM/test.conf"
	cat > "$CONF" <<EOF
community  = "$COMMUNITY"
trap-table = { "127.0.0.1" }
EOF
	start_snmpd -T 127.0.0.1:1620 -f "$CONF"
	expect_trap "$TRAPLOG"  "$COLDSTART" "coldStart (.conf sink)"
	expect_trap "$TRAPLOG2" "$COLDSTART" "coldStart (-T sink)"
fi

OK
