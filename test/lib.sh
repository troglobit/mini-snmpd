#!/bin/sh
# Helper functions for testing mini-snmpd
#
# Each test runs in its own mount + user + network namespace, courtesy
# of the `unshare -mrun --map-auto` wrapper in TESTS_ENVIRONMENT.  We are
# (mapped) root inside that namespace, so the daemon can bind the real
# SNMP port 161 without any elevated privileges on the host.

# Test name, used everywhere as /tmp/$NM/foo
NM=$(basename "$0" .sh)

# Path to the daemon under test (built one level up)
SNMPD=../mini-snmpd

# SNMP community and the address the daemon listens on inside the netns
COMMUNITY=public
HOST=127.0.0.1

# Print heading for test phases
print()
{
    printf "\e[7m>> %-76s\e[0m\n" "$1"
}

dprint()
{
    printf "\e[2m%-76s\e[0m\n" "$1"
}

SKIP()
{
    print "TEST: SKIP"
    [ $# -gt 0 ] && echo "$*"
    exit 77
}

FAIL()
{
    print "TEST: FAIL"
    [ $# -gt 0 ] && echo "$*"
    exit 99
}

OK()
{
    print "TEST: OK"
    [ $# -gt 0 ] && echo "$*"
    exit 0
}

# shellcheck disable=SC2068
check_dep()
{
    if ! command -v "$1" >/dev/null; then
	SKIP "Cannot find $1, skipping test."
    fi
}

# Retry $@ up to $1 seconds before giving up
# shellcheck disable=SC2068
tenacious()
{
    timeout=$1
    shift

    while [ "$timeout" -gt 0 ]; do
	$@ && return 0
	sleep 1
	timeout=$((timeout - 1))
    done

    FAIL "Timed out waiting for $*"
}

# Bring up loopback so the daemon has something to bind to, snmp tools
# something to talk to.  Called once per test from start_snmpd().
setup_lo()
{
    ip link set lo up
}

# Start mini-snmpd in the foreground (-n) inside the namespace, logging
# to a file, and record its PID for teardown.  Any extra arguments are
# passed straight through, e.g. -i eth0 or -D "description".
start_snmpd()
{
    setup_lo

    print "Starting mini-snmpd $* ..."
    $SNMPD -n -l debug "$@" > "/tmp/$NM/snmpd.log" 2>&1 &
    echo $! > "/tmp/$NM/snmpd.pid"

    # Wait for the daemon to answer before the test starts poking at it.
    # Probe with a numeric OID (sysUpTime.0) so we do not depend on the
    # net-snmp MIB files being installed.
    tenacious 5 snmpget -v1 -c $COMMUNITY -t 1 -r 0 $HOST \
	      .1.3.6.1.2.1.1.3.0 >/dev/null 2>&1
}

# Convenience wrappers around the net-snmp client tools
snmp_get()
{
    snmpget -v1 -c $COMMUNITY -On -t 2 -r 2 $HOST "$@"
}

snmp_walk()
{
    snmpwalk -v1 -c $COMMUNITY -On -t 2 -r 2 $HOST "$@"
}

teardown()
{
    if [ -f "/tmp/$NM/snmpd.pid" ]; then
	kill "$(cat "/tmp/$NM/snmpd.pid")" 2>/dev/null
    fi
    rm -rf "/tmp/$NM"
}

signal()
{
    echo
    [ "$1" != "EXIT" ] && print "Got signal, cleaning up"
    teardown
}

# props to https://stackoverflow.com/a/2183063/1708249
trapit()
{
    func="$1" ; shift
    for sig ; do
	trap "$func $sig" "$sig"
    done
}

# Runs once when including lib.sh
PATH=/sbin:/usr/sbin:$PATH
check_dep snmpget
check_dep snmpwalk
check_dep ip
mkdir -p "/tmp/$NM"
trapit signal INT TERM QUIT EXIT
