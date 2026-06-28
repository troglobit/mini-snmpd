#!/bin/sh
# Reload: SIGHUP re-reads the .conf over the command-line baseline, without
# touching the listening sockets.  This checks the tricky part of combining
# the two sources across reloads:
#
#   - a key set in the file overrides the matching command-line option
#   - deleting that key and reloading reverts to the command-line value,
#     i.e. the baseline is not lost
#   - list options (here -d) combine with the file and do not accumulate
#     when the same file is reloaded repeatedly
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.  Skipped when built without libConfuse.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

# Reload needs the .conf support, i.e. the -f/--file option
$SNMPD -h 2>&1 | grep -q -- '--file' || SKIP "built without libConfuse (.conf) support"

CONF="/tmp/$NM/test.conf"

# .1.3.6.1.2.1.1.6.0 -- sysLocation.0, .2021.9.1.2 -- UCD dskTable dskPath
sysLocation=.1.3.6.1.2.1.1.6.0
dskPath=.1.3.6.1.4.1.2021.9.1.2

reload()
{
	kill -HUP "$(cat "/tmp/$NM/snmpd.pid")"
}

# GET $1 and wait (up to 10s) for the response to contain $2
expect_reload()
{
	i=0
	while [ "$i" -lt 10 ]; do
		got=$(snmp_get "$1") && echo "$got" | grep -qF "$2" && {
			dprint "$got"
			return 0
		}
		sleep 1
		i=$((i + 1))
	done
	FAIL "GET $1: expected '$2', got '$got'"
}

# Count rows returned for the walk of $1
count()
{
	snmp_walk "$1" 2>/dev/null | grep -c .
}

# Start with a command-line location and disk, and an empty config file
: > "$CONF"
start_snmpd -L "cli-loc" -d /tmp -f "$CONF"

print "Baseline: the -L value is visible while the file is empty ..."
expect $sysLocation "cli-loc"

print "Set location in the file and reload: the file value wins ..."
echo 'location = "from-file"' > "$CONF"
reload
expect_reload $sysLocation "from-file"

print "Delete it and reload: revert to the -L value, not lost ..."
: > "$CONF"
reload
expect_reload $sysLocation "cli-loc"

print "disk-table combines with -d (expect 2: /tmp from -d, / from file) ..."
echo 'disk-table = { "/" }' > "$CONF"
reload

# dskPath is a table column, so walk it; wait for the combined list to settle
i=0
while [ "$i" -lt 10 ] && [ "$(count $dskPath)" != 2 ]; do
	sleep 1
	i=$((i + 1))
done
snmp_walk $dskPath | grep -qF /tmp || FAIL "-d /tmp lost across reload: $(snmp_walk $dskPath)"
before=$(count $dskPath)
[ "$before" = 2 ] || FAIL "expected 2 disks (/tmp + /), got $before: $(snmp_walk $dskPath)"

print "Reload the same file again: the list must not accumulate ..."
reload
sleep 2
after=$(count $dskPath)
[ "$before" = "$after" ] || FAIL "disk list grew across reload: $before -> $after"
dprint "dskTable rows stable at $after across reload"

OK
