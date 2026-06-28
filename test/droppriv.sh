#!/bin/sh
# Drop privileges: -u USER must switch to the user's *primary* group taken
# from the passwd entry -- not a group named after the user, which is not
# guaranteed to exist -- and must drop root's supplementary groups.
#
# This is a regression test for the old getgrnam(user) logic, which looked
# up a group by the user's name and refused to start for an account like
# 'nobody' that has no same-named group.
#
# Runs as (mapped) root inside the test's user namespace, so the daemon can
# actually call setuid/setgid.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

DROP=nobody
id "$DROP" >/dev/null 2>&1 || SKIP "no '$DROP' account to drop to"
uid=$(id -u "$DROP")
gid=$(id -g "$DROP")

# start_snmpd() waits for the daemon to answer.  With the old by-name GID
# logic it would have exited here (there is no 'nobody' group), so reaching
# a reply at all is already the core of the regression check.
start_snmpd -u "$DROP"
pid=$(cat "/tmp/$NM/snmpd.pid")

print "Daemon switched to $DROP's uid/gid ($uid/$gid) ..."
ruid=$(awk '/^Uid:/ { print $2 }' "/proc/$pid/status")
rgid=$(awk '/^Gid:/ { print $2 }' "/proc/$pid/status")
dprint "Uid: $ruid  Gid: $rgid"
[ "$ruid" = "$uid" ] || FAIL "expected uid $uid, daemon runs as $ruid"
[ "$rgid" = "$gid" ] || FAIL "expected gid $gid (primary group), daemon runs as $rgid"

print "Root's supplementary groups were dropped ..."
groups=$(awk '/^Groups:/ { $1 = ""; print }' "/proc/$pid/status")
dprint "Groups:$groups"
for g in $groups; do
	[ "$g" = 0 ] && FAIL "retained root supplementary group, Groups:$groups"
done

OK
