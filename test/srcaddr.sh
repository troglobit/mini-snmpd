#!/bin/sh
# Test: UDP reply uses the request's destination address (multi-homed).
#
# Binds mini-snmpd to the wildcard address, adds a secondary address to
# loopback, then checks that a request sent to the secondary address is
# answered FROM that same address -- not from the primary 127.0.0.1,
# which is what the kernel would pick by routing without the IP_PKTINFO
# source-address handling.
#
# The live capture uses tshark (its dumpcap helper works under the
# GitHub CI AppArmor profile, plain tcpdump capture does not); the saved
# pcap is then analyzed offline with tcpdump.  Skipped if either tool is
# missing, or where the daemon was built without the support (non-Linux).

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

check_dep tshark
check_dep tcpdump

SECOND=127.0.0.2
PORT=161
sysUpTime=.1.3.6.1.2.1.1.3.0
PCAP="/tmp/$NM/pcap"

setup_lo
ip addr add "$SECOND/8" dev lo 2>/dev/null

start_snmpd

print "Capturing the exchange with $SECOND ..."
tshark -ni lo -f "udp port $PORT" -c 2 -w "$PCAP" >/dev/null 2>&1 &
tpid=$!
sleep 2				# let dumpcap initialize

# Query until tshark has captured the request+reply pair and exited on
# its own (-c 2).  Looping avoids racing on the capture startup latency.
i=0
while kill -0 "$tpid" 2>/dev/null && [ "$i" -lt 10 ]; do
	snmpget -v2c -c "$COMMUNITY" -t 1 -r 0 "$SECOND:$PORT" $sysUpTime >/dev/null 2>&1
	sleep 1
	i=$((i + 1))
done
kill "$tpid" 2>/dev/null
wait "$tpid" 2>/dev/null

print "Reply must originate from $SECOND ..."
out=$(tcpdump -nr "$PCAP" 2>/dev/null)
echo "$out"
echo "$out" | grep -qE "IP $SECOND\.$PORT > " \
    || FAIL "reply did not come from $SECOND, source-address handling not working"

OK
