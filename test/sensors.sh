#!/bin/sh
# LM-SENSORS-MIB lmTempSensorsTable: hwmon temperatures, milli-degrees C.
# Skipped on machines without any hwmon temperature sensor, e.g. most VMs.
#
# Numeric OIDs are used so the test does not depend on the net-snmp MIB
# files being installed.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

ls /sys/class/hwmon/hwmon*/temp*_input >/dev/null 2>&1 \
	|| SKIP "no hwmon temperature sensors on this machine"

lmTempSensorsDevice=.1.3.6.1.4.1.2021.13.16.2.1.2
lmTempSensorsValue=.1.3.6.1.4.1.2021.13.16.2.1.3

start_snmpd -i lo

print "Sensor table has one device name per value ..."
ndev=$(snmp_walk $lmTempSensorsDevice | grep -c "STRING")
nval=$(snmp_walk $lmTempSensorsValue  | grep -c "Gauge32")
dprint "devices: $ndev, values: $nval"
[ "$ndev" -ge 1 ]        || FAIL "no sensor rows despite hwmon present"
[ "$ndev" = "$nval" ]    || FAIL "row mismatch: $ndev devices, $nval values"

print "First sensor reads as a Gauge32 ..."
expect $lmTempSensorsValue.1 "Gauge32"

OK
