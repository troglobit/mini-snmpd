Mini SNMP Daemon
================
[![License Badge][]][License] [![Travis Status][]][Travis]

The Mini SNMP daemon is a minimal implementation of an SNMP daemon.  It
is targeted at embedded systems with limited disk and memory resources.
All configuration is done using command line arguments.  It supports
basic CPU, memory, disk, and network interface statistics.

`mini-snmpd` is not as flexibible as, and does not support the same
features as, the de-facto standard [net-snmp][], but this also means
it does not have the same footprint and overhead.

Supported features:

* SNMP version 1 and 2c (v3 is on the TODO list)
* Community string authentication when using 2c or explicitely configured
* Read-only access (writing is not supported)
* Includes basic system info like CPU load, memory, disk and network interfaces
* Does not need a configuation file
* Supports UDP and TCP (thus supports SSH tunneling of SNMP connections)
* Supports linux kernel versions 2.4 and 2.6
* Supports FreeBSD (needs procfs mounted using "mount_linprocfs procfs /proc")

`mini-snmpd` has only been tested on x86 and ARM platforms using
net-snmp as client, so big endian may not work.

- For info about licensing, see the file [COPYING][license]
- For info about using the program, see the file [mini_snmpd.8][man]
- For info about how to (cross)compile the program, see the file [Makefile][build]
- For info about how to extend the MIB, see the file [README.develop][contrib]


Examples
--------

Start the daemon:

    ./mini_snmpd -n -p 16161 -D "My laptop" -L "Batcave" \
                 -C "Ops <ops@example.comf>" -d '/' -i wlp3s0

Check uptime, useful to "ping" a device over SNMP:

    snmpget -c public -v2c 127.0.0.1:16161 system.sysUpTime.0
    DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (93103) 0:15:31.03

Complete walk:

    snmpwalk -v2c -c public 127.0.0.1:16161
    SNMPv2-MIB::sysDescr.0 = STRING: My laptop
    SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises
    DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (93103) 0:15:31.03
    SNMPv2-MIB::sysContact.0 = STRING: Ops <ops@example.com>
    SNMPv2-MIB::sysName.0 = STRING: luthien
    SNMPv2-MIB::sysLocation.0 = STRING: Batcave
    IF-MIB::ifNumber.0 = INTEGER: 1
    IF-MIB::ifIndex.1 = INTEGER: 1
    IF-MIB::ifDescr.1 = STRING: wlp3s0
    IF-MIB::ifType.1 = INTEGER: ethernetCsmacd(6)
    IF-MIB::ifMtu.1 = INTEGER: 1500
    IF-MIB::ifSpeed.1 = Gauge32: 1000000000
    IF-MIB::ifPhysAddress.1 = STRING: 6c:88:14:48:57:1c
    IF-MIB::ifAdminStatus.1 = INTEGER: up(1)
    IF-MIB::ifOperStatus.1 = INTEGER: up(1)
    IF-MIB::ifLastChange.1 = Timeticks: (0) 0:00:00.00
    IF-MIB::ifInOctets.1 = Counter32: 207845364
    IF-MIB::ifInUcastPkts.1 = Counter32: 154221
    IF-MIB::ifInDiscards.1 = Counter32: 0
    IF-MIB::ifInErrors.1 = Counter32: 0
    IF-MIB::ifOutOctets.1 = Counter32: 13323787
    IF-MIB::ifOutUcastPkts.1 = Counter32: 88071
    IF-MIB::ifOutDiscards.1 = Counter32: 0
    IF-MIB::ifOutErrors.1 = Counter32: 0
    HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (454155) 1:15:41.55

Check load average:

    snmpwalk -v2c -c public 127.0.0.1:16161 UCD-SNMP-MIB::laLoad
    UCD-SNMP-MIB::laLoad.1 = STRING: 0.56
    UCD-SNMP-MIB::laLoad.2 = STRING: 0.46
    UCD-SNMP-MIB::laLoad.3 = STRING: 0.36


Origin & References
-------------------

[mini-snmpd][github] on is an effort by [Joachim Nilsson][] to create a
focal point for patches and development of the original [mini_snmpd][1]
project by [Robert Ernst][], since the original site now has gone dark.

The new project is [maintained at GitHub][github]. Use its issue tracker
and pull request functions to report bugs or contribute new features.

[1]:               http://members.aon.at/linuxfreak/linux/mini_snmpd.html
[man]:             http://ftp.troglobit.com/mini-snmpd/mini-snmpd.html
[github]:          https://github.com/troglobit/mini-snmpd
[license]:         https://github.com/troglobit/mini-snmpd/blob/master/COPYING
[contrib]:         https://github.com/troglobit/mini-snmpd/blob/master/README.develop
[build]:           https://github.com/troglobit/mini-snmpd/blob/master/Makefile
[Joachim Nilsson]: http://troglobit.com
[Robert Ernst]:    <mailto:robert.ernst@aon.at>
[net-snmp]:        http://www.net-snmp.org/
[License]:         https://en.wikipedia.org/wiki/GPL_license
[License Badge]:   https://img.shields.io/badge/License-GPL%20v2-blue.svg
[Travis]:          https://travis-ci.org/troglobit/mini-snmpd
[Travis Status]:   https://travis-ci.org/troglobit/mini-snmpd.png?branch=master
