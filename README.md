Mini SNMP Daemon
================
[![License Badge][]][License] [![Travis Status][]][Travis] [![Coverity Status][]][Coverity Scan]

> The [latest release][releases] is always available from GitHub.
> Download only versioned tarballs, `mini-snmpd-X.Y.tar.gz`.  See
> below for instructions on how to build.

Table of Contents
-----------------

* [Introduction](#introduction)
* [Examples](#examples)
* [Build & Install](#build--install)
* [Building from GIT](#building-from-git)
* [Origin & References](#origin--references)


Introduction
------------

The Mini SNMP daemon is a minimal implementation of an SNMP daemon.  It
is primarily targeted at embedded systems with limited disk and memory
resources.  All configuration can be done using command line arguments,
but it also supports a minimal `.conf` file.  It supports basic CPU,
memory, disk, and network interface statistics.

`mini-snmpd` is not as flexibible as, and does not support the same
features as, the de-facto standard [net-snmp][], but this also means
it does not have the same footprint and overhead.

Supported features:

* SNMP version 1 and 2c (v3 is on the TODO list)
* Community string authentication when using 2c or explicitely configured
* Read-only access (writing is not supported)
* Includes basic system info like CPU load, memory, disk and network interfaces
* Does not need a configuration file, but one is supported
* Supports UDP and TCP (thus supports SSH tunneling of SNMP connections)
* Supports linux kernel versions 2.4 and 2.6
* Supports FreeBSD (needs procfs mounted using "mount_linprocfs procfs /proc")

`mini-snmpd` has only been tested on x86 and ARM platforms using
net-snmp as client, so big endian may not work.

- For info about licensing, see the file [COPYING][license]
- For info about using the program, see the file [mini-snmpd.8][man]
- For info about how to (cross)compile the program, see the file [Makefile][build]
- For info about how to extend the MIB, see the file [README.develop][contrib]


Examples
--------

Start the daemon:

    ./mini-snmpd -n -p 16161 -D "My laptop" -L "Batcave" \
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

Check monitored disks:

    snmpwalk -v2c -c public 127.0.0.1:16161 UCD-SNMP-MIB::dskTable
    UCD-SNMP-MIB::dskIndex.1 = INTEGER: 1
    UCD-SNMP-MIB::dskPath.1 = STRING: /
    UCD-SNMP-MIB::dskTotal.1 = INTEGER: 245084448
    UCD-SNMP-MIB::dskAvail.1 = INTEGER: 38953552
    UCD-SNMP-MIB::dskUsed.1 = INTEGER: 206130896
    UCD-SNMP-MIB::dskPercent.1 = INTEGER: 85
    UCD-SNMP-MIB::dskPercentNode.1 = INTEGER: 10


Build & Install
---------------

The [GNU Configure & Build][buildsystem] system use `/usr/local` as the
default install prefix.  Usually this is sufficient, the below example
installs to `/usr` instead:

    tar xf mini-snmpd-X.Y.tar.xz
	cd mini-snmpd-X.Y/
    ./configure --prefix=/usr
    make -j5
    sudo make install-strip

To use the `/etc/mini-snmpd.conf` support, both the `pkgconfig` and
`libConfuse` packages must be installed.  Installing from pre-built
packages differ between systems, check naming and suffix (`-dev`) to
match your system.

> **Note:** mini-snmpd-X.Y.tar.gz is not an actual release.  See the
> [releases page on GitHub][releases] for the latest versioned release.


Building from GIT
-----------------

If you want to contribute, or simply want to try out the latest but
still unreleased features, then you need to know a few things about
the [GNU Configure & Build][buildsystem] system:

- `configure.ac` and a per-directory `Makefile.am` are key files
- `configure` and `Makefile.in` are generated from `autogen.sh`,
  they are not stored in GIT but automatically generated for the
  release tarballs
- `Makefile` is generated by `configure` script

To build from GIT you first need to clone the repository and run the
`autogen.sh` script.  This requires `automake` and `autoconf` to be
installed on your system.

    git clone https://github.com/troglobit/mini-snmpd.git
    cd mini-snmpd/
    ./autogen.sh
    ./configure && make

GIT sources are a moving target and are not recommended for production
systems, unless you know what you are doing!


Origin & References
-------------------

[mini-snmpd][github] is an effort by [Joachim Nilsson][] to create a
focal point for patches and development of the original [mini_snmpd][1]
project by [Robert Ernst][], since the original site now has gone dark.

The new project is [maintained at GitHub][github]. Use its issue tracker
and pull request functions to report bugs or contribute new features.

[1]:               http://members.aon.at/linuxfreak/linux/mini_snmpd.html
[man]:             https://man.troglobit.com/man8/mini-snmpd.8.html
[github]:          https://github.com/troglobit/mini-snmpd
[license]:         https://github.com/troglobit/mini-snmpd/blob/master/COPYING
[contrib]:         https://github.com/troglobit/mini-snmpd/blob/master/README.develop
[build]:           https://github.com/troglobit/mini-snmpd/blob/master/Makefile
[Joachim Nilsson]: https://troglobit.com
[Robert Ernst]:    <mailto:robert.ernst@aon.at>
[net-snmp]:        https://www.net-snmp.org/
[buildsystem]:     https://airs.com/ian/configure/
[releases]:        https://github.com/troglobit/mini-snmpd/releases
[License]:         https://en.wikipedia.org/wiki/GPL_license
[License Badge]:   https://img.shields.io/badge/License-GPL%20v2-blue.svg
[Travis]:          https://travis-ci.org/troglobit/mini-snmpd
[Travis Status]:   https://travis-ci.org/troglobit/mini-snmpd.png?branch=master
[Coverity Scan]:   https://scan.coverity.com/projects/15696
[Coverity Status]: https://scan.coverity.com/projects/15696/badge.svg
