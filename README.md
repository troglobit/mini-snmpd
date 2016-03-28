Mini SNMP Daemon
================
[![Travis Status][]][Travis]

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
* Ability to send traps on free disk space, CPU load, network interface status
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


Bugs & Features
---------------

The `mini-snmpd` project is [maintained at GitHub][github], use its
issue tracker and pull request functions to report bugs or contribute
new features.


Origin & References
-------------------

This is an attempt to recreate the original [mini_snmpd project][1], by
[Robert Ernst][author], since the original site now has gone dark.  The
new maintainer did however not recover more than the latest three
releases: 1.0, 1.1, and 1.2b.

[1]: http://members.aon.at/linuxfreak/linux/mini_snmpd.html
[man]: http://ftp.troglobit.com/mini-snmpd/mini-snmpd.html
[github]: https://github.com/troglobit/mini-snmpd
[license]: https://github.com/troglobit/mini-snmpd/blob/master/COPYING
[contrib]: https://github.com/troglobit/mini-snmpd/blob/master/README.develop
[build]: https://github.com/troglobit/mini-snmpd/blob/master/Makefile
[author]: <mailto:robert.ernst@aon.at>
[net-snmp]: http://www.net-snmp.org/
[Travis]: https://travis-ci.org/troglobit/mini-snmpd
[Travis Status]: https://travis-ci.org/troglobit/mini-snmpd.png?branch=master
