Change Log
==========

All notable changes to the project are documented in this file.


[v1.6][] -- 2020-02-23
----------------------

Bug fix release.

### Changes
- Added debian/ packaging, available from https://deb.troglobit.com

### Fixes
- Fix #16: regression in ifTable for point-to-point interfaces
- Fix #17: major memory leak in Linux backend
- Fix #18: consistent timeout handling in .conf file and command line


[v1.5][] -- 2020-02-03
----------------------

Major feature release.  Support for TCP-MIB, UDP-MIB, IP-MIB,
ifXTable with 64-bit counters.

- Majority of new features from [NDM Systems][]
- CVE fixes from [Cisco Talos Intelligence Group][talos]

### Changes
- Add support for ifXTable (64-bit counters), from NDM Systems
- Add support for TCP-MIB, from NDM Systems
- Add support for UDP-MIB, from NDM Systems
- Add support for IP-MIB, from NDM Systems
- Add support for ifType
- Add support for ifMtu
- Binary and man page renamed: `mini_snmpd` --> `mini-snmpd`
- New command line option `-l LEVEL` replaces `--verbose`
- New command line option `-v` to show program version
- Create PID file when daemon is ready to receive signals
- Add support for systemd unit file on Linux
- Add support for /etc/mini-snmpd.conf, disabled by default

### Fixes
- CVE-2020-6060: Fix stack overflow in client connection handler
- CVE-2020-6059: Fix out-of-bounds read in parsing of SNMP packet
- CVE-2020-6058: Fix out-of-bounds read in parsing of SNMP packet
- Let `-s` flag control use of syslog, when running in foreground
- Removed all (known) GNU:isms; i.e., `__progname` and `%m`


[v1.4][] -- 2017-06-26
----------------------

Bug fix release, courtesy of Andre Grosse Bley, @Haeretiker.

### Changes
- Increase MIB table size: 128 --> 192

### Fixes
- Fix default install directory: `$prefix/bin` --> `$prefix/sbin`
- Fix inverted enable/disable options to `configure` script, issue #4
- Incorrect OID types: `ifLastChange` should be `BER_TYPE_TIME_TICKS`
  and `ifSpeed` should be `BER_TYPE_GAUGE`, issue #1
- Fix `parse_line()` to prevent partial matches: `wlan0` matched both
  `wlan0-1` and `wlan0-2`, issue #1
- Fix `parse_lineint()` to prevent partial matches, issue #1
- Response OID order match with request order, reversed order breaks at
  least the MRTG SNMP client, issue #1
- Traffic counters get stuck after 4GB traffic.  Use `strtoull()` rather
  than `strtoul()` to parse numbers, issue #1
- OIDs in request can be in any order.  Reset OID table position after
  each handled OID from request, issue #1


[v1.3][] -- 2015-11-23
----------------------

### Changes

- Refactor and cleanup by [Javier Palacios][palacios]
- New maintainer, [Joachim Nilsson][troglobit]
- Hosting is now on [GitHub][home]
- Changed to GNU Configure and Build System, use `./autogen.sh` for
  first time checkout from GIT
- Reduced stack usage in Linux `/proc` file parser backend
- Add support for daemonizing automatically, `-n` for previous behavior
- Add support for logging to syslog even when running in the foreground
- Complete refactor of FreeBSD support.  Now with native syscalls instead
  of requirment for Linux `/proc` file system
- Add support for daemonizing by default, use `-n` to run in foreground
- Add support for syslog even if running in the foreground
- Dual stack support, IPv4 default, when building with `--enable-ipv6`,
  which is also default
- Use `sigaction()` instead of `signal()` and `siginterrupt()`, by
  [Henrik Nordstrom][hno]
- Increase MAX number of interfaces to monitor from four to eight, by
  [Henrik Nordstrom][hno]

### Fixes
- From [Vladimir N. Oleynik][dzo]'s [Busybox fork][vodz-fork]:
  - Do not allow ':' as interface separator
  - Simplify `read_values()` and its callee's, skip optional ':'
  - Inspirations for lots of reduced stack usage
  - Fix typo in `setsockopt()`
- Massive code cleanup and simplification by [Joachim Nilsson][troglobit]
- FreeBSD build fixes, e.g. `SO_BINDDEVICE` socket option does not exist
- Display OK log message *after* successful socket & bind


[v1.2b][] -- 2010-03-28
-----------------------

### Changes

- Added support for compilation for IPv4-only kernels

### Fixes

- Fixed bug in encoding of integers with 24 significant bits


[v1.1][] -- 2010-02-25
----------------------

### Changes

- Added support for IPv6


v1.0 -- 2009-01-27
------------------

### Fixes

- Fixed calculation of ticks since last MIB update (integer calculation
  resulted in overflows, updates not done in cases of error or time
  running backwards)


v0.8 -- 2008-10-08
------------------

### Fixes

- Fixed calculation of free inodes in percent for filesystems that do
  not support getting the number of inodes (for example FAT)


v0.7 -- 2008-10-06
------------------

### Fixes

- Fixed `get_process_uptime()` function to work regardless of time
  changes


v0.6 -- 2008-10-04
------------------

### Changes

- Split `utils.c` into common and operating-system specific functions
- Added an install target
- Added some developer documentation
- Added patches for FreeBSD support

### Fixes

- Reduced memory consumption: the `get*info()` functions now use a
  buffer provided by the caller rather than their static buffers


v0.5 -- 2008-09-29
------------------

### Changes

- Added CHANGELOG and TODO file
- Added a check for the file descriptors of TCP connections

v0.4 -- 2008-09-28
------------------

This is the first feature-complete version.  SNMP get, getnext, and
getbulk are supported on UDP and TCP connections.


[UNRELEASED]:  https://github.com/troglobit/mini-snmpd/compare/v1.6...HEAD
[v1.6]:        https://github.com/troglobit/mini-snmpd/compare/v1.5...v1.6
[v1.5]:        https://github.com/troglobit/mini-snmpd/compare/v1.4...v1.5
[v1.4]:        https://github.com/troglobit/mini-snmpd/compare/v1.3...v1.4
[v1.3]:        https://github.com/troglobit/mini-snmpd/compare/v1.2b...v1.3
[v1.2b]:       https://github.com/troglobit/mini-snmpd/compare/v1.1...v1.2b
[v1.1]:        https://github.com/troglobit/mini-snmpd/compare/v1.0...v1.1
[dzo]:         <mailto:dzo@simtreas.ru>
[hno]:         https://github.com/hno
[home]:        https://github.com/troglobit/mini-snmpd
[palacios]:    https://github.com/javiplx
[NDM Systems]: https://github.com/ndmsystems
[talos]:       https://twitter.com/talossecurity
[troglobit]:   https://github.com/troglobit
[vodz-fork]:   http://www.simtreas.ru/~dzo/busybox-vodz.html
