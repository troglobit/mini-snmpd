[v1.3][] -- UNRELEASED
----------------------

### Changes

- New maintainer, [Joachim Nilsson](https://github.com/troglobit)
- Hosting is now on [GitHub](https://github.com/troglobit/mini-snmpd)
- Changed to GNU Configure and Build System, use `./autogen.sh` first if
  you checkout the sources from GIT.
- Add support for daemonizing automatically, `-n` for previous behavior.
- Add support for logging to syslog even when running in the foreground.

### Fixes
- Cleanup and code simplification fixes from
  [Javier Palacios](https://github.com/javiplx)
- Some bug fixes from the http://www.simtreas.ru/~dzo/busybox-vodz.html
  fork of mini-snmpd by Vladimir N. Oleynik <dzo@simtreas.ru>
  - Do not allow ':' as interface separator
  - Simplify `read_values()` and its callee's, skip optional ':'
  - Inspirations for lots of reduced stack usage
  - Fix typo in `setsockopt()`
- Massive code cleanup and simplification by Joachim Nilsson


[v1.2b][] -- 2010-03-28
-----------------------

### Changes

- Added support for compilation for IPv4-only kernels

### Fixes

- Fixed bug in encoding of integers with 24 significant bits


[v1.1][] - 2010-02-25
---------------------

### Changes

- Added support for IPv6


v1.0 - 2009-01-27
-----------------

### Fixes

- Fixed calculation of ticks since last MIB update (integer calculation
  resulted in overflows, updates not done in cases of error or time
  running backwards)


v0.8 - 2008-10-08
-----------------

### Fixes

- Fixed calculation of free inodes in percent for filesystems that do
  not support getting the number of inodes (for example FAT)


v0.7 - 2008-10-06
-----------------

### Fixes

- Fixed `get_process_uptime()` function to work regardless of time
  changes


v0.6 - 2008-10-04
-----------------

### Changes

- Split `utils.c` into common and operating-system specific functions
- Added an install target
- Added some developer documentation
- Added patches for FreeBSD support

### Fixes

- Reduced memory consumption: the `get*info()` functions now use a
  buffer provided by the caller rather than their static buffers


v0.5 - 2008-09-29
-----------------

### Changes

- Added CHANGELOG and TODO file
- Added a check for the file descriptors of TCP connections

v0.4 - 2008-09-28
-----------------

This is the first feature-complete version.  SNMP get, getnext, and
getbulk are supported on UDP and TCP connections.


[v1.3]:  https://github.com/troglobit/mini-snmpd/compare/v1.2b...HEAD
[v1.2b]: https://github.com/troglobit/mini-snmpd/compare/v1.1...v1.2b
[v1.1]:  https://github.com/troglobit/mini-snmpd/compare/v1.0...v1.1

<!--
  -- Local Variables:
  -- mode: markdown
  -- End:
  -->
