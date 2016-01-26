# Use v2.61 for backwards compat with Ubuntu 12.04 LTS
AC_PREREQ([2.61])
AC_INIT([mini-snmpd],[1.4-rc1],[https://github.com/troglobit/mini-snmpd/issues])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([mini_snmpd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AC_PROG_INSTALL

dnl - Configuration.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h stdint.h stdlib.h syslog.h signal.h getopt.h arpa/inet.h sys/socket.h)
AC_CHECK_HEADERS(sys/time.h time.h sys/types.h net/if.h netinet/in.h)
AC_CHECK_FUNCS(strstr strtod strtoul strtok getopt)

dnl Check for uint[8,16,32]_t
dnl AC_TYPE_UINT8_T
dnl AC_TYPE_UINT16_T
dnl AC_TYPE_UINT32_T

AC_ARG_WITH(vendor,
   [AS_HELP_STRING([--with-vendor=OID], [Set a different vendor OID, default: .1.3.6.1.4.1])],
   [AC_DEFINE_UNQUOTED(VENDOR, "$withval")],
   [AC_DEFINE_UNQUOTED(VENDOR, ".1.3.6.1.4.1", [Vendor OID])])

AC_ARG_ENABLE(debug,
   [AS_HELP_STRING([--enable-debug], [Enable debug mode, also set CFLAGS="-g -O0".])],
   AC_DEFINE(DEBUG, 1, [Define to enable debug mode.]))

AC_ARG_ENABLE(demo,
   [AS_HELP_STRING([--enable-demo], [Enable demo mode.])],
   AC_DEFINE(CONFIG_ENABLE_DEMO, 1, [Define to enable demo mode.]))

AC_ARG_ENABLE(ipv6,
   [AS_HELP_STRING([--disable-ipv6], [Disable IPv6 support.])],
   , AC_DEFINE(CONFIG_ENABLE_IPV6, 1, [Define to enable IPv6 support.]))

AC_OUTPUT
