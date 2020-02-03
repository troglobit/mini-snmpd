AC_INIT([mini-snmpd], [1.5-pre], [https://github.com/troglobit/mini-snmpd/issues],,
	[https://troglobit.com/projects/inadyn/])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([mini-snmpd.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG

AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h stdint.h stdlib.h syslog.h signal.h getopt.h arpa/inet.h sys/socket.h)
AC_CHECK_HEADERS(sys/time.h time.h sys/types.h net/if.h netinet/in.h)
AC_CHECK_FUNCS(strstr strtod strtoul strtok getopt)

### Check for configured features #############################################################
AC_ARG_WITH(vendor,
        AS_HELP_STRING([--with-vendor=OID], [Set a different vendor OID, default: .1.3.6.1.4.1]),
	[vendor="$withval"], [vendor=".1.3.6.1.4.1"])

AC_ARG_WITH([config],
        AS_HELP_STRING([--without-config], [Disable /etc/mini-snmpd.conf support using libConfuse]),,
	[with_config=yes])

AC_ARG_ENABLE(debug,
   AS_HELP_STRING([--enable-debug], [Enable debug mode, also set CFLAGS="-g -O0", disabled by default.]))

AC_ARG_ENABLE(demo,
   AS_HELP_STRING([--enable-demo], [Enable demo mode, for budding devs only. Disabled by default.]))

AC_ARG_ENABLE(ipv6,
   AS_HELP_STRING([--disable-ipv6], [Disable IPv6 support, enabled by default.]))

### Enable features ###########################################################################
AS_IF([test "x$with_vendor" != "xno"],[
	AS_IF([test "x$vendor" = "xyes"],[
		AC_MSG_ERROR([Must supply a valid vendor OID])])
	],[
	AC_MSG_ERROR([Vendor OID cannot currently be disabled, use default.])])
AC_DEFINE_UNQUOTED(VENDOR, ["$vendor"], [Vendor OID])

AS_IF([test "x$with_config" != "xno"], [
	AC_DEFINE([HAVE_LIBCONFUSE], [1], [Build with support for /etc/mini-snmpd.conf])
	PKG_CHECK_MODULES([confuse], [libconfuse >= 2.7])])
AM_CONDITIONAL([HAVE_CONFUSE], [test "x$with_config" != "xno"])

AS_IF([test "x$enable_debug" = "xyes"],[
   AC_DEFINE(DEBUG, 1, [Define to enable debug mode.])])

AS_IF([test "x$enable_demo" = "xyes"],[
   AC_DEFINE(CONFIG_ENABLE_DEMO, 1, [Define to enable demo mode.])])

AS_IF([test "x$enable_ipv6" != "xno"],[
   AC_DEFINE(CONFIG_ENABLE_IPV6, 1, [Define to enable IPv6 support.])])

### Generate all files ########################################################################
AC_OUTPUT
