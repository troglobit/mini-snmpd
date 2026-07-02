# Extending mini-snmpd

mini-snmpd does not pass SNMP requests through to other processes, and it
does not load plugins.  To extend it with your own MIB variables you have
to build them in, as described below.

## Obtain a vendor OID

The default vendor OID is only a placeholder; insert the PEN (private
enterprise number) of your organization.  If you do not have one, IANA
assigns them free of charge, see the PEN application page at
<https://pen.iana.org/>.

Set the vendor OID at build time with `configure --with-vendor=OID`, or at
run time with the `-V` option.

## Write the MIB file

Not needed by mini-snmpd itself, but you should be prepared to hand your
users the MIB description in text form.  The net-snmp package has plenty of
examples to start from.

## Add a define and the code for your extension

Make the extension a compile-time option and keep its code in
`#ifdef`/`#endif` blocks, so built-in and added code stay easy to tell
apart.

The `demo` extension, two random integers, shows how (`CONFIG_ENABLE_DEMO`
in the sources).  It uses PEN 99999, which IANA has not assigned — and one
day might — so never enable the demo in a release build.

## Things to consider

- The MIB table has a fixed maximum length, `MAX_NR_VALUES`.  A runtime
  table-overflow error when creating an entry means you need to raise it.
- `mib_update()` runs on every request, so a handler can decide whether to
  refresh its variables every time (e.g. system uptime) or only on the
  interval set with `-t` (e.g. disk info).  Make slow or expensive updates
  depend on the timeout counter to save CPU.
- For an octet string, call `mib_build_entry()` with a string of the
  maximum length the variable can reach at run time; that is how it sizes
  the data buffer for the entry.
- If the value you read is OS dependent, put the code in `linux.c` and/or
  `freebsd.c`, not `utils.c`, which is for OS-independent helpers.
- For debug output use the `logit()` macro, not a raw `printf()` or
  `syslog()`.

Robert Ernst <robert.ernst@aon.at>
