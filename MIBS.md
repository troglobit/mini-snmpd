# Supported MIBs

This is the list of MIBs and objects mini-snmpd serves.  It doubles as
the conformance statement: if an object is not listed here, the agent
does not implement it.

Values come from the operating system back-end: `/proc` and `/sys` on
Linux, `sysctl` on FreeBSD.  Interface and disk tables are populated for
the interfaces and mount points selected with `-i` and `-d`.

> [!NOTE]
> The `enterprises.99999` demo MIB is built only with `--enable-demo`
> and is not described here.

## SNMPv2-MIB, system group

`1.3.6.1.2.1.1`

| OID  | Object      | Type          | Source                                      |
|------|-------------|---------------|---------------------------------------------|
| .1.0 | sysDescr    | DisplayString | `-D`, else `PRETTY_NAME` from os-release(5) |
| .2.0 | sysObjectID | OID           | `-V` vendor OID                             |
| .3.0 | sysUpTime   | TimeTicks     | process uptime                              |
| .4.0 | sysContact  | DisplayString | `-C`                                        |
| .5.0 | sysName     | DisplayString | `gethostname()`                             |
| .6.0 | sysLocation | DisplayString | `-L`                                        |
| .7.0 | sysServices | INTEGER       | fixed, layers 1-4 and 7                     |

## IF-MIB, interfaces group

`1.3.6.1.2.1.2` — one row per `-i` interface.

| OID      | Object         | Type                     |
|----------|----------------|--------------------------|
| 2.1.0    | ifNumber       | INTEGER                  |
| 2.2.1.1  | ifIndex        | INTEGER                  |
| 2.2.1.2  | ifDescr        | DisplayString            |
| 2.2.1.3  | ifType         | INTEGER (ethernetCsmacd) |
| 2.2.1.4  | ifMtu          | INTEGER                  |
| 2.2.1.5  | ifSpeed        | Gauge32                  |
| 2.2.1.6  | ifPhysAddress  | PhysAddress              |
| 2.2.1.7  | ifAdminStatus  | INTEGER                  |
| 2.2.1.8  | ifOperStatus   | INTEGER                  |
| 2.2.1.9  | ifLastChange   | TimeTicks                |
| 2.2.1.10 | ifInOctets     | Counter32                |
| 2.2.1.11 | ifInUcastPkts  | Counter32                |
| 2.2.1.13 | ifInDiscards   | Counter32                |
| 2.2.1.14 | ifInErrors     | Counter32                |
| 2.2.1.16 | ifOutOctets    | Counter32                |
| 2.2.1.17 | ifOutUcastPkts | Counter32                |
| 2.2.1.19 | ifOutDiscards  | Counter32                |
| 2.2.1.20 | ifOutErrors    | Counter32                |

## IF-MIB, ifXTable

`1.3.6.1.2.1.31.1.1.1` — the high-capacity counters, one row per `-i`
interface.  Poll the 64-bit octet counters on links faster than ~100
Mbit, where the 32-bit ifTable counters wrap too quickly.

| OID | Object                     | Type          |
|-----|----------------------------|---------------|
| .1  | ifName                     | DisplayString |
| .2  | ifInMulticastPkts          | Counter32     |
| .3  | ifInBroadcastPkts          | Counter32     |
| .4  | ifOutMulticastPkts         | Counter32     |
| .5  | ifOutBroadcastPkts         | Counter32     |
| .6  | ifHCInOctets               | Counter64     |
| .7  | ifHCInUcastPkts            | Counter64     |
| .8  | ifHCInMulticastPkts        | Counter64     |
| .9  | ifHCInBroadcastPkts        | Counter64     |
| .10 | ifHCOutOctets              | Counter64     |
| .11 | ifHCOutUcastPkts           | Counter64     |
| .12 | ifHCOutMulticastPkts       | Counter64     |
| .13 | ifHCOutBroadcastPkts       | Counter64     |
| .14 | ifLinkUpDownTrapEnable     | INTEGER       |
| .15 | ifHighSpeed                | Gauge32       |
| .16 | ifPromiscuousMode          | INTEGER       |
| .17 | ifConnectorPresent         | INTEGER       |
| .18 | ifAlias                    | DisplayString |
| .19 | ifCounterDiscontinuityTime | TimeTicks     |

## IP-MIB

`1.3.6.1.2.1.4`

| OID    | Object           | Type      |
|--------|------------------|-----------|
| .1.0   | ipForwarding     | INTEGER   |
| .2.0   | ipDefaultTTL     | INTEGER   |
| .13.0  | ipReasmTimeout   | INTEGER   |
| 20.1.1 | ipAdEntAddr      | IpAddress |
| 20.1.2 | ipAdEntIfIndex   | INTEGER   |
| 20.1.3 | ipAdEntNetMask   | IpAddress |
| 20.1.4 | ipAdEntBcastAddr | INTEGER   |

## TCP-MIB

`1.3.6.1.2.1.6` — the scalar counters, not the connection table.

| OID   | Object          | Type      |
|-------|-----------------|-----------|
| .1.0  | tcpRtoAlgorithm | INTEGER   |
| .2.0  | tcpRtoMin       | INTEGER   |
| .3.0  | tcpRtoMax       | INTEGER   |
| .4.0  | tcpMaxConn      | INTEGER   |
| .5.0  | tcpActiveOpens  | Counter32 |
| .6.0  | tcpPassiveOpens | Counter32 |
| .7.0  | tcpAttemptFails | Counter32 |
| .8.0  | tcpEstabResets  | Counter32 |
| .9.0  | tcpCurrEstab    | Gauge32   |
| .10.0 | tcpInSegs       | Counter32 |
| .11.0 | tcpOutSegs      | Counter32 |
| .12.0 | tcpRetransSegs  | Counter32 |
| .14.0 | tcpInErrs       | Counter32 |
| .15.0 | tcpOutRsts      | Counter32 |

## UDP-MIB

`1.3.6.1.2.1.7`

| OID  | Object            | Type      |
|------|-------------------|-----------|
| .1.0 | udpInDatagrams    | Counter32 |
| .2.0 | udpNoPorts        | Counter32 |
| .3.0 | udpInErrors       | Counter32 |
| .4.0 | udpOutDatagrams   | Counter32 |
| .8.0 | udpHCInDatagrams  | Counter64 |
| .9.0 | udpHCOutDatagrams | Counter64 |

## HOST-RESOURCES-MIB

`1.3.6.1.2.1.25`

### System, `.1`

| OID  | Object         | Type      |
|------|----------------|-----------|
| .1.0 | hrSystemUptime | TimeTicks |

### Storage, `.2`

| OID  | Object       | Type         |
|------|--------------|--------------|
| .2.0 | hrMemorySize | INTEGER (kB) |

`hrStorageTable`, `.3.1` — one row for physical memory, then one per `-d`
mount point.  `hrStorageSize`/`hrStorageUsed` are in `hrStorageAllocationUnits`,
which mini-snmpd reports as 1024 (i.e. kB).

| OID | Object                   | Type            |
|-----|--------------------------|-----------------|
| .1  | hrStorageIndex           | INTEGER         |
| .2  | hrStorageType            | OID             |
| .3  | hrStorageDescr           | DisplayString   |
| .4  | hrStorageAllocationUnits | INTEGER (bytes) |
| .5  | hrStorageSize            | INTEGER         |
| .6  | hrStorageUsed            | INTEGER         |

### Device, `.3`

`hrProcessorTable`, `.3.3.1` — one row per logical CPU.  `hrProcessorLoad`
is the percentage of time the CPU was busy since the previous poll.

| OID | Object           | Type                    |
|-----|------------------|-------------------------|
| .1  | hrProcessorFrwID | OID (`.0.0`, unknown)   |
| .2  | hrProcessorLoad  | INTEGER (0-100, % busy) |

## UCD-SNMP-MIB

`1.3.6.1.4.1.2021` — memory, disk, load average, and CPU statistics.

### Memory, `.4`

| OID   | Object       | Type         |
|-------|--------------|--------------|
| .5.0  | memTotalReal | INTEGER (kB) |
| .6.0  | memAvailReal | INTEGER (kB) |
| .13.0 | memShared    | INTEGER (kB) |
| .14.0 | memBuffer    | INTEGER (kB) |
| .15.0 | memCached    | INTEGER (kB) |

### Disk, `.9.1` — one row per `-d` mount point

| OID | Object         | Type          |
|-----|----------------|---------------|
| .1  | dskIndex       | INTEGER       |
| .2  | dskPath        | DisplayString |
| .6  | dskTotal       | INTEGER (kB)  |
| .7  | dskAvail       | INTEGER (kB)  |
| .8  | dskUsed        | INTEGER (kB)  |
| .9  | dskPercent     | INTEGER       |
| .10 | dskPercentNode | INTEGER       |

### Load average, `.10.1` — rows for the 1, 5, and 15 minute averages

| OID | Object    | Type          |
|-----|-----------|---------------|
| .1  | laIndex   | INTEGER       |
| .2  | laNames   | DisplayString |
| .3  | laLoad    | DisplayString |
| .4  | laConfig  | DisplayString |
| .5  | laLoadInt | INTEGER       |

### CPU, `.11`

| OID   | Object          | Type      |
|-------|-----------------|-----------|
| .50.0 | ssCpuRawUser    | Counter32 |
| .51.0 | ssCpuRawNice    | Counter32 |
| .52.0 | ssCpuRawSystem  | Counter32 |
| .53.0 | ssCpuRawIdle    | Counter32 |
| .59.0 | ssRawInterrupts | Counter32 |
| .60.0 | ssRawContexts   | Counter32 |
