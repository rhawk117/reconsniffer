# reconsniff

passive network reconnaissance sniffer for local network security research. captures and parses service-discovery and identity-revealing traffic, renders it in a rich terminal ui, and writes structured json log files.

## protocols

| protocol | description |
|---|---|
| `arp` | layer-2 address resolution, probes, and announcements |
| `dhcp` | ipv4 lease requests and offers (ports 67/68) |
| `dhcpv6` | ipv6 stateful address configuration (ports 546/547) |
| `dns` | classic unicast queries and responses (port 53) |
| `mdns` | multicast dns, service discovery on the local link (port 5353) |
| `llmnr` | link-local multicast name resolution (port 5355) |
| `nbns` | netbios name service (port 137) |
| `ssdp` | upnp device and service discovery (port 1900) |
| `icmpv6-nd` | neighbor solicitation/advertisement, router advertisement |
| `tls` | tls client hello, server hello, and certificate handshake messages |

## requirements

- Python >= 3.13
- root / administrator privileges for raw packet capture

## installation

```bash
# with uv (recommended)
uv pip install -e .

# or with pip
pip install -e .
```

## usage

```bash
sudo reconsniff [options]
# or
sudo python -m reconsniff [options]
```

### basic examples

```bash
# capture on a specific interface, write logs to a custom path
sudo reconsniff -i eth0 -o logs/reconsniff.log

# raise the log level and keep packets in memory for debugging
sudo reconsniff --log-level debug --store-packets

# drop noisy or irrelevant protocols
sudo reconsniff --no-tls --no-dhcp --no-dhcpv6

# inspect what bpf filter will be used before running
reconsniff --show-filter
reconsniff --no-tls --no-arp --show-filter

# dump the resolved configuration as json and exit
reconsniff --show-config
```

## options reference

```
capture options:
  -i, --interface IFACE     interface to sniff on (scapy default when omitted)
  --store-packets           keep packets in memory (debug only)

logging options:
  -o, --output FILE         json log output file (default: reconsniff.log)
  --log-level LEVEL         TRACE|DEBUG|INFO|SUCCESS|WARNING|ERROR|CRITICAL

port overrides:
  --dns-port PORT           default 53
  --mdns-port PORT          default 5353
  --ssdp-port PORT          default 1900

multicast overrides:
  --mdns-multicast-ipv4     default 224.0.0.251
  --ssdp-multicast-ipv4     default 239.255.255.250
  --ssdp-multicast-ipv6     default ff02::c

protocol filters:
  --no-arp  --no-dhcp  --no-dhcpv6  --no-dns  --no-mdns
  --no-llmnr  --no-nbns  --no-ssdp  --no-icmpv6nd  --no-tls

information:
  --show-filter             print computed bpf filter and exit
  --show-config             print resolved config as json and exit
```

## log format

each line in the output file is a json object. event types:

**startup**
```json
{"ts": "2024-01-15T10:30:00+00:00", "level": "INFO", "message": "capture started",
 "event_type": "startup", "interface": "eth0", "bpf_filter": "arp or udp port 53 ...",
 "excluded_protocols": [], "log_level": "INFO"}
```

**packet**
```json
{"ts": "2024-01-15T10:30:01+00:00", "level": "INFO",
 "message": "DNS q=example.com response=False rcode=0",
 "event_type": "packet", "protocol": "dns",
 "src": "192.168.1.5:52341", "dst": "8.8.8.8:53",
 "data": {"transaction_id": 12345, "is_response": false, "questions": [...]}}
```

**shutdown**
```json
{"ts": "2024-01-15T10:31:00+00:00", "level": "INFO", "message": "capture stopped",
 "event_type": "shutdown", "protocols": {"dns": 42, "mdns": 13}, "errors": {}}
```

parse with `jq`:
```bash
# stream all packet events
jq 'select(.event_type == "packet")' reconsniff.log

# filter by protocol
jq 'select(.protocol == "mdns")' reconsniff.log

# extract unique source addresses seen
jq -r 'select(.event_type == "packet") | .src' reconsniff.log | sort -u
```

## notes

- raw packet capture requires root on linux/macos and administrator on windows
- `--no-<protocol>` removes the protocol from both the bpf filter and the parser registry, reducing cpu and disk usage
- tls parsers detect handshake type from the wire but field extraction (sni, ciphers, certificates) is not yet implemented
- the rich console output is for interactive triage; the log file is the authoritative structured record
