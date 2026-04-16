# reconsniff

`reconsniff` is a lightweight network reconnaissance sniffer focused on
service-discovery traffic commonly useful during local network security research.

it captures and displays:

- dns
- mdns
- ssdp

it renders rich console output for interactive use and writes structured json
events to a rotating log file.

## requirements

- Python >=3.14
- uv package manager (reccomended)

## features

- async packet capture with scapy
- rich terminal rendering
- rotating file logs via loguru
- configurable ports and multicast targets

## installation

```bash
uv add scapy loguru rich
```

for editable local development:

```bash
uv pip install -e .
```

## usage

```bash
sudo python -m reconsniff --interface eth0 --output logs/reconsniff.log
```

or after install:

```bash
reconsniff --interface eth0 --output logs/reconsniff.log
```

## example

```bash
sudo reconsniff \
    --interface eth0 \
    --output logs/reconsniff.log \
    --log-level info \
    --dns-port 53 \
    --mdns-port 5353 \
    --ssdp-port 1900 \
    --mdns-multicast-ipv4 224.0.0.251 \
    --ssdp-multicast-ipv4 239.255.255.250 \
    --ssdp-multicast-ipv6 ff02::c
```

## notes

- root or administrator privileges are typically required for packet capture
- the file log contains structured json strings, one event per line
- rich console output is intended for human triage
- this tool is intentionally focused on discovery traffic rather than full packet inspection
