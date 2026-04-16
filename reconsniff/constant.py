SSDP_HEADER_KEYS = (
    "HOST",
    "CACHE-CONTROL",
    "LOCATION",
    "SERVER",
    "USER-AGENT",
    "USN",
    "NT",
    "NTS",
    "ST",
    "MAN",
    "MX",
    "BOOTID.UPNP.ORG",
    "CONFIGID.UPNP.ORG",
    "SEARCHPORT.UPNP.ORG",
)
SSDP_HEADER_SUMMARY_KEYS = ("ST", "NT", "USN", "LOCATION", "SERVER", "USER-AGENT")

PROTOCOL_KEYS: tuple[str, ...] = (
    'arp', 'dhcp', 'dhcpv6', 'dns', 'mdns', 'llmnr', 'nbns', 'ssdp', 'icmpv6nd', 'tls',
)

TOOL_NAME = "reconsniff"
TOOL_DESCRIPTION = (
    "passive network recon: capture and parse arp, dhcp, dhcpv6, dns, mdns, "
    "llmnr, nbns, ssdp, icmpv6-nd, and tls handshake traffic with rich console "
    "output and structured json file logging."
)
TOOL_EPILOG = (
    "made by - rhawk117\n\n"
    "examples:\n"
    f"  {TOOL_NAME} --interface eth0 --output logs/reconsniff.log\n"
    f"  {TOOL_NAME} --log-level debug --store-packets\n"
    f"  {TOOL_NAME} --no-tls --no-dhcp --no-dhcpv6\n"
    f"  {TOOL_NAME} --dns-port 53 --mdns-port 5353 --ssdp-port 1900\n"
    f"  {TOOL_NAME} --show-filter\n"
)
TOOL_VERSION = '1.1.0'
