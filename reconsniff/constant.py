

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
TOOL_NAME = "reconsniff"
TOOL_DESCRIPTION = (
    "capture dns, mdns, and ssdp discovery traffic with rich console output "
    "and structured loguru file logging for passive recon."
)
TOOL_EPILOG = (
    f"made by - rhawk117\n\n"
    "examples:\n"
    f"  {TOOL_NAME} --interface eth0 --output logs/reconsniff.log\n"
    f"  {TOOL_NAME} --log-level debug --store-packets\n"
    f"  {TOOL_NAME} --dns-port 53 --mdns-port 5353 --ssdp-port 1900\n"
    f"  {TOOL_NAME} --mdns-multicast-ipv4 224.0.0.251 "
    "--ssdp-multicast-ipv4 239.255.255.250\n"
)
TOOL_VERSION = '1.0.0'