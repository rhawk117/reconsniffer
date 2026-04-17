import argparse
import ipaddress
from typing import Literal

type LogLevelNames = Literal[
    'TRACE',
    'DEBUG',
    'INFO',
    'SUCCESS',
    'WARNING',
    'ERROR',
    'CRITICAL',
]

_VALID_LOG_LEVELS: frozenset[str] = frozenset({
    'TRACE',
    'DEBUG',
    'INFO',
    'SUCCESS',
    'WARNING',
    'ERROR',
    'CRITICAL',
})


def validate_port_number(value: str) -> int:
    port = int(value)
    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError(f'invalid port: {value}')
    return port


def validate_ip_address(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f'invalid ip address: {value}') from exc
    return value


def validate_log_level(value: str) -> str:
    value = value.upper()
    if value not in _VALID_LOG_LEVELS:
        raise argparse.ArgumentTypeError(
            f'invalid log level: {value!r}, expected one of {", ".join(sorted(_VALID_LOG_LEVELS))}'
        )
    return value
