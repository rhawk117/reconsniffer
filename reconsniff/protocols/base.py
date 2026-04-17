from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from reconsniff.models.core import PacketContext, PacketKind, ParsedEvent


class ProtocolAdapter(Protocol):
    kind: PacketKind

    def matches(self, context: PacketContext) -> bool: ...
    def parse(self, context: PacketContext) -> ParsedEvent: ...


@dataclass(slots=True)
class BaseParser:
    pass
