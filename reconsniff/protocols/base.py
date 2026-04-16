import dataclasses as dc
from typing import TYPE_CHECKING, ClassVar, Protocol

if TYPE_CHECKING:
    from reconsniff.protocols.records import PacketContext, PacketKind, ParsedEvent


class PacketAdapter(Protocol):
    kind: ClassVar[PacketKind]

    def matches(self, context: PacketContext) -> bool: ...

    def parse(self, context: PacketContext) -> ParsedEvent: ...


@dc.dataclass(slots=True)
class ParserRegistry:
    adapters: list[PacketAdapter] = dc.field(default_factory=list)

    def register(self, parser: PacketAdapter) -> None:
        self.adapters.append(parser)

    def register_all(self, *adapters: PacketAdapter) -> None:
        self.adapters.extend(adapters)

    def parse_first(self, context: PacketContext) -> ParsedEvent | None:
        for parser in self.adapters:
            if not parser.matches(context):
                continue
            return parser.parse(context)
        return None

    def parse_all(self, context: PacketContext) -> list[ParsedEvent]:
        events: list[ParsedEvent] = []
        for parser in self.adapters:
            if not parser.matches(context):
                continue
            events.append(parser.parse(context))

        return events
