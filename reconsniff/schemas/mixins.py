import copy
import dataclasses as dc
from typing import Any, Self


def get_field_default(cls_field: dc.Field[Any]) -> Any | None:
    if cls_field.default is not dc.MISSING:
        return cls_field.default

    if cls_field.default_factory is not dc.MISSING:
        return cls_field.default_factory()

    return None


def get_fieldnames(data_cls: type[Any]) -> set[str]:
    if not dc.is_dataclass(data_cls):
        raise TypeError(f'{data_cls!r} is not a dataclass')

    return {field.name for field in dc.fields(data_cls)}


def get_dataclass_kwargs(
    data_cls: type[Any],
    data: dict[str, Any],
) -> dict[str, Any]:
    """
    Extracts the key-word arguments in the dictionary that
    are field names for the dataclass
    """
    field_names = get_fieldnames(data_cls)
    return {key: value for key, value in data.items() if key in field_names}


class DataclassMixin:
    def to_dict(self, *, exclude: set[str] | None = None) -> dict[str, Any]:
        dumped = dc.asdict(self)  # type: ignore[arg-type]
        if exclude:
            return {key: value for key, value in dumped.items() if key not in exclude}
        return dumped

    def replace(self, **overrides: Any) -> Self:
        return dc.replace(self, **overrides)  # type: ignore[type-var]

    def to_tuple(self) -> tuple[Any, ...]:
        return dc.astuple(self)  # type: ignore[arg-type]

    def copy(self) -> Self:
        return copy.copy(self)

    def deepcopy(self) -> Self:
        return copy.deepcopy(self)

    @classmethod
    def class_fields(cls) -> tuple[dc.Field, ...]:
        return dc.field(cls)  # type: ignore
