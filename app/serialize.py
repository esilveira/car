"""Serialization of dataclasses to JSONable dictionaries.

This module provides a function to convert dataclasses to JSONable dictionaries
and a function to convert JSONable dictionaries to dataclasses.

Example:
    >>> from dataclasses import dataclass
    >>> from datetime import datetime
    >>> from app.serialize import to_dict, from_dict
    >>> @dataclass
    ... class Foo:
    ...     bar: str
    ...     baz: int
    ...     qux: datetime
    >>> foo = Foo("bar", 42, datetime(2021, 1, 1))
    >>> to_dict(foo)
    {'bar': 'bar', 'baz': 42, 'qux': '2021-01-01T00:00:00'}
    >>> from_dict(Foo, {'bar': 'bar', 'baz': 42, 'qux': '2021-01-01T00:00:00'})
    Foo(bar='bar', baz=42, qux=datetime.datetime(2021, 1, 1, 0, 0))
"""
import datetime as _datetime
from collections.abc import Collection as _Collection
from collections.abc import Mapping as _Mapping
from dataclasses import asdict as _asdict
from enum import Enum as _Enum
from operator import attrgetter as _attrgetter
from typing import Any as _Any
from typing import Callable as _Callable
from typing import TypeVar as _TypeVar
from typing import cast as _cast

from dacite import Config as _Config
from dacite.exceptions import MissingValueError as _MissingValueError
from dacite import from_dict as _from_dict

__all__ = ["to_dict", "from_dict"]

_T = _TypeVar("_T")

_JsonTypes = (str | int | float | bool | None |
              list["_JsonTypes"] | dict[str, "_JsonTypes"])

_JsonDict = dict[str, _JsonTypes]

_UnparametrizedJsonTypes = (str | int | float | bool | None | list | dict)

_EncodersDictionary = dict[type[_Any], _Callable[[_Any], _JsonTypes]]

_builtin_type_encoders: _EncodersDictionary = {
    _datetime.datetime: _datetime.datetime.isoformat,
    _Enum: _attrgetter("value"),
}

_DecodersDictionary = dict[type[_Any], _Callable[[_Any], _Any]]

_builtin_type_decoders: _DecodersDictionary = {
    _datetime.datetime: _datetime.datetime.fromisoformat,
}


def from_dict(datacls: type, data: _JsonDict, *,
              type_decoders: _DecodersDictionary = {}
              ) -> _Any:
    """Convert a dictionary to a dataclass.

    Example:
        >>> from dataclasses import dataclass
        >>> from datetime import datetime
        >>> from app.serialize import from_dict
        >>> @dataclass
        ... class Foo:
        ...     bar: str
        ...     baz: int
        ...     qux: datetime
        >>> from_dict(Foo, {'bar': 'bar', 'baz': 42,
        ... 'qux': '2021-01-01T00:00:00'})
        Foo(bar='bar', baz=42, qux=datetime.datetime(2021, 1, 1, 0, 0))

    Args:
        datacls: The dataclass to convert to.
        data: The dictionary to convert from.
        type_decoders: A dictionary of type decoders. A type decoder is a
            function that takes a JSONable value and returns a value of the
            desired type. The default type decoders are:
            - datetime.datetime.fromisoformat for datetime.datetime

    Returns:
        A dataclass.
    """

    type_decoders = _builtin_type_decoders | type_decoders
    try:
        return _from_dict(datacls, data,
                          config=_Config(type_hooks=type_decoders,
                                         cast=[_Enum]))
    except _MissingValueError as exc:
        raise ValueError(f"Data does not match {datacls!r}."
                         ) from exc


def to_dict(datacls: _Any, *,
            type_encoders: _EncodersDictionary = {}
            ) -> _JsonDict:
    """Convert a dataclass to a JSONable dictionary.

    Example:
        >>> from dataclasses import dataclass
        >>> from datetime import datetime
        >>> from app.serialize import to_dict
        >>> @dataclass
        ... class Foo:
        ...     bar: str
        ...     baz: int
        ...     qux: datetime
        >>> foo = Foo("bar", 42, datetime(2021, 1, 1))
        >>> to_dict(foo)
        {'bar': 'bar', 'baz': 42, 'qux': '2021-01-01T00:00:00'}

    Args:
        datacls: The dataclass to convert.
        type_encoders: A dictionary of type encoders. A type encoder is a
            function that takes an object and returns a JSONable object. If a
            type encoder is provided for a type, the type encoder will be used
            instead of the default conversion.

    Returns:
        A dictionary that can be converted to JSON.

    Raises:
        TypeError: If the object is not JSONable.
    """

    type_encoders = _builtin_type_encoders | type_encoders

    def _recurse(obj: _Any) -> _JsonTypes:
        if type(obj) in type_encoders:
            return type_encoders[type(obj)](obj)
        for type_, encoder in type_encoders.items():
            if isinstance(obj, type_):
                type_encoders[type_] = encoder
                return encoder(obj)
        if isinstance(obj, _Mapping):
            return {key: _recurse(value) for key, value in obj.items()}
        if isinstance(obj, _Collection) and not isinstance(obj, str):
            return [_recurse(value) for value in obj]

        # https://github.com/python/mypy/issues/3060
        if not isinstance(obj, _UnparametrizedJsonTypes):  # type: ignore
            raise TypeError(f"Object of type {type(obj)} is not JSONable.")

        return obj

    return _cast(dict[str, _JsonTypes], _recurse(_asdict(datacls)))
