#
# Autogenerated by Thrift
#
# DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
#  @generated
#

import folly.iobuf as _fbthrift_iobuf
import thrift.py3.types
import thrift.py3.exceptions
from thrift.py3.types import __NotSet, NOTSET
import typing as _typing
from typing_extensions import Final

import sys
import itertools


__property__ = property


class AnEnum(thrift.py3.types.Enum):
    FIELDA: AnEnum = ...
    FIELDB: AnEnum = ...


class AStruct(thrift.py3.types.Struct, _typing.Hashable):
    class __fbthrift_IsSet:
        FieldA: bool
        pass

    FieldA: Final[int] = ...

    def __init__(
        self, *,
        FieldA: _typing.Optional[int]=None
    ) -> None: ...

    def __call__(
        self, *,
        FieldA: _typing.Union[int, __NotSet, None]=NOTSET
    ) -> AStruct: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['AStruct'], bytes]]: ...
    def __hash__(self) -> int: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'AStruct') -> bool: ...
    def __gt__(self, other: 'AStruct') -> bool: ...
    def __le__(self, other: 'AStruct') -> bool: ...
    def __ge__(self, other: 'AStruct') -> bool: ...


class AStructB(thrift.py3.types.Struct, _typing.Hashable):
    class __fbthrift_IsSet:
        pass

    FieldA: Final[_typing.Optional['AStruct']] = ...

    def __init__(
        self, *,
        FieldA: _typing.Optional['AStruct']=None
    ) -> None: ...

    def __call__(
        self, *,
        FieldA: _typing.Union['AStruct', __NotSet, None]=NOTSET
    ) -> AStructB: ...

    def __reduce__(self) -> _typing.Tuple[_typing.Callable, _typing.Tuple[_typing.Type['AStructB'], bytes]]: ...
    def __hash__(self) -> int: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __lt__(self, other: 'AStructB') -> bool: ...
    def __gt__(self, other: 'AStructB') -> bool: ...
    def __le__(self, other: 'AStructB') -> bool: ...
    def __ge__(self, other: 'AStructB') -> bool: ...


IncludedConstant: int = ...
IncludedInt64 = int
