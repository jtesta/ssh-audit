"""
   The MIT License (MIT)

   Copyright (C) 2017-2020 Joe Testa (jtesta@positronsecurity.com)
   Copyright (C) 2017 Andris Raugulis (moo@arthepsy.eu)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
import ipaddress
import re
import sys

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401


class Utils:
    @classmethod
    def _type_err(cls, v: Any, target: str) -> TypeError:
        return TypeError('cannot convert {} to {}'.format(type(v), target))

    @classmethod
    def to_bytes(cls, v: Union[bytes, str], enc: str = 'utf-8') -> bytes:
        if isinstance(v, bytes):
            return v
        elif isinstance(v, str):
            return v.encode(enc)
        raise cls._type_err(v, 'bytes')

    @classmethod
    def to_text(cls, v: Union[str, bytes], enc: str = 'utf-8') -> str:
        if isinstance(v, str):
            return v
        elif isinstance(v, bytes):
            return v.decode(enc)
        raise cls._type_err(v, 'unicode text')

    @classmethod
    def _is_ascii(cls, v: str, char_filter: Callable[[int], bool] = lambda x: x <= 127) -> bool:
        r = False
        if isinstance(v, str):
            for c in v:
                i = cls.ctoi(c)
                if not char_filter(i):
                    return r
            r = True
        return r

    @classmethod
    def _to_ascii(cls, v: str, char_filter: Callable[[int], bool] = lambda x: x <= 127, errors: str = 'replace') -> str:
        if isinstance(v, str):
            r = bytearray()
            for c in v:
                i = cls.ctoi(c)
                if char_filter(i):
                    r.append(i)
                else:
                    if errors == 'ignore':
                        continue
                    r.append(63)
            return cls.to_text(r.decode('ascii'))
        raise cls._type_err(v, 'ascii')

    @classmethod
    def is_ascii(cls, v: str) -> bool:
        return cls._is_ascii(v)

    @classmethod
    def to_ascii(cls, v: str, errors: str = 'replace') -> str:
        return cls._to_ascii(v, errors=errors)

    @classmethod
    def is_print_ascii(cls, v: str) -> bool:
        return cls._is_ascii(v, lambda x: 126 >= x >= 32)

    @classmethod
    def to_print_ascii(cls, v: str, errors: str = 'replace') -> str:
        return cls._to_ascii(v, lambda x: 126 >= x >= 32, errors)

    @classmethod
    def unique_seq(cls, seq: Sequence[Any]) -> Sequence[Any]:
        seen: Set[Any] = set()

        def _seen_add(x: Any) -> bool:
            seen.add(x)
            return False

        if isinstance(seq, tuple):
            return tuple(x for x in seq if x not in seen and not _seen_add(x))
        else:
            return [x for x in seq if x not in seen and not _seen_add(x)]

    @classmethod
    def ctoi(cls, c: Union[str, int]) -> int:
        if isinstance(c, str):
            return ord(c[0])
        else:
            return c

    @staticmethod
    def parse_int(v: Any) -> int:
        try:
            return int(v)
        except ValueError:
            return 0

    @staticmethod
    def parse_float(v: Any) -> float:
        try:
            return float(v)
        except ValueError:
            return -1.0

    @staticmethod
    def parse_host_and_port(host_and_port: str, default_port: int = 0) -> Tuple[str, int]:
        '''Parses a string into a tuple of its host and port.  The port is 0 if not specified.'''
        host = host_and_port
        port = default_port

        mx = re.match(r'^\[([^\]]+)\](?::(\d+))?$', host_and_port)
        if mx is not None:
            host = mx.group(1)
            port_str = mx.group(2)
            if port_str is not None:
                port = int(port_str)
        else:
            s = host_and_port.split(':')
            if len(s) == 2:
                host = s[0]
                if len(s[1]) > 0:
                    port = int(s[1])

        return host, port

    @staticmethod
    def is_ipv6_address(address: str) -> bool:
        '''Returns True if address is an IPv6 address, otherwise False.'''
        is_ipv6 = True
        try:
            ipaddress.IPv6Address(address)
        except ipaddress.AddressValueError:
            is_ipv6 = False

        return is_ipv6

    @staticmethod
    def is_windows() -> bool:
        return sys.platform in ['win32', 'cygwin']
