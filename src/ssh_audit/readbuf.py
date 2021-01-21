"""
   The MIT License (MIT)

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
import io
import struct

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401


class ReadBuf:
    def __init__(self, data: Optional[bytes] = None) -> None:
        super(ReadBuf, self).__init__()
        self._buf = io.BytesIO(data) if data is not None else io.BytesIO()
        self._len = len(data) if data is not None else 0

    @property
    def unread_len(self) -> int:
        return self._len - self._buf.tell()

    def read(self, size: int) -> bytes:
        return self._buf.read(size)

    def read_byte(self) -> int:
        v: int = struct.unpack('B', self.read(1))[0]
        return v

    def read_bool(self) -> bool:
        return self.read_byte() != 0

    def read_int(self) -> int:
        v: int = struct.unpack('>I', self.read(4))[0]
        return v

    def read_list(self) -> List[str]:
        list_size = self.read_int()
        return self.read(list_size).decode('utf-8', 'replace').split(',')

    def read_string(self) -> bytes:
        n = self.read_int()
        return self.read(n)

    @classmethod
    def _parse_mpint(cls, v: bytes, pad: bytes, f: str) -> int:
        r = 0
        if len(v) % 4 != 0:
            v = pad * (4 - (len(v) % 4)) + v
        for i in range(0, len(v), 4):
            r = (r << 32) | struct.unpack(f, v[i:i + 4])[0]
        return r

    def read_mpint1(self) -> int:
        # NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
        bits = struct.unpack('>H', self.read(2))[0]
        n = (bits + 7) // 8
        return self._parse_mpint(self.read(n), b'\x00', '>I')

    def read_mpint2(self) -> int:
        # NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
        v = self.read_string()
        if len(v) == 0:
            return 0
        pad, f = (b'\xff', '>i') if ord(v[0:1]) & 0x80 != 0 else (b'\x00', '>I')
        return self._parse_mpint(v, pad, f)

    def read_line(self) -> str:
        return self._buf.readline().rstrip().decode('utf-8', 'replace')

    def reset(self) -> None:
        self._buf = io.BytesIO()
        self._len = 0
