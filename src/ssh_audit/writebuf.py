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


class WriteBuf:
    def __init__(self, data: Optional[bytes] = None) -> None:
        super(WriteBuf, self).__init__()
        self._wbuf = io.BytesIO(data) if data is not None else io.BytesIO()

    def write(self, data: bytes) -> 'WriteBuf':
        self._wbuf.write(data)
        return self

    def write_byte(self, v: int) -> 'WriteBuf':
        return self.write(struct.pack('B', v))

    def write_bool(self, v: bool) -> 'WriteBuf':
        return self.write_byte(1 if v else 0)

    def write_int(self, v: int) -> 'WriteBuf':
        return self.write(struct.pack('>I', v))

    def write_string(self, v: Union[bytes, str]) -> 'WriteBuf':
        if not isinstance(v, bytes):
            v = bytes(bytearray(v, 'utf-8'))
        self.write_int(len(v))
        return self.write(v)

    def write_list(self, v: List[str]) -> 'WriteBuf':
        return self.write_string(','.join(v))

    @classmethod
    def _bitlength(cls, n: int) -> int:
        try:
            return n.bit_length()
        except AttributeError:
            return len(bin(n)) - (2 if n > 0 else 3)

    @classmethod
    def _create_mpint(cls, n: int, signed: bool = True, bits: Optional[int] = None) -> bytes:
        if bits is None:
            bits = cls._bitlength(n)
        length = bits // 8 + (1 if n != 0 else 0)
        ql = (length + 7) // 8
        fmt, v2 = '>{}Q'.format(ql), [0] * ql
        for i in range(ql):
            v2[ql - i - 1] = n & 0xffffffffffffffff
            n >>= 64
        data = bytes(struct.pack(fmt, *v2)[-length:])
        if not signed:
            data = data.lstrip(b'\x00')
        elif data.startswith(b'\xff\x80'):
            data = data[1:]
        return data

    def write_mpint1(self, n: int) -> 'WriteBuf':
        # NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
        bits = self._bitlength(n)
        data = self._create_mpint(n, False, bits)
        self.write(struct.pack('>H', bits))
        return self.write(data)

    def write_mpint2(self, n: int) -> 'WriteBuf':
        # NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
        data = self._create_mpint(n)
        return self.write_string(data)

    def write_line(self, v: Union[bytes, str]) -> 'WriteBuf':
        if not isinstance(v, bytes):
            v = bytes(bytearray(v, 'utf-8'))
        v += b'\r\n'
        return self.write(v)

    def write_flush(self) -> bytes:
        payload = self._wbuf.getvalue()
        self._wbuf.truncate(0)
        self._wbuf.seek(0)
        return payload

    def reset(self) -> None:
        self._wbuf = io.BytesIO()
