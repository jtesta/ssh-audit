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
# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.ssh1 import SSH1
from ssh_audit.readbuf import ReadBuf
from ssh_audit.utils import Utils
from ssh_audit.writebuf import WriteBuf


class SSH1_PublicKeyMessage:
    def __init__(self, cookie: bytes, skey: Tuple[int, int, int], hkey: Tuple[int, int, int], pflags: int, cmask: int, amask: int) -> None:
        if len(skey) != 3:
            raise ValueError('invalid server key pair: {}'.format(skey))
        if len(hkey) != 3:
            raise ValueError('invalid host key pair: {}'.format(hkey))
        self.__cookie = cookie
        self.__server_key = skey
        self.__host_key = hkey
        self.__protocol_flags = pflags
        self.__supported_ciphers_mask = cmask
        self.__supported_authentications_mask = amask

    @property
    def cookie(self) -> bytes:
        return self.__cookie

    @property
    def server_key_bits(self) -> int:
        return self.__server_key[0]

    @property
    def server_key_public_exponent(self) -> int:
        return self.__server_key[1]

    @property
    def server_key_public_modulus(self) -> int:
        return self.__server_key[2]

    @property
    def host_key_bits(self) -> int:
        return self.__host_key[0]

    @property
    def host_key_public_exponent(self) -> int:
        return self.__host_key[1]

    @property
    def host_key_public_modulus(self) -> int:
        return self.__host_key[2]

    @property
    def host_key_fingerprint_data(self) -> bytes:
        # pylint: disable=protected-access
        mod = WriteBuf._create_mpint(self.host_key_public_modulus, False)
        e = WriteBuf._create_mpint(self.host_key_public_exponent, False)
        return mod + e

    @property
    def protocol_flags(self) -> int:
        return self.__protocol_flags

    @property
    def supported_ciphers_mask(self) -> int:
        return self.__supported_ciphers_mask

    @property
    def supported_ciphers(self) -> List[str]:
        ciphers = []
        for i in range(len(SSH1.CIPHERS)):  # pylint: disable=consider-using-enumerate
            if self.__supported_ciphers_mask & (1 << i) != 0:
                ciphers.append(Utils.to_text(SSH1.CIPHERS[i]))
        return ciphers

    @property
    def supported_authentications_mask(self) -> int:
        return self.__supported_authentications_mask

    @property
    def supported_authentications(self) -> List[str]:
        auths = []
        for i in range(1, len(SSH1.AUTHS)):
            if self.__supported_authentications_mask & (1 << i) != 0:
                auths.append(Utils.to_text(SSH1.AUTHS[i]))
        return auths

    def write(self, wbuf: 'WriteBuf') -> None:
        wbuf.write(self.cookie)
        wbuf.write_int(self.server_key_bits)
        wbuf.write_mpint1(self.server_key_public_exponent)
        wbuf.write_mpint1(self.server_key_public_modulus)
        wbuf.write_int(self.host_key_bits)
        wbuf.write_mpint1(self.host_key_public_exponent)
        wbuf.write_mpint1(self.host_key_public_modulus)
        wbuf.write_int(self.protocol_flags)
        wbuf.write_int(self.supported_ciphers_mask)
        wbuf.write_int(self.supported_authentications_mask)

    @property
    def payload(self) -> bytes:
        wbuf = WriteBuf()
        self.write(wbuf)
        return wbuf.write_flush()

    @classmethod
    def parse(cls, payload: bytes) -> 'SSH1_PublicKeyMessage':
        buf = ReadBuf(payload)
        cookie = buf.read(8)
        server_key_bits = buf.read_int()
        server_key_exponent = buf.read_mpint1()
        server_key_modulus = buf.read_mpint1()
        skey = (server_key_bits, server_key_exponent, server_key_modulus)
        host_key_bits = buf.read_int()
        host_key_exponent = buf.read_mpint1()
        host_key_modulus = buf.read_mpint1()
        hkey = (host_key_bits, host_key_exponent, host_key_modulus)
        pflags = buf.read_int()
        cmask = buf.read_int()
        amask = buf.read_int()
        pkm = cls(cookie, skey, hkey, pflags, cmask, amask)
        return pkm
