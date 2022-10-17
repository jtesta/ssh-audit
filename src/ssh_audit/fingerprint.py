"""
   The MIT License (MIT)

   Copyright (C) 2017-2021 Joe Testa (jtesta@positronsecurity.com)
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
import base64
import hashlib


class Fingerprint:
    def __init__(self, fpd: bytes) -> None:
        self.__fpd = fpd

    @property
    def md5(self) -> str:
        h = hashlib.md5(self.__fpd).hexdigest()
        r = ':'.join(h[i:i + 2] for i in range(0, len(h), 2))
        return 'MD5:{}'.format(r)

    @property
    def sha256(self) -> str:
        h = base64.b64encode(hashlib.sha256(self.__fpd).digest())
        r = h.decode('ascii').rstrip('=')
        return 'SHA256:{}'.format(r)

    @property
    def sha512(self) -> str:
        h = base64.b64encode(hashlib.sha512(self.__fpd).digest())
        r = h.decode('ascii').rstrip('=')
        return 'SHA512:{}'.format(r)

