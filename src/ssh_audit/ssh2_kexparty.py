"""
   The MIT License (MIT)

   Copyright (C) 2024 Joe Testa (jtesta@positronsecurity.com)
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


class SSH2_KexParty:
    def __init__(self, enc: List[str], mac: List[str], compression: List[str], languages: List[str]) -> None:
        self.__enc = enc
        self.__mac = mac
        self.__compression = compression
        self.__languages = languages

    @property
    def encryption(self) -> List[str]:
        return self.__enc

    @property
    def mac(self) -> List[str]:
        return self.__mac

    @property
    def compression(self) -> List[str]:
        return self.__compression

    @property
    def languages(self) -> List[str]:
        return self.__languages

    def __str__(self) -> str:
        ret = "Ciphers: " + ", ".join(self.__enc)
        ret += "\nMACs: " + ", ".join(self.__mac)
        ret += "\nCompressions: " + ", ".join(self.__compression)
        ret += "\nLanguages: " + ", ".join(self.__languages)
        return ret
