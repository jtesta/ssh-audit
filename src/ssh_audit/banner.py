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
import re

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.utils import Utils


class Banner:
    _RXP, _RXR = r'SSH-\d\.\s*?\d+', r'(-\s*([^\s]*)(?:\s+(.*))?)?'
    RX_PROTOCOL = re.compile(re.sub(r'\\d(\+?)', r'(\\d\g<1>)', _RXP))
    RX_BANNER = re.compile(r'^({0}(?:(?:-{0})*)){1}$'.format(_RXP, _RXR))

    def __init__(self, protocol: Tuple[int, int], software: Optional[str], comments: Optional[str], valid_ascii: bool) -> None:
        self.__protocol = protocol
        self.__software = software
        self.__comments = comments
        self.__valid_ascii = valid_ascii

    @property
    def protocol(self) -> Tuple[int, int]:
        return self.__protocol

    @property
    def software(self) -> Optional[str]:
        return self.__software

    @property
    def comments(self) -> Optional[str]:
        return self.__comments

    @property
    def valid_ascii(self) -> bool:
        return self.__valid_ascii

    def __str__(self) -> str:
        r = 'SSH-{}.{}'.format(self.protocol[0], self.protocol[1])
        if self.software is not None:
            r += '-{}'.format(self.software)
        if bool(self.comments):
            r += ' {}'.format(self.comments)
        return r

    def __repr__(self) -> str:
        p = '{}.{}'.format(self.protocol[0], self.protocol[1])
        r = 'protocol={}'.format(p)
        if self.software is not None:
            r += ', software={}'.format(self.software)
        if bool(self.comments):
            r += ', comments={}'.format(self.comments)
        return '<{}({})>'.format(self.__class__.__name__, r)

    @classmethod
    def parse(cls, banner: str) -> Optional['Banner']:
        valid_ascii = Utils.is_print_ascii(banner)
        ascii_banner = Utils.to_print_ascii(banner)
        mx = cls.RX_BANNER.match(ascii_banner)
        if mx is None:
            return None
        protocol = min(re.findall(cls.RX_PROTOCOL, mx.group(1)))
        protocol = (int(protocol[0]), int(protocol[1]))
        software = (mx.group(3) or '').strip() or None
        if software is None and (mx.group(2) or '').startswith('-'):
            software = ''
        comments = (mx.group(4) or '').strip() or None
        if comments is not None:
            comments = re.sub(r'\s+', ' ', comments)
        return cls(protocol, software, comments, valid_ascii)
