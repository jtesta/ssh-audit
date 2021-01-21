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
import os
import sys

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.utils import Utils


class Output:
    LEVELS: Sequence[str] = ('info', 'warn', 'fail')
    COLORS = {'head': 36, 'good': 32, 'warn': 33, 'fail': 31}

    # Use brighter colors on Windows for better readability.
    if Utils.is_windows():
        COLORS = {'head': 96, 'good': 92, 'warn': 93, 'fail': 91}

    def __init__(self) -> None:
        self.batch = False
        self.verbose = False
        self.use_colors = True
        self.json = False
        self.__level = 0
        self.__colsupport = 'colorama' in sys.modules or os.name == 'posix'

    @property
    def level(self) -> str:
        if self.__level < len(self.LEVELS):
            return self.LEVELS[self.__level]
        return 'unknown'

    @level.setter
    def level(self, name: str) -> None:
        self.__level = self.get_level(name)

    def get_level(self, name: str) -> int:
        cname = 'info' if name == 'good' else name
        if cname not in self.LEVELS:
            return sys.maxsize
        return self.LEVELS.index(cname)

    def sep(self) -> None:
        if not self.batch:
            print()

    @property
    def colors_supported(self) -> bool:
        return self.__colsupport

    @staticmethod
    def _colorized(color: str) -> Callable[[str], None]:
        return lambda x: print(u'{}{}\033[0m'.format(color, x))

    def __getattr__(self, name: str) -> Callable[[str], None]:
        if name == 'head' and self.batch:
            return lambda x: None
        if not self.get_level(name) >= self.__level:
            return lambda x: None
        if self.use_colors and self.colors_supported and name in self.COLORS:
            color = '\033[0;{}m'.format(self.COLORS[name])
            return self._colorized(color)
        else:
            return lambda x: print(u'{}'.format(x))
