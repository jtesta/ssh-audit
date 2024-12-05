"""
   The MIT License (MIT)

   Copyright (C) 2021 Joe Testa (jtesta@positronsecurity.com)
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


class OutputBuffer:
    LEVELS: Sequence[str] = ('info', 'warn', 'fail')
    COLORS = {'head': 36, 'good': 32, 'warn': 33, 'fail': 31}

    # Use brighter colors on Windows for better readability.
    if Utils.is_windows():
        COLORS = {'head': 96, 'good': 92, 'warn': 93, 'fail': 91}

    def __init__(self, buffer_output: bool = True) -> None:
        self.buffer_output = buffer_output
        self.buffer: List[str] = []
        self.in_section = False
        self.section: List[str] = []
        self.batch = False
        self.verbose = False
        self.debug = False
        self.use_colors = True
        self.json = False
        self.__level = 0
        self.__is_color_supported = ('colorama' in sys.modules) or (os.name == 'posix')
        self.line_ended = True

    def _print(self, level: str, s: str = '', line_ended: bool = True, always_print: bool = False) -> None:
        '''Saves output to buffer (if in buffered mode), or immediately prints to stdout otherwise.'''

        # If we're logging only 'warn' or above, and this is an 'info', ignore message, unless always_print is True (useful for printing informational lines regardless of the level setting).
        if (always_print is False) and (self.get_level(level) < self.__level):
            return

        if self.use_colors and self.colors_supported and len(s) > 0 and level != 'info':
            s = "\033[0;%dm%s\033[0m" % (self.COLORS[level], s)

        if self.buffer_output:
            # Select which list to add to.  If we are in a 'with' statement, then this goes in the section buffer, otherwise the general buffer.
            buf = self.section if self.in_section else self.buffer

            # Determine if a new line should be added, or if the last line should be appended.
            if not self.line_ended:
                last_entry = -1 if len(buf) > 0 else 0
                buf[last_entry] = buf[last_entry] + s
            else:
                buf.append(s)

            # When False, this tells the next call to append to the last line we just added.
            self.line_ended = line_ended
        else:
            print(s)

    def get_buffer(self) -> str:
        '''Returns all buffered output, then clears the buffer.'''
        self.flush_section()

        buffer_str = "\n".join(self.buffer)
        self.buffer = []
        return buffer_str

    def write(self) -> None:
        '''Writes the output to stdout.'''
        self.flush_section()
        print(self.get_buffer(), flush=True)

    def reset(self) -> None:
        self.flush_section()
        self.get_buffer()

    @property
    def level(self) -> str:
        '''Returns the minimum level for output.'''
        if self.__level < len(self.LEVELS):
            return self.LEVELS[self.__level]
        return 'unknown'

    @level.setter
    def level(self, name: str) -> None:
        '''Sets the minimum level for output (one of: 'info', 'warn', 'fail').'''
        self.__level = self.get_level(name)

    def get_level(self, name: str) -> int:
        cname = 'info' if name == 'good' else name
        if cname not in self.LEVELS:
            return sys.maxsize
        return self.LEVELS.index(cname)

    @property
    def colors_supported(self) -> bool:
        '''Returns True if the system supports color output.'''
        return self.__is_color_supported

    # When used in a 'with' block, the output to goes into a section; this can be sorted separately when add_section_to_buffer() is later called.
    def __enter__(self) -> 'OutputBuffer':
        self.in_section = True
        return self

    def __exit__(self, *args: Any) -> None:
        self.in_section = False

    def flush_section(self, sort_section: bool = False) -> None:
        '''Appends section output (optionally sorting it first) to the end of the buffer, then clears the section output.'''
        if sort_section:
            self.section.sort()

        self.buffer.extend(self.section)
        self.section = []

    def is_section_empty(self) -> bool:
        '''Returns True if the section buffer is empty, otherwise False.'''
        return len(self.section) == 0

    def head(self, s: str, line_ended: bool = True) -> 'OutputBuffer':
        if not self.batch:
            self._print('head', s, line_ended)
        return self

    def fail(self, s: str, line_ended: bool = True, write_now: bool = False, always_print: bool = False) -> 'OutputBuffer':
        self._print('fail', s, line_ended, always_print=always_print)
        if write_now:
            self.write()
        return self

    def warn(self, s: str, line_ended: bool = True, always_print: bool = False) -> 'OutputBuffer':
        self._print('warn', s, line_ended, always_print=always_print)
        return self

    def info(self, s: str, line_ended: bool = True, always_print: bool = False) -> 'OutputBuffer':
        self._print('info', s, line_ended, always_print=always_print)
        return self

    def good(self, s: str, line_ended: bool = True, always_print: bool = False) -> 'OutputBuffer':
        self._print('good', s, line_ended, always_print=always_print)
        return self

    def sep(self) -> 'OutputBuffer':
        if not self.batch:
            self._print('info')
        return self

    def v(self, s: str, write_now: bool = False) -> 'OutputBuffer':
        '''Prints a message if verbose output is enabled.'''
        if self.verbose or self.debug:
            self.info(s)
            if write_now:
                self.write()

        return self

    def d(self, s: str, write_now: bool = False) -> 'OutputBuffer':
        '''Prints a message if verbose output is enabled.'''
        if self.debug:
            self.info(s)
            if write_now:
                self.write()

        return self
