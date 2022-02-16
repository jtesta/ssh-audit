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
# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.policy import Policy
from ssh_audit.utils import Utils


class AuditConf:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, host: str = '', port: int = 22) -> None:
        self.host = host
        self.port = port
        self.ssh1 = True
        self.ssh2 = True
        self.batch = False
        self.client_audit = False
        self.colors = True
        self.json = False
        self.json_print_indent = False
        self.verbose = False
        self.level = 'info'
        self.ip_version_preference: List[int] = []  # Holds only 5 possible values: [] (no preference), [4] (use IPv4 only), [6] (use IPv6 only), [46] (use both IPv4 and IPv6, but prioritize v4), and [64] (use both IPv4 and IPv6, but prioritize v6).
        self.ipv4 = False
        self.ipv6 = False
        self.make_policy = False  # When True, creates a policy file from an audit scan.
        self.policy_file: Optional[str] = None   # File system path to a policy
        self.policy: Optional[Policy] = None  # Policy object
        self.timeout = 5.0
        self.timeout_set = False  # Set to True when the user explicitly sets it.
        self.target_file: Optional[str] = None
        self.target_list: List[str] = []
        self.threads = 32
        self.list_policies = False
        self.lookup = ''
        self.manual = False
        self.debug = False
        self.gex_test = ''

    def __setattr__(self, name: str, value: Union[str, int, float, bool, Sequence[int]]) -> None:
        valid = False
        if name in ['batch', 'client_audit', 'colors', 'json', 'json_print_indent', 'list_policies', 'manual', 'make_policy', 'ssh1', 'ssh2', 'timeout_set', 'verbose', 'debug']:
            valid, value = True, bool(value)
        elif name in ['ipv4', 'ipv6']:
            valid, value = True, bool(value)
            if len(self.ip_version_preference) == 2:  # Being called more than twice is not valid.
                valid = False
            elif value:
                self.ip_version_preference.append(4 if name == 'ipv4' else 6)
        elif name == 'port':
            valid, port = True, Utils.parse_int(value)
            if port < 1 or port > 65535:
                raise ValueError('invalid port: {}'.format(value))
            value = port
        elif name in ['level']:
            if value not in ('info', 'warn', 'fail'):
                raise ValueError('invalid level: {}'.format(value))
            valid = True
        elif name == 'host':
            valid = True
        elif name == 'timeout':
            value = Utils.parse_float(value)
            if value == -1.0:
                raise ValueError('invalid timeout: {}'.format(value))
            valid = True
        elif name in ['ip_version_preference', 'lookup', 'policy_file', 'policy', 'target_file', 'target_list', 'gex_test']:
            valid = True
        elif name == "threads":
            valid, num_threads = True, Utils.parse_int(value)
            if num_threads < 1:
                raise ValueError('invalid number of threads: {}'.format(value))
            value = num_threads

        if valid:
            object.__setattr__(self, name, value)
