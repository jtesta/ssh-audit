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


class SSH1_KexDB:  # pylint: disable=too-few-public-methods

    FAIL_PLAINTEXT = 'no encryption/integrity'
    FAIL_OPENSSH37_REMOVE = 'removed since OpenSSH 3.7'
    FAIL_NA_BROKEN = 'not implemented in OpenSSH, broken algorithm'
    FAIL_NA_UNSAFE = 'not implemented in OpenSSH (server), unsafe algorithm'
    TEXT_CIPHER_IDEA = 'cipher used by commercial SSH'

    ALGORITHMS: Dict[str, Dict[str, List[List[Optional[str]]]]] = {
        'key': {
            'ssh-rsa1': [['1.2.2']],
        },
        'enc': {
            'none': [['1.2.2'], [FAIL_PLAINTEXT]],
            'idea': [[None], [], [], [TEXT_CIPHER_IDEA]],
            'des': [['2.3.0C'], [FAIL_NA_UNSAFE]],
            '3des': [['1.2.2']],
            'tss': [[''], [FAIL_NA_BROKEN]],
            'rc4': [[], [FAIL_NA_BROKEN]],
            'blowfish': [['1.2.2']],
        },
        'aut': {
            'rhosts': [['1.2.2', '3.6'], [FAIL_OPENSSH37_REMOVE]],
            'rsa': [['1.2.2']],
            'password': [['1.2.2']],
            'rhosts_rsa': [['1.2.2']],
            'tis': [['1.2.2']],
            'kerberos': [['1.2.2', '3.6'], [FAIL_OPENSSH37_REMOVE]],
        }
    }
