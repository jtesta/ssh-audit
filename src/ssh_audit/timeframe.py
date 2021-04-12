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

from ssh_audit.algorithm import Algorithm


class Timeframe:
    def __init__(self) -> None:
        self.__storage: Dict[str, List[Optional[str]]] = {}

    def __contains__(self, product: str) -> bool:
        return product in self.__storage

    def __getitem__(self, product: str) -> Sequence[Optional[str]]:
        return tuple(self.__storage.get(product, [None] * 4))

    def __str__(self) -> str:
        return self.__storage.__str__()

    def __repr__(self) -> str:
        return self.__str__()

    def get_from(self, product: str, for_server: bool = True) -> Optional[str]:
        return self[product][0 if bool(for_server) else 2]

    def get_till(self, product: str, for_server: bool = True) -> Optional[str]:
        return self[product][1 if bool(for_server) else 3]

    def _update(self, versions: Optional[str], pos: int) -> None:
        ssh_versions: Dict[str, str] = {}
        for_srv, for_cli = pos < 2, pos > 1
        for v in (versions or '').split(','):
            ssh_prod, ssh_ver, is_cli = Algorithm.get_ssh_version(v)
            if not ssh_ver or (is_cli and for_srv) or (not is_cli and for_cli and ssh_prod in ssh_versions):
                continue
            ssh_versions[ssh_prod] = ssh_ver
        for ssh_product, ssh_version in ssh_versions.items():
            if ssh_product not in self.__storage:
                self.__storage[ssh_product] = [None] * 4
            prev = self[ssh_product][pos]
            if (prev is None or (prev < ssh_version and pos % 2 == 0) or (prev > ssh_version and pos % 2 == 1)):
                self.__storage[ssh_product][pos] = ssh_version

    def update(self, versions: List[Optional[str]], for_server: Optional[bool] = None) -> 'Timeframe':
        for_cli = for_server is None or for_server is False
        for_srv = for_server is None or for_server is True
        vlen = len(versions)
        for i in range(min(3, vlen)):
            if for_srv and i < 2:
                self._update(versions[i], i)
            if for_cli and (i % 2 == 0 or vlen == 2):
                self._update(versions[i], 3 - 0**i)
        return self
