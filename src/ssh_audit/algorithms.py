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

from ssh_audit.algorithm import Algorithm
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh1_kexdb import SSH1_KexDB
from ssh_audit.ssh1_publickeymessage import SSH1_PublicKeyMessage
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.timeframe import Timeframe
from ssh_audit.utils import Utils


class Algorithms:
    def __init__(self, pkm: Optional[SSH1_PublicKeyMessage], kex: Optional[SSH2_Kex]) -> None:
        self.__ssh1kex = pkm
        self.__ssh2kex = kex

    @property
    def ssh1kex(self) -> Optional[SSH1_PublicKeyMessage]:
        return self.__ssh1kex

    @property
    def ssh2kex(self) -> Optional[SSH2_Kex]:
        return self.__ssh2kex

    @property
    def ssh1(self) -> Optional['Algorithms.Item']:
        if self.ssh1kex is None:
            return None
        item = Algorithms.Item(1, SSH1_KexDB.get_db())
        item.add('key', ['ssh-rsa1'])
        item.add('enc', self.ssh1kex.supported_ciphers)
        item.add('aut', self.ssh1kex.supported_authentications)
        return item

    @property
    def ssh2(self) -> Optional['Algorithms.Item']:
        if self.ssh2kex is None:
            return None
        item = Algorithms.Item(2, SSH2_KexDB.get_db())
        item.add('kex', self.ssh2kex.kex_algorithms)
        item.add('key', self.ssh2kex.key_algorithms)
        item.add('enc', self.ssh2kex.server.encryption)
        item.add('mac', self.ssh2kex.server.mac)
        return item

    @property
    def values(self) -> Iterable['Algorithms.Item']:
        for item in [self.ssh1, self.ssh2]:
            if item is not None:
                yield item

    @property
    def maxlen(self) -> int:
        def _ml(items: Sequence[str]) -> int:
            return max(len(i) for i in items)
        maxlen = 0
        if self.ssh1kex is not None:
            maxlen = max(_ml(self.ssh1kex.supported_ciphers),
                         _ml(self.ssh1kex.supported_authentications),
                         maxlen)
        if self.ssh2kex is not None:
            maxlen = max(_ml(self.ssh2kex.kex_algorithms),
                         _ml(self.ssh2kex.key_algorithms),
                         _ml(self.ssh2kex.server.encryption),
                         _ml(self.ssh2kex.server.mac),
                         maxlen)
        return maxlen

    def get_ssh_timeframe(self, for_server: Optional[bool] = None) -> 'Timeframe':
        timeframe = Timeframe()
        for alg_pair in self.values:
            alg_db = alg_pair.db
            for alg_type, alg_list in alg_pair.items():
                for alg_name in alg_list:
                    alg_name_native = Utils.to_text(alg_name)
                    alg_desc = alg_db[alg_type].get(alg_name_native)
                    if alg_desc is None:
                        continue
                    versions = alg_desc[0]
                    timeframe.update(versions, for_server)
        return timeframe

    def get_recommendations(self, software: Optional['Software'], for_server: bool = True) -> Tuple[Optional['Software'], Dict[int, Dict[str, Dict[str, Dict[str, int]]]]]:
        # pylint: disable=too-many-locals,too-many-statements
        vproducts = [Product.OpenSSH,
                     Product.DropbearSSH,
                     Product.LibSSH,
                     Product.TinySSH]
        # Set to True if server is not one of vproducts, above.
        unknown_software = False
        if software is not None:
            if software.product not in vproducts:
                unknown_software = True

        # The code below is commented out because it would try to guess what the server is,
        # usually resulting in wild & incorrect recommendations.
        # if software is None:
        #     ssh_timeframe = self.get_ssh_timeframe(for_server)
        #     for product in vproducts:
        #         if product not in ssh_timeframe:
        #             continue
        #         version = ssh_timeframe.get_from(product, for_server)
        #         if version is not None:
        #             software = SSH.Software(None, product, version, None, None)
        #             break
        rec: Dict[int, Dict[str, Dict[str, Dict[str, int]]]] = {}
        if software is None:
            unknown_software = True
        for alg_pair in self.values:
            sshv, alg_db = alg_pair.sshv, alg_pair.db
            rec[sshv] = {}
            for alg_type, alg_list in alg_pair.items():
                if alg_type == 'aut':
                    continue
                rec[sshv][alg_type] = {'add': {}, 'del': {}, 'chg': {}}
                for n, alg_desc in alg_db[alg_type].items():
                    versions = alg_desc[0]
                    empty_version = False
                    if len(versions) == 0 or versions[0] is None:
                        empty_version = True
                    else:
                        matches = False
                        if unknown_software:
                            matches = True
                        for v in versions[0].split(','):
                            ssh_prefix, ssh_version, is_cli = Algorithm.get_ssh_version(v)
                            if not ssh_version:
                                continue
                            if (software is not None) and (ssh_prefix != software.product):
                                continue
                            if is_cli and for_server:
                                continue
                            if (software is not None) and (software.compare_version(ssh_version) < 0):
                                continue
                            matches = True
                            break
                        if not matches:
                            continue
                    adl, faults = len(alg_desc), 0
                    for i in range(1, 3):
                        if not adl > i:
                            continue
                        fc = len(alg_desc[i])
                        if fc > 0:
                            faults += pow(10, 2 - i) * fc
                    if n not in alg_list:
                        # Don't recommend certificate or token types; these will only appear in the server's list if they are fully configured & functional on the server.
                        if faults > 0 or (alg_type == 'key' and (('-cert-' in n) or (n.startswith('sk-')))) or empty_version:
                            continue
                        rec[sshv][alg_type]['add'][n] = 0
                    else:
                        if faults == 0:
                            continue
                        if n in ['diffie-hellman-group-exchange-sha256', 'rsa-sha2-256', 'rsa-sha2-512', 'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com']:
                            rec[sshv][alg_type]['chg'][n] = faults
                        else:
                            rec[sshv][alg_type]['del'][n] = faults
                # If we are working with unknown software, drop all add recommendations, because we don't know if they're valid.
                if unknown_software:
                    rec[sshv][alg_type]['add'] = {}
                add_count = len(rec[sshv][alg_type]['add'])
                del_count = len(rec[sshv][alg_type]['del'])
                chg_count = len(rec[sshv][alg_type]['chg'])

                if add_count == 0:
                    del rec[sshv][alg_type]['add']
                if del_count == 0:
                    del rec[sshv][alg_type]['del']
                if chg_count == 0:
                    del rec[sshv][alg_type]['chg']
                if len(rec[sshv][alg_type]) == 0:
                    del rec[sshv][alg_type]
            if len(rec[sshv]) == 0:
                del rec[sshv]
        return software, rec

    class Item:
        def __init__(self, sshv: int, db: Dict[str, Dict[str, List[List[Optional[str]]]]]) -> None:
            self.__sshv = sshv
            self.__db = db
            self.__storage: Dict[str, List[str]] = {}

        @property
        def sshv(self) -> int:
            return self.__sshv

        @property
        def db(self) -> Dict[str, Dict[str, List[List[Optional[str]]]]]:
            return self.__db

        def add(self, key: str, value: List[str]) -> None:
            self.__storage[key] = value

        def items(self) -> Iterable[Tuple[str, List[str]]]:
            return self.__storage.items()
