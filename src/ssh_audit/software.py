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

from ssh_audit.banner import Banner
from ssh_audit.product import Product


class Software:
    def __init__(self, vendor: Optional[str], product: str, version: str, patch: Optional[str], os_version: Optional[str]) -> None:
        self.__vendor = vendor
        self.__product = product
        self.__version = version
        self.__patch = patch
        self.__os = os_version

    @property
    def vendor(self) -> Optional[str]:
        return self.__vendor

    @property
    def product(self) -> str:
        return self.__product

    @property
    def version(self) -> str:
        return self.__version

    @property
    def patch(self) -> Optional[str]:
        return self.__patch

    @property
    def os(self) -> Optional[str]:
        return self.__os

    def compare_version(self, other: Union[None, 'Software', str]) -> int:
        # pylint: disable=too-many-branches,too-many-return-statements
        if other is None:
            return 1
        if isinstance(other, Software):
            other = '{}{}'.format(other.version, other.patch or '')
        else:
            other = str(other)
        mx = re.match(r'^([\d\.]+\d+)(.*)$', other)
        if mx is not None:
            oversion, opatch = mx.group(1), mx.group(2).strip()
        else:
            oversion, opatch = other, ''
        if self.version < oversion:
            return -1
        elif self.version > oversion:
            return 1
        spatch = self.patch or ''
        if self.product == Product.DropbearSSH:
            if not re.match(r'^test\d.*$', opatch):
                opatch = 'z{}'.format(opatch)
            if not re.match(r'^test\d.*$', spatch):
                spatch = 'z{}'.format(spatch)
        elif self.product == Product.OpenSSH:
            mx1 = re.match(r'^p(\d).*', opatch)
            mx2 = re.match(r'^p(\d).*', spatch)
            if not (bool(mx1) and bool(mx2)):
                if mx1 is not None:
                    opatch = mx1.group(1)
                if mx2 is not None:
                    spatch = mx2.group(1)
            # OpenBSD version and p1 versions are considered the same.
            if ((spatch == '') and (opatch == '1')) or ((spatch == '1') and (opatch == '')):
                return 0
        if spatch < opatch:
            return -1
        elif spatch > opatch:
            return 1
        return 0

    def between_versions(self, vfrom: str, vtill: str) -> bool:
        if bool(vfrom) and self.compare_version(vfrom) < 0:
            return False
        if bool(vtill) and self.compare_version(vtill) > 0:
            return False
        return True

    def display(self, full: bool = True) -> str:
        r = '{} '.format(self.vendor) if bool(self.vendor) else ''
        r += self.product
        if bool(self.version):
            r += ' {}'.format(self.version)
        if full:
            patch = self.patch or ''
            if self.product == Product.OpenSSH:
                mx = re.match(r'^(p\d)(.*)$', patch)
                if mx is not None:
                    r += mx.group(1)
                    patch = mx.group(2).strip()
            if bool(patch):
                r += ' ({})'.format(patch)
            if bool(self.os):
                r += ' running on {}'.format(self.os)
        return r

    def __str__(self) -> str:
        return self.display()

    def __repr__(self) -> str:
        r = 'vendor={}, '.format(self.vendor) if bool(self.vendor) else ''
        r += 'product={}'.format(self.product)
        if bool(self.version):
            r += ', version={}'.format(self.version)
        if bool(self.patch):
            r += ', patch={}'.format(self.patch)
        if bool(self.os):
            r += ', os={}'.format(self.os)
        return '<{}({})>'.format(self.__class__.__name__, r)

    @staticmethod
    def _fix_patch(patch: str) -> Optional[str]:
        return re.sub(r'^[-_\.]+', '', patch) or None

    @staticmethod
    def _fix_date(d: Optional[str]) -> Optional[str]:
        if d is not None and len(d) == 8:
            return '{}-{}-{}'.format(d[:4], d[4:6], d[6:8])
        else:
            return None

    @classmethod
    def _extract_os_version(cls, c: Optional[str]) -> Optional[str]:
        if c is None:
            return None
        mx = re.match(r'^NetBSD(?:_Secure_Shell)?(?:[\s-]+(\d{8})(.*))?$', c)
        if mx is not None:
            d = cls._fix_date(mx.group(1))
            return 'NetBSD' if d is None else 'NetBSD ({})'.format(d)
        mx = re.match(r'^FreeBSD(?:\slocalisations)?[\s-]+(\d{8})(.*)$', c)
        if not bool(mx):
            mx = re.match(r'^[^@]+@FreeBSD\.org[\s-]+(\d{8})(.*)$', c)
        if mx is not None:
            d = cls._fix_date(mx.group(1))
            return 'FreeBSD' if d is None else 'FreeBSD ({})'.format(d)
        w = ['RemotelyAnywhere', 'DesktopAuthority', 'RemoteSupportManager']
        for win_soft in w:
            mx = re.match(r'^in ' + win_soft + r' ([\d\.]+\d)$', c)
            if mx is not None:
                ver = mx.group(1)
                return 'Microsoft Windows ({} {})'.format(win_soft, ver)
        generic = ['NetBSD', 'FreeBSD']
        for g in generic:
            if c.startswith(g) or c.endswith(g):
                return g
        return None

    @classmethod
    def parse(cls, banner: 'Banner') -> Optional['Software']:
        # pylint: disable=too-many-return-statements
        software = str(banner.software)
        mx = re.match(r'^dropbear_([\d\.]+\d+)(.*)', software)
        v: Optional[str] = None
        if mx is not None:
            patch = cls._fix_patch(mx.group(2))
            v, p = 'Matt Johnston', Product.DropbearSSH
            v = None
            return cls(v, p, mx.group(1), patch, None)
        mx = re.match(r'^OpenSSH[_\.-]+([\d\.]+\d+)(.*)', software)
        if mx is not None:
            patch = cls._fix_patch(mx.group(2))
            v, p = 'OpenBSD', Product.OpenSSH
            v = None
            os_version = cls._extract_os_version(banner.comments)
            return cls(v, p, mx.group(1), patch, os_version)
        mx = re.match(r'^libssh-([\d\.]+\d+)(.*)', software)
        if mx is not None:
            patch = cls._fix_patch(mx.group(2))
            v, p = None, Product.LibSSH
            os_version = cls._extract_os_version(banner.comments)
            return cls(v, p, mx.group(1), patch, os_version)
        mx = re.match(r'^libssh_([\d\.]+\d+)(.*)', software)
        if mx is not None:
            patch = cls._fix_patch(mx.group(2))
            v, p = None, Product.LibSSH
            os_version = cls._extract_os_version(banner.comments)
            return cls(v, p, mx.group(1), patch, os_version)
        mx = re.match(r'^RomSShell_([\d\.]+\d+)(.*)', software)
        if mx is not None:
            patch = cls._fix_patch(mx.group(2))
            v, p = 'Allegro Software', 'RomSShell'
            return cls(v, p, mx.group(1), patch, None)
        mx = re.match(r'^mpSSH_([\d\.]+\d+)', software)
        if mx is not None:
            v, p = 'HP', 'iLO (Integrated Lights-Out) sshd'
            return cls(v, p, mx.group(1), None, None)
        mx = re.match(r'^Cisco-([\d\.]+\d+)', software)
        if mx is not None:
            v, p = 'Cisco', 'IOS/PIX sshd'
            return cls(v, p, mx.group(1), None, None)
        mx = re.match(r'^tinyssh_(.*)', software)
        if mx is not None:
            return cls(None, Product.TinySSH, mx.group(1), None, None)
        mx = re.match(r'^PuTTY_Release_(.*)', software)
        if mx:
            return cls(None, Product.PuTTY, mx.group(1), None, None)
        return None
