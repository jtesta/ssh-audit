#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
   The MIT License (MIT)
   
   Copyright (C) 2016 Andris Raugulis (moo@arthepsy.eu)
   
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
from __future__ import print_function
import os, io, sys, socket, struct, random, errno, getopt, re, hashlib, base64

VERSION = 'v1.7.0'

if sys.version_info >= (3,):  # pragma: nocover
	StringIO, BytesIO = io.StringIO, io.BytesIO
	text_type = str
	binary_type = bytes
else:  # pragma: nocover
	import StringIO as _StringIO  # pylint: disable=import-error
	StringIO = BytesIO = _StringIO.StringIO
	text_type = unicode  # pylint: disable=undefined-variable
	binary_type = str
try:  # pragma: nocover
	# pylint: disable=unused-import
	from typing import List, Set, Sequence, Tuple, Iterable
	from typing import Callable, Optional, Union, Any
except ImportError:  # pragma: nocover
	pass
try:  # pragma: nocover
	from colorama import init as colorama_init
	colorama_init()  # pragma: nocover
except ImportError:  # pragma: nocover
	pass


def usage(err=None):
	# type: (Optional[str]) -> None
	uout = Output()
	p = os.path.basename(sys.argv[0])
	uout.head('# {0} {1}, moo@arthepsy.eu\n'.format(p, VERSION))
	if err is not None:
		uout.fail('\n' + err)
	uout.info('usage: {0} [-1246pbnvl] <host>\n'.format(p))
	uout.info('   -h,  --help             print this help')
	uout.info('   -1,  --ssh1             force ssh version 1 only')
	uout.info('   -2,  --ssh2             force ssh version 2 only')
	uout.info('   -4,  --ipv4             enable IPv4 (order of precedence)')
	uout.info('   -6,  --ipv6             enable IPv6 (order of precedence)')
	uout.info('   -p,  --port=<port>      port to connect')
	uout.info('   -b,  --batch            batch output')
	uout.info('   -n,  --no-colors        disable colors')
	uout.info('   -v,  --verbose          verbose output')
	uout.info('   -l,  --level=<level>    minimum output level (info|warn|fail)')
	uout.sep()
	sys.exit(1)


class AuditConf(object):
	# pylint: disable=too-many-instance-attributes
	def __init__(self, host=None, port=22):
		# type: (Optional[str], int) -> None
		self.host = host
		self.port = port
		self.ssh1 = True
		self.ssh2 = True
		self.batch = False
		self.colors = True
		self.verbose = False
		self.minlevel = 'info'
		self.ipvo = ()  # type: Sequence[int]
		self.ipv4 = False
		self.ipv6 = False
	
	def __setattr__(self, name, value):
		# type: (str, Union[str, int, bool, Sequence[int]]) -> None
		valid = False
		if name in ['ssh1', 'ssh2', 'batch', 'colors', 'verbose']:
			valid, value = True, True if value else False
		elif name in ['ipv4', 'ipv6']:
			valid = False
			value = True if value else False
			ipv = 4 if name == 'ipv4' else 6
			if value:
				value = tuple(list(self.ipvo) + [ipv])
			else:
				if len(self.ipvo) == 0:
					value = (6,) if ipv == 4 else (4,)
				else:
					value = tuple(filter(lambda x: x != ipv, self.ipvo))
			self.__setattr__('ipvo', value)
		elif name == 'ipvo':
			if isinstance(value, (tuple, list)):
				uniq_value = utils.unique_seq(value)
				value = tuple(filter(lambda x: x in (4, 6), uniq_value))
				valid = True
				ipv_both = len(value) == 0
				object.__setattr__(self, 'ipv4', ipv_both or 4 in value)
				object.__setattr__(self, 'ipv6', ipv_both or 6 in value)
		elif name == 'port':
			valid, port = True, utils.parse_int(value)
			if port < 1 or port > 65535:
				raise ValueError('invalid port: {0}'.format(value))
			value = port
		elif name in ['minlevel']:
			if value not in ('info', 'warn', 'fail'):
				raise ValueError('invalid level: {0}'.format(value))
			valid = True
		elif name == 'host':
			valid = True
		if valid:
			object.__setattr__(self, name, value)
	
	@classmethod
	def from_cmdline(cls, args, usage_cb):
		# type: (List[str], Callable[..., None]) -> AuditConf
		# pylint: disable=too-many-branches
		aconf = cls()
		try:
			sopts = 'h1246p:bnvl:'
			lopts = ['help', 'ssh1', 'ssh2', 'ipv4', 'ipv6', 'port',
			         'batch', 'no-colors', 'verbose', 'level=']
			opts, args = getopt.getopt(args, sopts, lopts)
		except getopt.GetoptError as err:
			usage_cb(str(err))
		aconf.ssh1, aconf.ssh2 = False, False
		oport = None
		for o, a in opts:
			if o in ('-h', '--help'):
				usage_cb()
			elif o in ('-1', '--ssh1'):
				aconf.ssh1 = True
			elif o in ('-2', '--ssh2'):
				aconf.ssh2 = True
			elif o in ('-4', '--ipv4'):
				aconf.ipv4 = True
			elif o in ('-6', '--ipv6'):
				aconf.ipv6 = True
			elif o in ('-p', '--port'):
				oport = a
			elif o in ('-b', '--batch'):
				aconf.batch = True
				aconf.verbose = True
			elif o in ('-n', '--no-colors'):
				aconf.colors = False
			elif o in ('-v', '--verbose'):
				aconf.verbose = True
			elif o in ('-l', '--level'):
				if a not in ('info', 'warn', 'fail'):
					usage_cb('level {0} is not valid'.format(a))
				aconf.minlevel = a
		if len(args) == 0:
			usage_cb()
		if oport is not None:
			host = args[0]
			port = utils.parse_int(oport)
		else:
			s = args[0].split(':')
			host = s[0].strip()
			if len(s) == 2:
				oport, port = s[1], utils.parse_int(s[1])
			else:
				oport, port = '22', 22
		if not host:
			usage_cb('host is empty')
		if port <= 0 or port > 65535:
			usage_cb('port {0} is not valid'.format(oport))
		aconf.host = host
		aconf.port = port
		if not (aconf.ssh1 or aconf.ssh2):
			aconf.ssh1, aconf.ssh2 = True, True
		return aconf


class Output(object):
	LEVELS = ['info', 'warn', 'fail']
	COLORS = {'head': 36, 'good': 32, 'warn': 33, 'fail': 31}
	
	def __init__(self):
		# type: () -> None
		self.batch = False
		self.colors = True
		self.verbose = False
		self.__minlevel = 0
	
	@property
	def minlevel(self):
		# type: () -> str
		if self.__minlevel < len(self.LEVELS):
			return self.LEVELS[self.__minlevel]
		return 'unknown'
	
	@minlevel.setter
	def minlevel(self, name):
		# type: (str) -> None
		self.__minlevel = self.getlevel(name)
	
	def getlevel(self, name):
		# type: (str) -> int
		cname = 'info' if name == 'good' else name
		if cname not in self.LEVELS:
			return sys.maxsize
		return self.LEVELS.index(cname)
	
	def sep(self):
		# type: () -> None
		if not self.batch:
			print()
	
	@property
	def colors_supported(self):
		# type: () -> bool
		return 'colorama' in sys.modules or os.name == 'posix'
	
	@staticmethod
	def _colorized(color):
		# type: (str) -> Callable[[text_type], None]
		return lambda x: print(u'{0}{1}\033[0m'.format(color, x))
	
	def __getattr__(self, name):
		# type: (str) -> Callable[[text_type], None]
		if name == 'head' and self.batch:
			return lambda x: None
		if not self.getlevel(name) >= self.__minlevel:
			return lambda x: None
		if self.colors and self.colors_supported and name in self.COLORS:
			color = '\033[0;{0}m'.format(self.COLORS[name])
			return self._colorized(color)
		else:
			return lambda x: print(u'{0}'.format(x))


class OutputBuffer(list):
	def __enter__(self):
		# type: () -> OutputBuffer
		# pylint: disable=attribute-defined-outside-init
		self.__buf = StringIO()
		self.__stdout = sys.stdout
		sys.stdout = self.__buf
		return self
	
	def flush(self):
		# type: () -> None
		for line in self:
			print(line)
	
	def __exit__(self, *args):
		# type: (*Any) -> None
		self.extend(self.__buf.getvalue().splitlines())
		sys.stdout = self.__stdout


class SSH2(object):  # pylint: disable=too-few-public-methods
	class KexParty(object):
		def __init__(self, enc, mac, compression, languages):
			# type: (List[text_type], List[text_type], List[text_type], List[text_type]) -> None
			self.__enc = enc
			self.__mac = mac
			self.__compression = compression
			self.__languages = languages
		
		@property
		def encryption(self):
			# type: () -> List[text_type]
			return self.__enc
		
		@property
		def mac(self):
			# type: () -> List[text_type]
			return self.__mac
		
		@property
		def compression(self):
			# type: () -> List[text_type]
			return self.__compression
		
		@property
		def languages(self):
			# type: () -> List[text_type]
			return self.__languages
	
	class Kex(object):
		def __init__(self, cookie, kex_algs, key_algs, cli, srv, follows, unused=0):
			# type: (binary_type, List[text_type], List[text_type], SSH2.KexParty, SSH2.KexParty, bool, int) -> None
			self.__cookie = cookie
			self.__kex_algs = kex_algs
			self.__key_algs = key_algs
			self.__client = cli
			self.__server = srv
			self.__follows = follows
			self.__unused = unused
		
		@property
		def cookie(self):
			# type: () -> binary_type
			return self.__cookie
		
		@property
		def kex_algorithms(self):
			# type: () -> List[text_type]
			return self.__kex_algs
		
		@property
		def key_algorithms(self):
			# type: () -> List[text_type]
			return self.__key_algs
		
		# client_to_server
		@property
		def client(self):
			# type: () -> SSH2.KexParty
			return self.__client
		
		# server_to_client
		@property
		def server(self):
			# type: () -> SSH2.KexParty
			return self.__server
		
		@property
		def follows(self):
			# type: () -> bool
			return self.__follows
		
		@property
		def unused(self):
			# type: () -> int
			return self.__unused
		
		def write(self, wbuf):
			# type: (WriteBuf) -> None
			wbuf.write(self.cookie)
			wbuf.write_list(self.kex_algorithms)
			wbuf.write_list(self.key_algorithms)
			wbuf.write_list(self.client.encryption)
			wbuf.write_list(self.server.encryption)
			wbuf.write_list(self.client.mac)
			wbuf.write_list(self.server.mac)
			wbuf.write_list(self.client.compression)
			wbuf.write_list(self.server.compression)
			wbuf.write_list(self.client.languages)
			wbuf.write_list(self.server.languages)
			wbuf.write_bool(self.follows)
			wbuf.write_int(self.__unused)
		
		@property
		def payload(self):
			# type: () -> binary_type
			wbuf = WriteBuf()
			self.write(wbuf)
			return wbuf.write_flush()
		
		@classmethod
		def parse(cls, payload):
			# type: (binary_type) -> SSH2.Kex
			buf = ReadBuf(payload)
			cookie = buf.read(16)
			kex_algs = buf.read_list()
			key_algs = buf.read_list()
			cli_enc = buf.read_list()
			srv_enc = buf.read_list()
			cli_mac = buf.read_list()
			srv_mac = buf.read_list()
			cli_compression = buf.read_list()
			srv_compression = buf.read_list()
			cli_languages = buf.read_list()
			srv_languages = buf.read_list()
			follows = buf.read_bool()
			unused = buf.read_int()
			cli = SSH2.KexParty(cli_enc, cli_mac, cli_compression, cli_languages)
			srv = SSH2.KexParty(srv_enc, srv_mac, srv_compression, srv_languages)
			kex = cls(cookie, kex_algs, key_algs, cli, srv, follows, unused)
			return kex


class SSH1(object):
	class CRC32(object):
		def __init__(self):
			# type: () -> None
			self._table = [0] * 256
			for i in range(256):
				crc = 0
				n = i
				for _ in range(8):
					x = (crc ^ n) & 1
					crc = (crc >> 1) ^ (x * 0xedb88320)
					n = n >> 1
				self._table[i] = crc
		
		def calc(self, v):
			# type: (binary_type) -> int
			crc, l = 0, len(v)
			for i in range(l):
				n = ord(v[i:i + 1])
				n = n ^ (crc & 0xff)
				crc = (crc >> 8) ^ self._table[n]
			return crc
	
	_crc32 = None  # type: Optional[SSH1.CRC32]
	CIPHERS = ['none', 'idea', 'des', '3des', 'tss', 'rc4', 'blowfish']
	AUTHS = [None, 'rhosts', 'rsa', 'password', 'rhosts_rsa', 'tis', 'kerberos']
	
	@classmethod
	def crc32(cls, v):
		# type: (binary_type) -> int
		if cls._crc32 is None:
			cls._crc32 = cls.CRC32()
		return cls._crc32.calc(v)
	
	class KexDB(object):  # pylint: disable=too-few-public-methods
		# pylint: disable=bad-whitespace
		FAIL_PLAINTEXT        = 'no encryption/integrity'
		FAIL_OPENSSH37_REMOVE = 'removed since OpenSSH 3.7'
		FAIL_NA_BROKEN        = 'not implemented in OpenSSH, broken algorithm'
		FAIL_NA_UNSAFE        = 'not implemented in OpenSSH (server), unsafe algorithm'
		TEXT_CIPHER_IDEA      = 'cipher used by commercial SSH'
		
		ALGORITHMS = {
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
		}  # type: Dict[str, Dict[str, List[List[str]]]]
	
	class PublicKeyMessage(object):
		def __init__(self, cookie, skey, hkey, pflags, cmask, amask):
			# type: (binary_type, Tuple[int, int, int], Tuple[int, int, int], int, int, int) -> None
			assert len(skey) == 3
			assert len(hkey) == 3
			self.__cookie = cookie
			self.__server_key = skey
			self.__host_key = hkey
			self.__protocol_flags = pflags
			self.__supported_ciphers_mask = cmask
			self.__supported_authentications_mask = amask
		
		@property
		def cookie(self):
			# type: () -> binary_type
			return self.__cookie
		
		@property
		def server_key_bits(self):
			# type: () -> int
			return self.__server_key[0]
		
		@property
		def server_key_public_exponent(self):
			# type: () -> int
			return self.__server_key[1]
		
		@property
		def server_key_public_modulus(self):
			# type: () -> int
			return self.__server_key[2]
		
		@property
		def host_key_bits(self):
			# type: () -> int
			return self.__host_key[0]
		
		@property
		def host_key_public_exponent(self):
			# type: () -> int
			return self.__host_key[1]
		
		@property
		def host_key_public_modulus(self):
			# type: () -> int
			return self.__host_key[2]
		
		@property
		def host_key_fingerprint_data(self):
			# type: () -> binary_type
			# pylint: disable=protected-access
			mod = WriteBuf._create_mpint(self.host_key_public_modulus, False)
			e = WriteBuf._create_mpint(self.host_key_public_exponent, False)
			return mod + e
		
		@property
		def protocol_flags(self):
			# type: () -> int
			return self.__protocol_flags
		
		@property
		def supported_ciphers_mask(self):
			# type: () -> int
			return self.__supported_ciphers_mask
		
		@property
		def supported_ciphers(self):
			# type: () -> List[text_type]
			ciphers = []
			for i in range(len(SSH1.CIPHERS)):
				if self.__supported_ciphers_mask & (1 << i) != 0:
					ciphers.append(utils.to_utext(SSH1.CIPHERS[i]))
			return ciphers
		
		@property
		def supported_authentications_mask(self):
			# type: () -> int
			return self.__supported_authentications_mask
		
		@property
		def supported_authentications(self):
			# type: () -> List[text_type]
			auths = []
			for i in range(1, len(SSH1.AUTHS)):
				if self.__supported_authentications_mask & (1 << i) != 0:
					auths.append(utils.to_utext(SSH1.AUTHS[i]))
			return auths
		
		def write(self, wbuf):
			# type: (WriteBuf) -> None
			wbuf.write(self.cookie)
			wbuf.write_int(self.server_key_bits)
			wbuf.write_mpint1(self.server_key_public_exponent)
			wbuf.write_mpint1(self.server_key_public_modulus)
			wbuf.write_int(self.host_key_bits)
			wbuf.write_mpint1(self.host_key_public_exponent)
			wbuf.write_mpint1(self.host_key_public_modulus)
			wbuf.write_int(self.protocol_flags)
			wbuf.write_int(self.supported_ciphers_mask)
			wbuf.write_int(self.supported_authentications_mask)
		
		@property
		def payload(self):
			# type: () -> binary_type
			wbuf = WriteBuf()
			self.write(wbuf)
			return wbuf.write_flush()
		
		@classmethod
		def parse(cls, payload):
			# type: (binary_type) -> SSH1.PublicKeyMessage
			buf = ReadBuf(payload)
			cookie = buf.read(8)
			server_key_bits = buf.read_int()
			server_key_exponent = buf.read_mpint1()
			server_key_modulus = buf.read_mpint1()
			skey = (server_key_bits, server_key_exponent, server_key_modulus)
			host_key_bits = buf.read_int()
			host_key_exponent = buf.read_mpint1()
			host_key_modulus = buf.read_mpint1()
			hkey = (host_key_bits, host_key_exponent, host_key_modulus)
			pflags = buf.read_int()
			cmask = buf.read_int()
			amask = buf.read_int()
			pkm = cls(cookie, skey, hkey, pflags, cmask, amask)
			return pkm


class ReadBuf(object):
	def __init__(self, data=None):
		# type: (Optional[binary_type]) -> None
		super(ReadBuf, self).__init__()
		self._buf = BytesIO(data) if data else BytesIO()
		self._len = len(data) if data else 0
	
	@property
	def unread_len(self):
		# type: () -> int
		return self._len - self._buf.tell()
	
	def read(self, size):
		# type: (int) -> binary_type
		return self._buf.read(size)
	
	def read_byte(self):
		# type: () -> int
		return struct.unpack('B', self.read(1))[0]
	
	def read_bool(self):
		# type: () -> bool
		return self.read_byte() != 0
	
	def read_int(self):
		# type: () -> int
		return struct.unpack('>I', self.read(4))[0]
	
	def read_list(self):
		# type: () -> List[text_type]
		list_size = self.read_int()
		return self.read(list_size).decode('utf-8', 'replace').split(',')
	
	def read_string(self):
		# type: () -> binary_type
		n = self.read_int()
		return self.read(n)
	
	@classmethod
	def _parse_mpint(cls, v, pad, sf):
		# type: (binary_type, binary_type, str) -> int
		r = 0
		if len(v) % 4:
			v = pad * (4 - (len(v) % 4)) + v
		for i in range(0, len(v), 4):
			r = (r << 32) | struct.unpack(sf, v[i:i + 4])[0]
		return r
		
	def read_mpint1(self):
		# type: () -> int
		# NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
		bits = struct.unpack('>H', self.read(2))[0]
		n = (bits + 7) // 8
		return self._parse_mpint(self.read(n), b'\x00', '>I')
	
	def read_mpint2(self):
		# type: () -> int
		# NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
		v = self.read_string()
		if len(v) == 0:
			return 0
		pad, sf = (b'\xff', '>i') if ord(v[0:1]) & 0x80 else (b'\x00', '>I')
		return self._parse_mpint(v, pad, sf)
	
	def read_line(self):
		# type: () -> text_type
		return self._buf.readline().rstrip().decode('utf-8', 'replace')


class WriteBuf(object):
	def __init__(self, data=None):
		# type: (Optional[binary_type]) -> None
		super(WriteBuf, self).__init__()
		self._wbuf = BytesIO(data) if data else BytesIO()
	
	def write(self, data):
		# type: (binary_type) -> WriteBuf
		self._wbuf.write(data)
		return self
	
	def write_byte(self, v):
		# type: (int) -> WriteBuf
		return self.write(struct.pack('B', v))
	
	def write_bool(self, v):
		# type: (bool) -> WriteBuf
		return self.write_byte(1 if v else 0)
	
	def write_int(self, v):
		# type: (int) -> WriteBuf
		return self.write(struct.pack('>I', v))
	
	def write_string(self, v):
		# type: (Union[binary_type, text_type]) -> WriteBuf
		if not isinstance(v, bytes):
			v = bytes(bytearray(v, 'utf-8'))
		self.write_int(len(v))
		return self.write(v)
	
	def write_list(self, v):
		# type: (List[text_type]) -> WriteBuf
		return self.write_string(u','.join(v))
	
	@classmethod
	def _bitlength(cls, n):
		# type: (int) -> int
		try:
			return n.bit_length()
		except AttributeError:
			return len(bin(n)) - (2 if n > 0 else 3)
		
	@classmethod
	def _create_mpint(cls, n, signed=True, bits=None):
		# type: (int, bool, Optional[int]) -> binary_type
		if bits is None:
			bits = cls._bitlength(n)
		length = bits // 8 + (1 if n != 0 else 0)
		ql = (length + 7) // 8
		fmt, v2 = '>{0}Q'.format(ql), [0] * ql
		for i in range(ql):
			v2[ql - i - 1] = (n & 0xffffffffffffffff)
			n >>= 64
		data = bytes(struct.pack(fmt, *v2)[-length:])
		if not signed:
			data = data.lstrip(b'\x00')
		elif data.startswith(b'\xff\x80'):
			data = data[1:]
		return data
	
	def write_mpint1(self, n):
		# type: (int) -> WriteBuf
		# NOTE: Data Type Enc @ http://www.snailbook.com/docs/protocol-1.5.txt
		bits = self._bitlength(n)
		data = self._create_mpint(n, False, bits)
		self.write(struct.pack('>H', bits))
		return self.write(data)
	
	def write_mpint2(self, n):
		# type: (int) -> WriteBuf
		# NOTE: Section 5 @ https://www.ietf.org/rfc/rfc4251.txt
		data = self._create_mpint(n)
		return self.write_string(data)
	
	def write_line(self, v):
		# type: (Union[binary_type, str]) -> WriteBuf
		if not isinstance(v, bytes):
			v = bytes(bytearray(v, 'utf-8'))
		v += b'\r\n'
		return self.write(v)
	
	def write_flush(self):
		# type: () -> binary_type
		payload = self._wbuf.getvalue()
		self._wbuf.truncate(0)
		self._wbuf.seek(0)
		return payload


class SSH(object):  # pylint: disable=too-few-public-methods
	class Protocol(object):  # pylint: disable=too-few-public-methods
		# pylint: disable=bad-whitespace
		SMSG_PUBLIC_KEY = 2
		MSG_KEXINIT     = 20
		MSG_NEWKEYS     = 21
		MSG_KEXDH_INIT  = 30
		MSG_KEXDH_REPLY = 32
	
	class Product(object):  # pylint: disable=too-few-public-methods
		OpenSSH = 'OpenSSH'
		DropbearSSH = 'Dropbear SSH'
		LibSSH = 'libssh'
	
	class Software(object):
		def __init__(self, vendor, product, version, patch, os_version):
			# type: (Optional[str], str, str, Optional[str], Optional[str]) -> None
			self.__vendor = vendor
			self.__product = product
			self.__version = version
			self.__patch = patch
			self.__os = os_version
		
		@property
		def vendor(self):
			# type: () -> Optional[str]
			return self.__vendor
		
		@property
		def product(self):
			# type: () -> str
			return self.__product
		
		@property
		def version(self):
			# type: () -> str
			return self.__version
		
		@property
		def patch(self):
			# type: () -> Optional[str]
			return self.__patch
		
		@property
		def os(self):
			# type: () -> Optional[str]
			return self.__os
		
		def compare_version(self, other):
			# type: (Union[None, SSH.Software, text_type]) -> int
			# pylint: disable=too-many-branches
			if other is None:
				return 1
			if isinstance(other, SSH.Software):
				other = '{0}{1}'.format(other.version, other.patch or '')
			else:
				other = str(other)
			mx = re.match(r'^([\d\.]+\d+)(.*)$', other)
			if mx:
				oversion, opatch = mx.group(1), mx.group(2).strip()
			else:
				oversion, opatch = other, ''
			if self.version < oversion:
				return -1
			elif self.version > oversion:
				return 1
			spatch = self.patch or ''
			if self.product == SSH.Product.DropbearSSH:
				if not re.match(r'^test\d.*$', opatch):
					opatch = 'z{0}'.format(opatch)
				if not re.match(r'^test\d.*$', spatch):
					spatch = 'z{0}'.format(spatch)
			elif self.product == SSH.Product.OpenSSH:
				mx1 = re.match(r'^p\d(.*)', opatch)
				mx2 = re.match(r'^p\d(.*)', spatch)
				if not (mx1 and mx2):
					if mx1:
						opatch = mx1.group(1)
					if mx2:
						spatch = mx2.group(1)
			if spatch < opatch:
				return -1
			elif spatch > opatch:
				return 1
			return 0
		
		def between_versions(self, vfrom, vtill):
			# type: (str, str) -> bool
			if vfrom and self.compare_version(vfrom) < 0:
				return False
			if vtill and self.compare_version(vtill) > 0:
				return False
			return True
		
		def display(self, full=True):
			# type: (bool) -> str
			r = '{0} '.format(self.vendor) if self.vendor else ''
			r += self.product
			if self.version:
				r += ' {0}'.format(self.version)
			if full:
				patch = self.patch or ''
				if self.product == SSH.Product.OpenSSH:
					mx = re.match(r'^(p\d)(.*)$', patch)
					if mx is not None:
						r += mx.group(1)
						patch = mx.group(2).strip()
				if patch:
					r += ' ({0})'.format(patch)
				if self.os:
					r += ' running on {0}'.format(self.os)
			return r
		
		def __str__(self):
			# type: () -> str
			return self.display()
		
		def __repr__(self):
			# type: () -> str
			r = 'vendor={0}'.format(self.vendor) if self.vendor else ''
			if self.product:
				if self.vendor:
					r += ', '
				r += 'product={0}'.format(self.product)
			if self.version:
				r += ', version={0}'.format(self.version)
			if self.patch:
				r += ', patch={0}'.format(self.patch)
			if self.os:
				r += ', os={0}'.format(self.os)
			return '<{0}({1})>'.format(self.__class__.__name__, r)
		
		@staticmethod
		def _fix_patch(patch):
			# type: (str) -> Optional[str]
			return re.sub(r'^[-_\.]+', '', patch) or None
		
		@staticmethod
		def _fix_date(d):
			# type: (str) -> Optional[str]
			if d is not None and len(d) == 8:
				return '{0}-{1}-{2}'.format(d[:4], d[4:6], d[6:8])
			else:
				return None
		
		@classmethod
		def _extract_os_version(cls, c):
			# type: (Optional[str]) -> str
			if c is None:
				return None
			mx = re.match(r'^NetBSD(?:_Secure_Shell)?(?:[\s-]+(\d{8})(.*))?$', c)
			if mx:
				d = cls._fix_date(mx.group(1))
				return 'NetBSD' if d is None else 'NetBSD ({0})'.format(d)
			mx = re.match(r'^FreeBSD(?:\slocalisations)?[\s-]+(\d{8})(.*)$', c)
			if not mx:
				mx = re.match(r'^[^@]+@FreeBSD\.org[\s-]+(\d{8})(.*)$', c)
			if mx:
				d = cls._fix_date(mx.group(1))
				return 'FreeBSD' if d is None else 'FreeBSD ({0})'.format(d)
			w = ['RemotelyAnywhere', 'DesktopAuthority', 'RemoteSupportManager']
			for win_soft in w:
				mx = re.match(r'^in ' + win_soft + r' ([\d\.]+\d)$', c)
				if mx:
					ver = mx.group(1)
					return 'Microsoft Windows ({0} {1})'.format(win_soft, ver)
			generic = ['NetBSD', 'FreeBSD']
			for g in generic:
				if c.startswith(g) or c.endswith(g):
					return g
			return None
		
		@classmethod
		def parse(cls, banner):
			# type: (SSH.Banner) -> SSH.Software
			# pylint: disable=too-many-return-statements
			software = str(banner.software)
			mx = re.match(r'^dropbear_([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = 'Matt Johnston', SSH.Product.DropbearSSH
				v = None
				return cls(v, p, mx.group(1), patch, None)
			mx = re.match(r'^OpenSSH[_\.-]+([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = 'OpenBSD', SSH.Product.OpenSSH
				v = None
				os_version = cls._extract_os_version(banner.comments)
				return cls(v, p, mx.group(1), patch, os_version)
			mx = re.match(r'^libssh-([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = None, SSH.Product.LibSSH
				os_version = cls._extract_os_version(banner.comments)
				return cls(v, p, mx.group(1), patch, os_version)
			mx = re.match(r'^RomSShell_([\d\.]+\d+)(.*)', software)
			if mx:
				patch = cls._fix_patch(mx.group(2))
				v, p = 'Allegro Software', 'RomSShell'
				return cls(v, p, mx.group(1), patch, None)
			mx = re.match(r'^mpSSH_([\d\.]+\d+)', software)
			if mx:
				v, p = 'HP', 'iLO (Integrated Lights-Out) sshd'
				return cls(v, p, mx.group(1), None, None)
			mx = re.match(r'^Cisco-([\d\.]+\d+)', software)
			if mx:
				v, p = 'Cisco', 'IOS/PIX sshd'
				return cls(v, p, mx.group(1), None, None)
			return None
	
	class Banner(object):
		_RXP, _RXR = r'SSH-\d\.\s*?\d+', r'(-\s*([^\s]*)(?:\s+(.*))?)?'
		RX_PROTOCOL = re.compile(re.sub(r'\\d(\+?)', r'(\\d\g<1>)', _RXP))
		RX_BANNER = re.compile(r'^({0}(?:(?:-{0})*)){1}$'.format(_RXP, _RXR))
		
		def __init__(self, protocol, software, comments, valid_ascii):
			# type: (Tuple[int, int], str, str, bool) -> None
			self.__protocol = protocol
			self.__software = software
			self.__comments = comments
			self.__valid_ascii = valid_ascii
		
		@property
		def protocol(self):
			# type: () -> Tuple[int, int]
			return self.__protocol
		
		@property
		def software(self):
			# type: () -> str
			return self.__software
		
		@property
		def comments(self):
			# type: () -> str
			return self.__comments
		
		@property
		def valid_ascii(self):
			# type: () -> bool
			return self.__valid_ascii
		
		def __str__(self):
			# type: () -> str
			r = 'SSH-{0}.{1}'.format(self.protocol[0], self.protocol[1])
			if self.software is not None:
				r += '-{0}'.format(self.software)
			if self.comments:
				r += ' {0}'.format(self.comments)
			return r
		
		def __repr__(self):
			# type: () -> str
			p = '{0}.{1}'.format(self.protocol[0], self.protocol[1])
			r = 'protocol={0}'.format(p)
			if self.software:
				r += ', software={0}'.format(self.software)
			if self.comments:
				r += ', comments={0}'.format(self.comments)
			return '<{0}({1})>'.format(self.__class__.__name__, r)
		
		@classmethod
		def parse(cls, banner):
			# type: (text_type) -> SSH.Banner
			valid_ascii = utils.is_ascii(banner)
			ascii_banner = utils.to_ascii(banner)
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
	
	class Fingerprint(object):
		def __init__(self, fpd):
			# type: (binary_type) -> None
			self.__fpd = fpd
		
		@property
		def md5(self):
			# type: () -> text_type
			h = hashlib.md5(self.__fpd).hexdigest()
			r = u':'.join(h[i:i + 2] for i in range(0, len(h), 2))
			return u'MD5:{0}'.format(r)
		
		@property
		def sha256(self):
			# type: () -> text_type
			h = base64.b64encode(hashlib.sha256(self.__fpd).digest())
			r = h.decode('ascii').rstrip('=')
			return u'SHA256:{0}'.format(r)
	
	class Security(object):  # pylint: disable=too-few-public-methods
		# pylint: disable=bad-whitespace
		CVE = {
			'Dropbear SSH': [
				['0.44', '2015.71', 1, 'CVE-2016-3116', 5.5, 'bypass command restrictions via xauth command injection'],
				['0.28', '2013.58', 1, 'CVE-2013-4434', 5.0, 'discover valid usernames through different time delays'],
				['0.28', '2013.58', 1, 'CVE-2013-4421', 5.0, 'cause DoS (memory consumption) via a compressed packet'],
				['0.52', '2011.54', 1, 'CVE-2012-0920', 7.1, 'execute arbitrary code or bypass command restrictions'],
				['0.40', '0.48.1',  1, 'CVE-2007-1099', 7.5, 'conduct a MitM attack (no warning for hostkey mismatch)'],
				['0.28', '0.47',    1, 'CVE-2006-1206', 7.5, 'cause DoS (slot exhaustion) via large number of connections'],
				['0.39', '0.47',    1, 'CVE-2006-0225', 4.6, 'execute arbitrary commands via scp with crafted filenames'],
				['0.28', '0.46',    1, 'CVE-2005-4178', 6.5, 'execute arbitrary code via buffer overflow vulnerability'],
				['0.28', '0.42',    1, 'CVE-2004-2486', 7.5, 'execute arbitrary code via DSS verification code']],
			'libssh': [
				['0.1',   '0.7.2',  1, 'CVE-2016-0739', 4.3, 'conduct a MitM attack (weakness in DH key generation)'],
				['0.5.1', '0.6.4',  1, 'CVE-2015-3146', 5.0, 'cause DoS via kex packets (null pointer dereference)'],
				['0.5.1', '0.6.3',  1, 'CVE-2014-8132', 5.0, 'cause DoS via kex init packet (dangling pointer)'],
				['0.4.7', '0.6.2',  1, 'CVE-2014-0017', 1.9, 'leak data via PRNG state reuse on forking servers'],
				['0.4.7', '0.5.3',  1, 'CVE-2013-0176', 4.3, 'cause DoS via kex packet (null pointer dereference)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-6063', 7.5, 'cause DoS or execute arbitrary code via sftp (double free)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4562', 7.5, 'cause DoS or execute arbitrary code (overflow check)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4561', 5.0, 'cause DoS via unspecified vectors (invalid pointer)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4560', 7.5, 'cause DoS or execute arbitrary code (buffer overflow)'],
				['0.4.7', '0.5.2',  1, 'CVE-2012-4559', 6.8, 'cause DoS or execute arbitrary code (double free)']]
		}  # type: Dict[str, List[List[Any]]]
		TXT = {
			'Dropbear SSH': [
				['0.28', '0.34', 1, 'remote root exploit', 'remote format string buffer overflow exploit (exploit-db#387)']],
			'libssh': [
				['0.3.3', '0.3.3', 1, 'null pointer check', 'missing null pointer check in "crypt_set_algorithms_server"'],
				['0.3.3', '0.3.3', 1, 'integer overflow',   'integer overflow in "buffer_get_data"'],
				['0.3.3', '0.3.3', 3, 'heap overflow',      'heap overflow in "packet_decrypt"']]
		}  # type: Dict[str, List[List[Any]]]
	
	class Socket(ReadBuf, WriteBuf):
		class InsufficientReadException(Exception):
			pass
		
		SM_BANNER_SENT = 1
		
		def __init__(self, host, port):
			# type: (str, int) -> None
			super(SSH.Socket, self).__init__()
			self.__block_size = 8
			self.__state = 0
			self.__header = []  # type: List[text_type]
			self.__banner = None  # type: Optional[SSH.Banner]
			self.__host = host
			self.__port = port
			self.__sock = None  # type: socket.socket
		
		def __enter__(self):
			# type: () -> SSH.Socket
			return self
		
		def _resolve(self, ipvo):
			# type: (Sequence[int]) -> Iterable[Tuple[int, Tuple[Any, ...]]]
			ipvo = tuple(filter(lambda x: x in (4, 6), utils.unique_seq(ipvo)))
			ipvo_len = len(ipvo)
			prefer_ipvo = ipvo_len > 0
			prefer_ipv4 = prefer_ipvo and ipvo[0] == 4
			if len(ipvo) == 1:
				family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(ipvo[0])
			else:
				family = socket.AF_UNSPEC
			try:
				stype = socket.SOCK_STREAM
				r = socket.getaddrinfo(self.__host, self.__port, family, stype)
				if prefer_ipvo:
					r = sorted(r, key=lambda x: x[0], reverse=not prefer_ipv4)
				check = any(stype == rline[2] for rline in r)
				for (af, socktype, proto, canonname, addr) in r:
					if not check or socktype == socket.SOCK_STREAM:
						yield (af, addr)
			except socket.error as e:
				out.fail('[exception] {0}'.format(e))
				sys.exit(1)
		
		def connect(self, ipvo=(), cto=3.0, rto=5.0):
			# type: (Sequence[int], float, float) -> None
			err = None
			for (af, addr) in self._resolve(ipvo):
				s = None
				try:
					s = socket.socket(af, socket.SOCK_STREAM)
					s.settimeout(cto)
					s.connect(addr)
					s.settimeout(rto)
					self.__sock = s
					return
				except socket.error as e:
					err = e
					self._close_socket(s)
			if err is None:
				errm = 'host {0} has no DNS records'.format(self.__host)
			else:
				errt = (self.__host, self.__port, err)
				errm = 'cannot connect to {0} port {1}: {2}'.format(*errt)
			out.fail('[exception] {0}'.format(errm))
			sys.exit(1)
		
		def get_banner(self, sshv=2):
			# type: (int) -> Tuple[Optional[SSH.Banner], List[text_type]]
			banner = 'SSH-{0}-OpenSSH_7.3'.format('1.5' if sshv == 1 else '2.0')
			rto = self.__sock.gettimeout()
			self.__sock.settimeout(0.7)
			s, e = self.recv()
			self.__sock.settimeout(rto)
			if s < 0:
				return self.__banner, self.__header
			if self.__state < self.SM_BANNER_SENT:
				self.send_banner(banner)
			while self.__banner is None:
				if not s > 0:
					s, e = self.recv()
					if s < 0:
						break
				while self.__banner is None and self.unread_len > 0:
					line = self.read_line()
					if len(line.strip()) == 0:
						continue
					if self.__banner is None:
						self.__banner = SSH.Banner.parse(line)
						if self.__banner is not None:
							continue
					self.__header.append(line)
				s = 0
			return self.__banner, self.__header
		
		def recv(self, size=2048):
			# type: (int) -> Tuple[int, Optional[str]]
			try:
				data = self.__sock.recv(size)
			except socket.timeout:
				return (-1, 'timeout')
			except socket.error as e:
				if e.args[0] in (errno.EAGAIN, errno.EWOULDBLOCK):
					return (0, 'retry')
				return (-1, str(e.args[-1]))
			if len(data) == 0:
				return (-1, None)
			pos = self._buf.tell()
			self._buf.seek(0, 2)
			self._buf.write(data)
			self._len += len(data)
			self._buf.seek(pos, 0)
			return (len(data), None)
		
		def send(self, data):
			# type: (binary_type) -> Tuple[int, Optional[str]]
			try:
				self.__sock.send(data)
				return (0, None)
			except socket.error as e:
				return (-1, str(e.args[-1]))
			self.__sock.send(data)
		
		def send_banner(self, banner):
			# type: (str) -> None
			self.send(banner.encode() + b'\r\n')
			if self.__state < self.SM_BANNER_SENT:
				self.__state = self.SM_BANNER_SENT
		
		def ensure_read(self, size):
			# type: (int) -> None
			while self.unread_len < size:
				s, e = self.recv()
				if s < 0:
					raise SSH.Socket.InsufficientReadException(e)
		
		def read_packet(self, sshv=2):
			# type: (int) -> Tuple[int, binary_type]
			try:
				header = WriteBuf()
				self.ensure_read(4)
				packet_length = self.read_int()
				header.write_int(packet_length)
				# XXX: validate length
				if sshv == 1:
					padding_length = (8 - packet_length % 8)
					self.ensure_read(padding_length)
					padding = self.read(padding_length)
					header.write(padding)
					payload_length = packet_length
					check_size = padding_length + payload_length
				else:
					self.ensure_read(1)
					padding_length = self.read_byte()
					header.write_byte(padding_length)
					payload_length = packet_length - padding_length - 1
					check_size = 4 + 1 + payload_length + padding_length
				if check_size % self.__block_size != 0:
					out.fail('[exception] invalid ssh packet (block size)')
					sys.exit(1)
				self.ensure_read(payload_length)
				if sshv == 1:
					payload = self.read(payload_length - 4)
					header.write(payload)
					crc = self.read_int()
					header.write_int(crc)
				else:
					payload = self.read(payload_length)
					header.write(payload)
				packet_type = ord(payload[0:1])
				if sshv == 1:
					rcrc = SSH1.crc32(padding + payload)
					if crc != rcrc:
						out.fail('[exception] packet checksum CRC32 mismatch.')
						sys.exit(1)
				else:
					self.ensure_read(padding_length)
					padding = self.read(padding_length)
				payload = payload[1:]
				return packet_type, payload
			except SSH.Socket.InsufficientReadException as ex:
				if ex.args[0] is None:
					header.write(self.read(self.unread_len))
					e = header.write_flush().strip()
				else:
					e = ex.args[0].encode('utf-8')
				return (-1, e)
		
		def send_packet(self):
			# type: () -> Tuple[int, Optional[str]]
			payload = self.write_flush()
			padding = -(len(payload) + 5) % 8
			if padding < 4:
				padding += 8
			plen = len(payload) + padding + 1
			pad_bytes = b'\x00' * padding
			data = struct.pack('>Ib', plen, padding) + payload + pad_bytes
			return self.send(data)
		
		def _close_socket(self, s):
			# type: (Optional[socket.socket]) -> None
			try:
				if s is not None:
					s.shutdown(socket.SHUT_RDWR)
					s.close()
			except:  # pylint: disable=bare-except
				pass
		
		def __del__(self):
			# type: () -> None
			self.__cleanup()
		
		def __exit__(self, *args):
			# type: (*Any) -> None
			self.__cleanup()
		
		def __cleanup(self):
			# type: () -> None
			self._close_socket(self.__sock)


class KexDH(object):
	def __init__(self, alg, g, p):
		# type: (str, int, int) -> None
		self.__alg = alg
		self.__g = g
		self.__p = p
		self.__q = (self.__p - 1) // 2
		self.__x = None  # type: Optional[int]
		self.__e = None  # type: Optional[int]
	
	def send_init(self, s):
		# type: (SSH.Socket) -> None
		r = random.SystemRandom()
		self.__x = r.randrange(2, self.__q)
		self.__e = pow(self.__g, self.__x, self.__p)
		s.write_byte(SSH.Protocol.MSG_KEXDH_INIT)
		s.write_mpint2(self.__e)
		s.send_packet()


class KexGroup1(KexDH):
	def __init__(self):
		# type: () -> None
		# rfc2409: second oakley group
		p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67'
		        'cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6d'
		        'f25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff'
		        '5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381'
		        'ffffffffffffffff', 16)
		super(KexGroup1, self).__init__('sha1', 2, p)


class KexGroup14(KexDH):
	def __init__(self):
		# type: () -> None
		# rfc3526: 2048-bit modp group
		p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67'
		        'cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6d'
		        'f25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff'
		        '5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d'
		        'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3'
		        'ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08'
		        'ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c5'
		        '5df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa0510'
		        '15728e5a8aacaa68ffffffffffffffff', 16)
		super(KexGroup14, self).__init__('sha1', 2, p)


class KexDB(object):  # pylint: disable=too-few-public-methods
	# pylint: disable=bad-whitespace
	WARN_OPENSSH72_LEGACY = 'disabled (in client) since OpenSSH 7.2, legacy algorithm'
	FAIL_OPENSSH70_LEGACY = 'removed since OpenSSH 7.0, legacy algorithm'
	FAIL_OPENSSH70_WEAK   = 'removed (in server) and disabled (in client) since OpenSSH 7.0, weak algorithm'
	FAIL_OPENSSH70_LOGJAM = 'disabled (in client) since OpenSSH 7.0, logjam attack'
	INFO_OPENSSH69_CHACHA = 'default cipher since OpenSSH 6.9.'
	FAIL_OPENSSH67_UNSAFE = 'removed (in server) since OpenSSH 6.7, unsafe algorithm'
	FAIL_OPENSSH61_REMOVE = 'removed since OpenSSH 6.1, removed from specification'
	FAIL_OPENSSH31_REMOVE = 'removed since OpenSSH 3.1'
	FAIL_DBEAR67_DISABLED = 'disabled since Dropbear SSH 2015.67'
	FAIL_DBEAR53_DISABLED = 'disabled since Dropbear SSH 0.53'
	FAIL_PLAINTEXT        = 'no encryption/integrity'
	WARN_CURVES_WEAK      = 'using weak elliptic curves'
	WARN_RNDSIG_KEY       = 'using weak random number generator could reveal the key'
	WARN_MODULUS_SIZE     = 'using small 1024-bit modulus'
	WARN_MODULUS_CUSTOM   = 'using custom size modulus (possibly weak)'
	WARN_HASH_WEAK        = 'using weak hashing algorithm'
	WARN_CIPHER_MODE      = 'using weak cipher mode'
	WARN_BLOCK_SIZE       = 'using small 64-bit block size'
	WARN_CIPHER_WEAK      = 'using weak cipher'
	WARN_ENCRYPT_AND_MAC  = 'using encrypt-and-MAC mode'
	WARN_TAG_SIZE         = 'using small 64-bit tag size'

	ALGORITHMS = {
		'kex': {
			'diffie-hellman-group1-sha1': [['2.3.0,d0.28,l10.2', '6.6', '6.9'], [FAIL_OPENSSH67_UNSAFE, FAIL_OPENSSH70_LOGJAM], [WARN_MODULUS_SIZE, WARN_HASH_WEAK]],
			'diffie-hellman-group14-sha1': [['3.9,d0.53,l10.6.0'], [], [WARN_HASH_WEAK]],
			'diffie-hellman-group14-sha256': [['7.3,d2016.73']],
			'diffie-hellman-group16-sha512': [['7.3,d2016.73']],
			'diffie-hellman-group18-sha512': [['7.3']],
			'diffie-hellman-group-exchange-sha1': [['2.3.0', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_HASH_WEAK]],
			'diffie-hellman-group-exchange-sha256': [['4.4'], [], [WARN_MODULUS_CUSTOM]],
			'ecdh-sha2-nistp256': [['5.7,d2013.62,l10.6.0'], [WARN_CURVES_WEAK]],
			'ecdh-sha2-nistp384': [['5.7,d2013.62'], [WARN_CURVES_WEAK]],
			'ecdh-sha2-nistp521': [['5.7,d2013.62'], [WARN_CURVES_WEAK]],
			'curve25519-sha256@libssh.org': [['6.5,d2013.62,l10.6.0']],
			'kexguess2@matt.ucc.asn.au': [['d2013.57']],
		},
		'key': {
			'rsa-sha2-256': [['7.2']],
			'rsa-sha2-512': [['7.2']],
			'ssh-ed25519': [['6.5,l10.7.0']],
			'ssh-ed25519-cert-v01@openssh.com': [['6.5']],
			'ssh-rsa': [['2.5.0,d0.28,l10.2']],
			'ssh-dss': [['2.1.0,d0.28,l10.2', '6.9'], [FAIL_OPENSSH70_WEAK], [WARN_MODULUS_SIZE, WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp256': [['5.7,d2013.62,l10.6.4'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp384': [['5.7,d2013.62,l10.6.4'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp521': [['5.7,d2013.62,l10.6.4'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ssh-rsa-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_OPENSSH70_LEGACY], []],
			'ssh-dss-cert-v00@openssh.com': [['5.4', '6.9'], [FAIL_OPENSSH70_LEGACY], [WARN_MODULUS_SIZE, WARN_RNDSIG_KEY]],
			'ssh-rsa-cert-v01@openssh.com': [['5.6']],
			'ssh-dss-cert-v01@openssh.com': [['5.6', '6.9'], [FAIL_OPENSSH70_WEAK], [WARN_MODULUS_SIZE, WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp256-cert-v01@openssh.com': [['5.7'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp384-cert-v01@openssh.com': [['5.7'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
			'ecdsa-sha2-nistp521-cert-v01@openssh.com': [['5.7'], [WARN_CURVES_WEAK], [WARN_RNDSIG_KEY]],
		},
		'enc': {
			'none': [['1.2.2,d2013.56,l10.2'], [FAIL_PLAINTEXT]],
			'3des-cbc': [['1.2.2,d0.28,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_WEAK, WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
			'3des-ctr': [['d0.52']],
			'blowfish-cbc': [['1.2.2,d0.28,l10.2', '6.6,d0.52', '7.1,d0.52'], [FAIL_OPENSSH67_UNSAFE, FAIL_DBEAR53_DISABLED], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
			'twofish-cbc': [['d0.28', 'd2014.66'], [FAIL_DBEAR67_DISABLED], [WARN_CIPHER_MODE]],
			'twofish128-cbc': [['d0.47', 'd2014.66'], [FAIL_DBEAR67_DISABLED], [WARN_CIPHER_MODE]],
			'twofish256-cbc': [['d0.47', 'd2014.66'], [FAIL_DBEAR67_DISABLED], [WARN_CIPHER_MODE]],
			'twofish128-ctr': [['d2015.68']],
			'twofish256-ctr': [['d2015.68']],
			'cast128-cbc': [['2.1.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE, WARN_BLOCK_SIZE]],
			'arcfour': [['2.1.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK]],
			'arcfour128': [['4.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK]],
			'arcfour256': [['4.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_WEAK]],
			'aes128-cbc': [['2.3.0,d0.28,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_MODE]],
			'aes192-cbc': [['2.3.0,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_MODE]],
			'aes256-cbc': [['2.3.0,d0.47,l10.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_CIPHER_MODE]],
			'rijndael128-cbc': [['2.3.0', '3.0.2'], [FAIL_OPENSSH31_REMOVE], [WARN_CIPHER_MODE]],
			'rijndael192-cbc': [['2.3.0', '3.0.2'], [FAIL_OPENSSH31_REMOVE], [WARN_CIPHER_MODE]],
			'rijndael256-cbc': [['2.3.0', '3.0.2'], [FAIL_OPENSSH31_REMOVE], [WARN_CIPHER_MODE]],
			'rijndael-cbc@lysator.liu.se': [['2.3.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_CIPHER_MODE]],
			'aes128-ctr': [['3.7,d0.52,l10.4.1']],
			'aes192-ctr': [['3.7,l10.4.1']],
			'aes256-ctr': [['3.7,d0.52,l10.4.1']],
			'aes128-gcm@openssh.com': [['6.2']],
			'aes256-gcm@openssh.com': [['6.2']],
			'chacha20-poly1305@openssh.com': [['6.5'], [], [], [INFO_OPENSSH69_CHACHA]],
		},
		'mac': {
			'none': [['d2013.56'], [FAIL_PLAINTEXT]],
			'hmac-sha1': [['2.1.0,d0.28,l10.2'], [], [WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-sha1-96': [['2.5.0,d0.47', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-sha2-256': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha2-256-96': [['5.9', '6.0'], [FAIL_OPENSSH61_REMOVE], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha2-512': [['5.9,d2013.56,l10.7.0'], [], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha2-512-96': [['5.9', '6.0'], [FAIL_OPENSSH61_REMOVE], [WARN_ENCRYPT_AND_MAC]],
			'hmac-md5': [['2.1.0,d0.28', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-md5-96': [['2.5.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC, WARN_HASH_WEAK]],
			'hmac-ripemd160': [['2.5.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC]],
			'hmac-ripemd160@openssh.com': [['2.1.0', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_ENCRYPT_AND_MAC]],
			'umac-64@openssh.com': [['4.7'], [], [WARN_ENCRYPT_AND_MAC, WARN_TAG_SIZE]],
			'umac-128@openssh.com': [['6.2'], [], [WARN_ENCRYPT_AND_MAC]],
			'hmac-sha1-etm@openssh.com': [['6.2'], [], [WARN_HASH_WEAK]],
			'hmac-sha1-96-etm@openssh.com': [['6.2', '6.6', None], [FAIL_OPENSSH67_UNSAFE], [WARN_HASH_WEAK]],
			'hmac-sha2-256-etm@openssh.com': [['6.2']],
			'hmac-sha2-512-etm@openssh.com': [['6.2']],
			'hmac-md5-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_HASH_WEAK]],
			'hmac-md5-96-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY, WARN_HASH_WEAK]],
			'hmac-ripemd160-etm@openssh.com': [['6.2', '6.6', '7.1'], [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
			'umac-64-etm@openssh.com': [['6.2'], [], [WARN_TAG_SIZE]],
			'umac-128-etm@openssh.com': [['6.2']],
		}
	}  # type: Dict[str, Dict[str, List[List[str]]]]


def get_ssh_version(version_desc):
	# type: (str) -> Tuple[str, str]
	if version_desc.startswith('d'):
		return (SSH.Product.DropbearSSH, version_desc[1:])
	elif version_desc.startswith('l1'):
		return (SSH.Product.LibSSH, version_desc[2:])
	else:
		return (SSH.Product.OpenSSH, version_desc)


def get_alg_timeframe(versions, for_server=True, result=None):
	# type: (List[str], bool, Optional[Dict[str, List[Optional[str]]]]) -> Dict[str, List[Optional[str]]]
	result = result or {}
	vlen = len(versions)
	for i in range(3):
		if i > vlen - 1:
			if i == 2 and vlen > 1:
				cversions = versions[1]
			else:
				continue
		else:
			cversions = versions[i]
		if cversions is None:
			continue
		for v in cversions.split(','):
			ssh_prefix, ssh_version = get_ssh_version(v)
			if not ssh_version:
				continue
			if ssh_version.endswith('C'):
				if for_server:
					continue
				ssh_version = ssh_version[:-1]
			if ssh_prefix not in result:
				result[ssh_prefix] = [None, None, None]
			prev, push = result[ssh_prefix][i], False
			if prev is None:
				push = True
			elif i == 0 and prev < ssh_version:
				push = True
			elif i > 0 and prev > ssh_version:
				push = True
			if push:
				result[ssh_prefix][i] = ssh_version
	return result


def get_ssh_timeframe(alg_pairs, for_server=True):
	# type: (List[Tuple[int, Dict[str, Dict[str, List[List[str]]]], List[Tuple[str, List[text_type]]]]], bool) -> Dict[str, List[Optional[str]]]
	timeframe = {}  # type: Dict[str, List[Optional[str]]]
	for alg_pair in alg_pairs:
		alg_db = alg_pair[1]
		for alg_set in alg_pair[2]:
			alg_type, alg_list = alg_set
			for alg_name in alg_list:
				alg_name_native = utils.to_ntext(alg_name)
				alg_desc = alg_db[alg_type].get(alg_name_native)
				if alg_desc is None:
					continue
				versions = alg_desc[0]
				timeframe = get_alg_timeframe(versions, for_server, timeframe)
	return timeframe


def get_alg_since_text(versions):
	# type: (List[str]) -> text_type
	tv = []
	if len(versions) == 0 or versions[0] is None:
		return None
	for v in versions[0].split(','):
		ssh_prefix, ssh_version = get_ssh_version(v)
		if not ssh_version:
			continue
		if ssh_prefix in [SSH.Product.LibSSH]:
			continue
		if ssh_version.endswith('C'):
			ssh_version = '{0} (client only)'.format(ssh_version[:-1])
		tv.append('{0} {1}'.format(ssh_prefix, ssh_version))
	if len(tv) == 0:
		return None
	return 'available since ' + ', '.join(tv).rstrip(', ')


def get_alg_pairs(kex, pkm):
	# type: (Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage]) -> List[Tuple[int, Dict[str, Dict[str, List[List[str]]]], List[Tuple[str, List[text_type]]]]]
	alg_pairs = []
	if pkm is not None:
		alg_pairs.append((1, SSH1.KexDB.ALGORITHMS,
		                  [('key', [u'ssh-rsa1']),
		                   ('enc', pkm.supported_ciphers),
		                   ('aut', pkm.supported_authentications)]))
	if kex is not None:
		alg_pairs.append((2, KexDB.ALGORITHMS,
		                  [('kex', kex.kex_algorithms),
		                   ('key', kex.key_algorithms),
		                   ('enc', kex.server.encryption),
		                   ('mac', kex.server.mac)]))
	return alg_pairs


def get_alg_recommendations(software, kex, pkm, for_server=True):
	# type: (SSH.Software, SSH2.Kex, SSH1.PublicKeyMessage, bool) -> Tuple[SSH.Software, Dict[int, Dict[str, Dict[str, Dict[str, int]]]]]
	# pylint: disable=too-many-locals,too-many-statements
	alg_pairs = get_alg_pairs(kex, pkm)
	vproducts = [SSH.Product.OpenSSH,
	             SSH.Product.DropbearSSH,
	             SSH.Product.LibSSH]
	if software is not None:
		if software.product not in vproducts:
			software = None
	if software is None:
		ssh_timeframe = get_ssh_timeframe(alg_pairs, for_server)
		for product in vproducts:
			if product not in ssh_timeframe:
				continue
			version = ssh_timeframe[product][0]
			if version is not None:
				software = SSH.Software(None, product, version, None, None)
				break
	rec = {}  # type: Dict[int, Dict[str, Dict[str, Dict[str, int]]]]
	if software is None:
		return software, rec
	for alg_pair in alg_pairs:
		sshv, alg_db = alg_pair[0], alg_pair[1]
		rec[sshv] = {}
		for alg_set in alg_pair[2]:
			alg_type, alg_list = alg_set
			if alg_type == 'aut':
				continue
			rec[sshv][alg_type] = {'add': {}, 'del': {}}
			for n, alg_desc in alg_db[alg_type].items():
				if alg_type == 'key' and '-cert-' in n:
					continue
				versions = alg_desc[0]
				if len(versions) == 0 or versions[0] is None:
					continue
				matches = False
				for v in versions[0].split(','):
					ssh_prefix, ssh_version = get_ssh_version(v)
					if not ssh_version:
						continue
					if ssh_prefix != software.product:
						continue
					if ssh_version.endswith('C'):
						if for_server:
							continue
						ssh_version = ssh_version[:-1]
					if software.compare_version(ssh_version) < 0:
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
					if faults > 0:
						continue
					rec[sshv][alg_type]['add'][n] = 0
				else:
					if faults == 0:
						continue
					if n == 'diffie-hellman-group-exchange-sha256':
						if software.compare_version('7.3') < 0:
							continue
					rec[sshv][alg_type]['del'][n] = faults
			add_count = len(rec[sshv][alg_type]['add'])
			del_count = len(rec[sshv][alg_type]['del'])
			new_alg_count = len(alg_list) + add_count - del_count
			if new_alg_count < 1 and del_count > 0:
				mf = min(rec[sshv][alg_type]['del'].values())
				new_del = {}
				for k, cf in rec[sshv][alg_type]['del'].items():
					if cf != mf:
						new_del[k] = cf
				if del_count != len(new_del):
					rec[sshv][alg_type]['del'] = new_del
					new_alg_count += del_count - len(new_del)
			if new_alg_count < 1:
				del rec[sshv][alg_type]
			else:
				if add_count == 0:
					del rec[sshv][alg_type]['add']
				if del_count == 0:
					del rec[sshv][alg_type]['del']
				if len(rec[sshv][alg_type]) == 0:
					del rec[sshv][alg_type]
		if len(rec[sshv]) == 0:
			del rec[sshv]
	return software, rec


def output_algorithms(title, alg_db, alg_type, algorithms, maxlen=0):
	# type: (str, Dict[str, Dict[str, List[List[str]]]], str, List[text_type], int) -> None
	with OutputBuffer() as obuf:
		for algorithm in algorithms:
			output_algorithm(alg_db, alg_type, algorithm, maxlen)
	if len(obuf) > 0:
		out.head('# ' + title)
		obuf.flush()
		out.sep()


def output_algorithm(alg_db, alg_type, alg_name, alg_max_len=0):
	# type: (Dict[str, Dict[str, List[List[str]]]], str, text_type, int) -> None
	prefix = '(' + alg_type + ') '
	if alg_max_len == 0:
		alg_max_len = len(alg_name)
	padding = '' if out.batch else ' ' * (alg_max_len - len(alg_name))
	texts = []
	if len(alg_name.strip()) == 0:
		return
	alg_name_native = utils.to_ntext(alg_name)
	if alg_name_native in alg_db[alg_type]:
		alg_desc = alg_db[alg_type][alg_name_native]
		ldesc = len(alg_desc)
		for idx, level in enumerate(['fail', 'warn', 'info']):
			if level == 'info':
				versions = alg_desc[0]
				since_text = get_alg_since_text(versions)
				if since_text:
					texts.append((level, since_text))
			idx = idx + 1
			if ldesc > idx:
				for t in alg_desc[idx]:
					texts.append((level, t))
		if len(texts) == 0:
			texts.append(('info', ''))
	else:
		texts.append(('warn', 'unknown algorithm'))
	first = True
	for (level, text) in texts:
		f = getattr(out, level)
		text = '[' + level + '] ' + text
		if first:
			if first and level == 'info':
				f = out.good
			f(prefix + alg_name + padding + ' -- ' + text)
			first = False
		else:
			if out.verbose:
				f(prefix + alg_name + padding + ' -- ' + text)
			else:
				f(' ' * len(prefix + alg_name) + padding + ' `- ' + text)


def output_compatibility(kex, pkm, for_server=True):
	# type: (Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage], bool) -> None
	alg_pairs = get_alg_pairs(kex, pkm)
	ssh_timeframe = get_ssh_timeframe(alg_pairs, for_server)
	vp = 1 if for_server else 2
	comp_text = []
	for sshd_name in [SSH.Product.OpenSSH, SSH.Product.DropbearSSH]:
		if sshd_name not in ssh_timeframe:
			continue
		v = ssh_timeframe[sshd_name]
		if v[vp] is None:
			comp_text.append('{0} {1}+'.format(sshd_name, v[0]))
		elif v[0] == v[vp]:
			comp_text.append('{0} {1}'.format(sshd_name, v[0]))
		else:
			if v[vp] < v[0]:
				tfmt = '{0} {1}+ (some functionality from {2})'
			else:
				tfmt = '{0} {1}-{2}'
			comp_text.append(tfmt.format(sshd_name, v[0], v[vp]))
	if len(comp_text) > 0:
		out.good('(gen) compatibility: ' + ', '.join(comp_text))


def output_security_sub(sub, software, padlen):
	# type: (str, SSH.Software, int) -> None
	secdb = SSH.Security.CVE if sub == 'cve' else SSH.Security.TXT
	if software is None or software.product not in secdb:
		return
	for line in secdb[software.product]:
		vfrom, vtill = line[0:2]  # type: str, str
		if not software.between_versions(vfrom, vtill):
			continue
		target, name = line[2:4]  # type: int, str
		is_server, is_client = target & 1 == 1, target & 2 == 2
		is_local = target & 4 == 4
		if not is_server:
			continue
		p = '' if out.batch else ' ' * (padlen - len(name))
		if sub == 'cve':
			cvss, descr = line[4:6]  # type: float, str
			out.fail('(cve) {0}{1} -- ({2}) {3}'.format(name, p, cvss, descr))
		else:
			descr = line[4]
			out.fail('(sec) {0}{1} -- {2}'.format(name, p, descr))


def output_security(banner, padlen):
	# type: (SSH.Banner, int) -> None
	with OutputBuffer() as obuf:
		if banner:
			software = SSH.Software.parse(banner)
			output_security_sub('cve', software, padlen)
			output_security_sub('txt', software, padlen)
	if len(obuf) > 0:
		out.head('# security')
		obuf.flush()
		out.sep()


def output_fingerprint(kex, pkm, sha256=True, padlen=0):
	# type: (Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage], bool, int) -> None
	with OutputBuffer() as obuf:
		fps = []
		if pkm is not None:
			name = 'ssh-rsa1'
			fp = SSH.Fingerprint(pkm.host_key_fingerprint_data)
			bits = pkm.host_key_bits
			fps.append((name, fp, bits))
		for fpp in fps:
			name, fp, bits = fpp
			fpo = fp.sha256 if sha256 else fp.md5
			p = '' if out.batch else ' ' * (padlen - len(name))
			out.good('(fin) {0}{1} -- {2} {3}'.format(name, p, bits, fpo))
	if len(obuf) > 0:
		out.head('# fingerprints')
		obuf.flush()
		out.sep()


def output_recommendations(software, kex, pkm, padlen=0):
	# type: (SSH.Software, SSH2.Kex, SSH1.PublicKeyMessage, int) -> None
	for_server = True
	with OutputBuffer() as obuf:
		software, alg_rec = get_alg_recommendations(software, kex, pkm, for_server)
		for sshv in range(2, 0, -1):
			if sshv not in alg_rec:
				continue
			for alg_type in ['kex', 'key', 'enc', 'mac']:
				if alg_type not in alg_rec[sshv]:
					continue
				for action in ['del', 'add']:
					if action not in alg_rec[sshv][alg_type]:
						continue
					for name in alg_rec[sshv][alg_type][action]:
						p = '' if out.batch else ' ' * (padlen - len(name))
						if action == 'del':
							an, sg, fn = 'remove', '-', out.warn
							if alg_rec[sshv][alg_type][action][name] >= 10:
								fn = out.fail
						else:
							an, sg, fn = 'append', '+', out.good
						b = '(SSH{0})'.format(sshv) if sshv == 1 else ''
						fm = '(rec) {0}{1}{2}-- {3} algorithm to {4} {5}'
						fn(fm.format(sg, name, p, alg_type, an, b))
	if len(obuf) > 0:
		title = '(for {0})'.format(software.display(False)) if software else ''
		out.head('# algorithm recommendations {0}'.format(title))
		obuf.flush()
		out.sep()


def output(banner, header, kex=None, pkm=None):
	# type: (Optional[SSH.Banner], List[text_type], Optional[SSH2.Kex], Optional[SSH1.PublicKeyMessage]) -> None
	sshv = 1 if pkm else 2
	with OutputBuffer() as obuf:
		if len(header) > 0:
			out.info('(gen) header: ' + '\n'.join(header))
		if banner is not None:
			out.good('(gen) banner: {0}'.format(banner))
			if not banner.valid_ascii:
				# NOTE: RFC 4253, Section 4.2
				out.warn('(gen) banner contains non-printable ASCII')
			if sshv == 1 or banner.protocol[0] == 1:
				out.fail('(gen) protocol SSH1 enabled')
			software = SSH.Software.parse(banner)
			if software is not None:
				out.good('(gen) software: {0}'.format(software))
		else:
			software = None
		output_compatibility(kex, pkm)
		if kex is not None:
			compressions = [x for x in kex.server.compression if x != 'none']
			if len(compressions) > 0:
				cmptxt = 'enabled ({0})'.format(', '.join(compressions))
			else:
				cmptxt = 'disabled'
			out.good('(gen) compression: {0}'.format(cmptxt))
	if len(obuf) > 0:
		out.head('# general')
		obuf.flush()
		out.sep()
	ml, maxlen = lambda l: max(len(i) for i in l), 0
	if pkm is not None:
		maxlen = max(ml(pkm.supported_ciphers),
		             ml(pkm.supported_authentications),
		             maxlen)
	if kex is not None:
		maxlen = max(ml(kex.kex_algorithms),
		             ml(kex.key_algorithms),
		             ml(kex.server.encryption),
		             ml(kex.server.mac),
		             maxlen)
	maxlen += 1
	output_security(banner, maxlen)
	if pkm is not None:
		adb = SSH1.KexDB.ALGORITHMS
		ciphers = pkm.supported_ciphers
		auths = pkm.supported_authentications
		title, atype = 'SSH1 host-key algorithms', 'key'
		output_algorithms(title, adb, atype, ['ssh-rsa1'], maxlen)
		title, atype = 'SSH1 encryption algorithms (ciphers)', 'enc'
		output_algorithms(title, adb, atype, ciphers, maxlen)
		title, atype = 'SSH1 authentication types', 'aut'
		output_algorithms(title, adb, atype, auths, maxlen)
	if kex is not None:
		adb = KexDB.ALGORITHMS
		title, atype = 'key exchange algorithms', 'kex'
		output_algorithms(title, adb, atype, kex.kex_algorithms, maxlen)
		title, atype = 'host-key algorithms', 'key'
		output_algorithms(title, adb, atype, kex.key_algorithms, maxlen)
		title, atype = 'encryption algorithms (ciphers)', 'enc'
		output_algorithms(title, adb, atype, kex.server.encryption, maxlen)
		title, atype = 'message authentication code algorithms', 'mac'
		output_algorithms(title, adb, atype, kex.server.mac, maxlen)
	output_recommendations(software, kex, pkm, maxlen)
	output_fingerprint(kex, pkm, True, maxlen)


class Utils(object):
	@classmethod
	def _type_err(cls, v, target):
		# type: (Any, text_type) -> TypeError
		return TypeError('cannot convert {0} to {1}'.format(type(v), target))
	
	@classmethod
	def to_bytes(cls, v, enc='utf-8'):
		# type: (Union[binary_type, text_type], str) -> binary_type
		if isinstance(v, binary_type):
			return v
		elif isinstance(v, text_type):
			return v.encode(enc)
		raise cls._type_err(v, 'bytes')
	
	@classmethod
	def to_utext(cls, v, enc='utf-8'):
		# type: (Union[text_type, binary_type], str) -> text_type
		if isinstance(v, text_type):
			return v
		elif isinstance(v, binary_type):
			return v.decode(enc)
		raise cls._type_err(v, 'unicode text')
	
	@classmethod
	def to_ntext(cls, v, enc='utf-8'):
		# type: (Union[text_type, binary_type], str) -> str
		if isinstance(v, str):
			return v
		elif isinstance(v, text_type):
			return v.encode(enc)
		elif isinstance(v, binary_type):
			return v.decode(enc)
		raise cls._type_err(v, 'native text')
	
	@classmethod
	def is_ascii(cls, v):
		# type: (Union[text_type, str]) -> bool
		try:
			if isinstance(v, (text_type, str)):
				v.encode('ascii')
				return True
		except UnicodeEncodeError:
			pass
		return False
	
	@classmethod
	def to_ascii(cls, v, errors='replace'):
		# type: (Union[text_type, str], str) -> str
		if isinstance(v, (text_type, str)):
			return cls.to_ntext(v.encode('ascii', errors))
		raise cls._type_err(v, 'ascii')
	
	@classmethod
	def unique_seq(cls, seq):
		# type: (Sequence[Any]) -> Sequence[Any]
		seen = set()  # type: Set[Any]
		
		def _seen_add(x):
			# type: (Any) -> bool
			seen.add(x)
			return False
		
		if isinstance(seq, tuple):
			return tuple(x for x in seq if x not in seen and not _seen_add(x))
		else:
			return [x for x in seq if x not in seen and not _seen_add(x)]
		
	@staticmethod
	def parse_int(v):
		# type: (Any) -> int
		try:
			return int(v)
		except:  # pylint: disable=bare-except
			return 0


def audit(aconf, sshv=None):
	# type: (AuditConf, Optional[int]) -> None
	out.batch = aconf.batch
	out.colors = aconf.colors
	out.verbose = aconf.verbose
	out.minlevel = aconf.minlevel
	s = SSH.Socket(aconf.host, aconf.port)
	s.connect(aconf.ipvo)
	if sshv is None:
		sshv = 2 if aconf.ssh2 else 1
	err = None
	banner, header = s.get_banner(sshv)
	if banner is None:
		err = '[exception] did not receive banner.'
	if err is None:
		packet_type, payload = s.read_packet(sshv)
		if packet_type < 0:
			try:
				payload_txt = payload.decode('utf-8') if payload else u'empty'
			except UnicodeDecodeError:
				payload_txt = u'"{0}"'.format(repr(payload).lstrip('b')[1:-1])
			if payload_txt == u'Protocol major versions differ.':
				if sshv == 2 and aconf.ssh1:
					audit(aconf, 1)
					return
			err = '[exception] error reading packet ({0})'.format(payload_txt)
		else:
			err_pair = None
			if sshv == 1 and packet_type != SSH.Protocol.SMSG_PUBLIC_KEY:
				err_pair = ('SMSG_PUBLIC_KEY', SSH.Protocol.SMSG_PUBLIC_KEY)
			elif sshv == 2 and packet_type != SSH.Protocol.MSG_KEXINIT:
				err_pair = ('MSG_KEXINIT', SSH.Protocol.MSG_KEXINIT)
			if err_pair is not None:
				fmt = '[exception] did not receive {0} ({1}), ' + \
				      'instead received unknown message ({2})'
				err = fmt.format(err_pair[0], err_pair[1], packet_type)
	if err:
		output(banner, header)
		out.fail(err)
		sys.exit(1)
	if sshv == 1:
		pkm = SSH1.PublicKeyMessage.parse(payload)
		output(banner, header, pkm=pkm)
	elif sshv == 2:
		kex = SSH2.Kex.parse(payload)
		output(banner, header, kex=kex)


utils = Utils()
out = Output()
if __name__ == '__main__':  # pragma: nocover
	conf = AuditConf.from_cmdline(sys.argv[1:], usage)
	audit(conf)
