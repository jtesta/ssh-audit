#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
   The MIT License (MIT)
   
   Copyright (C) 2015 Andris Raugulis (moo@arthepsy.eu)
   
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
import os, io, sys, socket, struct

SSH_BANNER = 'SSH-2.0-OpenSSH_7.1'
SOCK_CONN_TIMEOUT = 3.0
SOCK_READ_TIMEOUT = 5.0

def usage():
	p = os.path.basename(sys.argv[0])
	out.head('# {0} v1.0.20151223, moo@arthepsy.eu'.format(p))
	out.info('\nusage: {} [-nv] host[:port]\n'.format(p))
	out.info('   -v  verbose')
	out.info('   -n  disable colors' + os.linesep)
	sys.exit(1)

class Output(object):
	colors = True
	verbose = False
	
	_colors = {
		'head': 36,
		'good': 32,
		'fail': 31,
		'warn': 33,
	}
	def sep(self):
		print()
	def _colorized(self, color):
		return lambda x: print(color + x + '\033[0m')
	def __getattr__(self, name):
		if self.colors and os.name == 'posix' and name in self._colors:
			color = '\033[0;{0}m'.format(self._colors[name])
			return self._colorized(color)
		else:
			return lambda x: print(x)

class KexParty(object):
	encryption = []
	mac = []
	compression = []
	languages = []

class Kex(object):
	cookie = None
	kex_algorithms = []
	key_algorithms = []
	server = KexParty()
	client = KexParty()
	follows = False
	unused = 0
	
	@classmethod
	def parse(cls, payload):
		kex = cls()
		buf = io.BytesIO(payload)
		kex.cookie = buf.read(16)
		kex.kex_algorithms = read_list(buf)
		kex.key_algorithms = read_list(buf)
		kex.client.encryption = read_list(buf)
		kex.server.encryption = read_list(buf)
		kex.client.mac = read_list(buf)
		kex.server.mac = read_list(buf)
		kex.client.compression = read_list(buf)
		kex.server.compression = read_list(buf)
		kex.client.languages = read_list(buf)
		kex.server.languages = read_list(buf)
		kex.follows = read_bool(buf)
		kex.unused = read_int(buf)
		return kex

def read_int(buf):
	return struct.unpack('>I', buf.read(4))[0]

def read_bool(buf):
	return struct.unpack('b', buf.read(1))[0] != 0

def read_list(buf):
	list_size = read_int(buf)
	return buf.read(list_size).decode().split(',')

def get_ssh_ver(v):
	return 'available since OpenSSH {0}'.format(v)


WARN_OPENSSH72_LEGACY = 'removed (in client) since OpenSSH 7.2, legacy algorithm'
WARN_OPENSSH70_LEGACY = 'removed since OpenSSH 7.0, legacy algorithm'
FAIL_OPENSSH70_WEAK   = 'removed (in server) and disabled (in client) since OpenSSH 7.0, weak algorithm'
FAIL_OPENSSH70_LOGJAM = 'disabled (in client) since OpenSSH 7.0, logjam attack'
INFO_OPENSSH69_CHACHA = 'default cipher since OpenSSH 6.9.'
FAIL_OPENSSH67_UNSAFE = 'removed (in server) since OpenSSH 6.7, unsafe algorithm'
FAIL_OPENSSH61_REMOVE = 'removed since OpenSSH 6.1, removed from specification'
FAIL_OPENSSH31_REMOVE = 'removed since OpenSSH 3.1'
KEX_DB = {
	'kex': {
		'diffie-hellman-group1-sha1': ['2.3.0', [FAIL_OPENSSH67_UNSAFE, FAIL_OPENSSH70_LOGJAM]],
		'diffie-hellman-group14-sha1': ['3.9'],
		'diffie-hellman-group-exchange-sha1': ['2.3.0', [FAIL_OPENSSH67_UNSAFE]],
		'diffie-hellman-group-exchange-sha256': ['4.4'],
		'ecdh-sha2-nistp256': ['5.7'],
		'ecdh-sha2-nistp384': ['5.7'],
		'ecdh-sha2-nistp521': ['5.7'],
		'curve25519-sha256@libssh.org': ['6.5'],
	},
	'key': {
		'ssh-ed25519': ['6.5'],
		'ssh-ed25519-cert-v01@openssh.com': ['6.5'],
		'ssh-rsa': ['2.5.0'],
		'ssh-dss': ['2.1.0', [FAIL_OPENSSH70_WEAK]],
		'ecdsa-sha2-nistp256': ['5.7'],
		'ecdsa-sha2-nistp384': ['5.7'],
		'ecdsa-sha2-nistp521': ['5.7'],
		'ssh-rsa-cert-v00@openssh.com': ['5.4', [], [WARN_OPENSSH70_LEGACY]],
		'ssh-dss-cert-v00@openssh.com': ['5.4', [FAIL_OPENSSH70_WEAK], [WARN_OPENSSH70_LEGACY]], 
		'ssh-rsa-cert-v01@openssh.com': ['5.6'],
		'ssh-dss-cert-v01@openssh.com': ['5.6', [FAIL_OPENSSH70_WEAK]],
		'ecdsa-sha2-nistp256-cert-v01@openssh.com': ['5.7'],
		'ecdsa-sha2-nistp384-cert-v01@openssh.com': ['5.7'],
		'ecdsa-sha2-nistp521-cert-v01@openssh.com': ['5.7'],
	},
	'enc': {
		'3des-cbc': ['1.2.2', [FAIL_OPENSSH67_UNSAFE]],
		'blowfish-cbc': ['1.2.2', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]], 
		'cast128-cbc': ['2.1.0', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'arcfour': ['2.1.0', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'arcfour128': ['4.2', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'arcfour256': ['4.2', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'aes128-cbc': ['2.3.0', [FAIL_OPENSSH67_UNSAFE]],
		'aes192-cbc': ['2.3.0', [FAIL_OPENSSH67_UNSAFE]],
		'aes256-cbc': ['2.3.0', [FAIL_OPENSSH67_UNSAFE]],
		'rijndael128-cbc': ['2.3.0', [FAIL_OPENSSH31_REMOVE]],
		'rijndael192-cbc': ['2.3.0', [FAIL_OPENSSH31_REMOVE]],
		'rijndael256-cbc': ['2.3.0', [FAIL_OPENSSH31_REMOVE]],
		'rijndael-cbc@lysator.liu.se': ['2.3.0', [], [WARN_OPENSSH72_LEGACY]],
		'aes128-ctr': ['3.7'],
		'aes192-ctr': ['3.7'],
		'aes256-ctr': ['3.7'],
		'aes128-gcm@openssh.com': ['6.2'],
		'aes256-gcm@openssh.com': ['6.2'],
		'chacha20-poly1305@openssh.com': ['6.5', [], [], [INFO_OPENSSH69_CHACHA]],
	},
	'mac': {
		'hmac-sha1': ['2.1.0'],
		'hmac-sha1-96': ['2.5.0', [FAIL_OPENSSH67_UNSAFE]],
		'hmac-sha2-256': ['5.9'],
		'hmac-sha2-256-96': ['5.9', [FAIL_OPENSSH61_REMOVE]],
		'hmac-sha2-512': ['5.9'],
		'hmac-sha2-512-96': ['5.9', [FAIL_OPENSSH61_REMOVE]],
		'hmac-md5': ['2.1.0', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'hmac-md5-96': ['2.5.0', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'hmac-ripemd160': ['2.5.0', [FAIL_OPENSSH67_UNSAFE]],
		'hmac-ripemd160@openssh.com': ['2.1.0', [FAIL_OPENSSH67_UNSAFE]],
		'umac-64@openssh.com': ['4.7'],
		'umac-128@openssh.com': ['6.2'],
		'hmac-sha1-etm@openssh.com': ['6.2'],
		'hmac-sha1-96-etm@openssh.com': ['6.2', [FAIL_OPENSSH67_UNSAFE]],
		'hmac-sha2-256-etm@openssh.com': ['6.2'],
		'hmac-sha2-512-etm@openssh.com': ['6.2'],
		'hmac-md5-etm@openssh.com': ['6.2', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'hmac-md5-96-etm@openssh.com': ['6.2', [FAIL_OPENSSH67_UNSAFE], [WARN_OPENSSH72_LEGACY]],
		'hmac-ripemd160-etm@openssh.com': ['6.2', [FAIL_OPENSSH67_UNSAFE]],
		'umac-64-etm@openssh.com': ['6.2'],
		'umac-128-etm@openssh.com': ['6.2'],
	}
}

def process_algorithms(alg_type, algorithms, maxlen=0):
	for algorithm in algorithms:
		process_algorithm(alg_type, algorithm, maxlen)

def process_algorithm(alg_type, alg_name, alg_max_len=0):
	prefix = '(' + alg_type + ') '
	if alg_max_len == 0:
		alg_max_len = len(alg_name)
	padding = ' ' * (alg_max_len - len(alg_name))
	texts = []
	if alg_name in KEX_DB[alg_type]:
		alg_desc = KEX_DB[alg_type][alg_name]
		ldesc = len(alg_desc)
		for idx, level in enumerate(['fail', 'warn', 'info']):
			if level == 'info':
				texts.append((level, get_ssh_ver(alg_desc[0])))
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

def process_kex(kex):
	state = 'zlib@openssh.com' in kex.server.compression
	state = 'enabled' if state else 'disabled'
	out.good('[info] compression is ' + state)
	ml = lambda l: max(len(i) for i in l)
	maxlen = max(ml(kex.kex_algorithms),
	             ml(kex.key_algorithms),
	             ml(kex.server.encryption),
	             ml(kex.server.mac))
	out.head('\n# key exchange algorithms')
	process_algorithms('kex', kex.kex_algorithms, maxlen)
	out.head('\n# host-key algorithms')
	process_algorithms('key', kex.key_algorithms, maxlen)
	out.head('\n# encryption algorithms (ciphers)')
	process_algorithms('enc', kex.server.encryption, maxlen)
	out.head('\n# message authentication code algorithms')
	process_algorithms('mac', kex.server.mac, maxlen)
	out.sep()

def read_ssh_packet(s):
	block_size = 8
	header = s.recv(block_size)
	packet_size = struct.unpack('>I', header[:4])[0]
	rest = header[4:]
	lrest = len(rest)
	padding = ord(rest[0:1])
	packet_type = ord(rest[1:2])
	if (packet_size - lrest) % block_size != 0:
		out.fail('[exception] invalid ssh packet (block size)')
		sys.exit(1)
	buf = s.recv(packet_size - lrest)
	packet = rest[2:] + buf[0:packet_size - lrest]
	payload = packet[0:packet_size - padding]
	return packet_type, payload

def parse_int(v):
	try:
		return int(v)
	except:
		return 0

def parse_args():
	host = None
	port = 22
	for arg in sys.argv[1:]:
		if arg.startswith('-'):
			arg = arg.lstrip('-')
			if arg == 'n': out.colors = False
			elif arg == 'v': out.verbose = True
			continue
		s = arg.split(':')
		host = s[0].strip()
		if len(s) > 1:
			port = parse_int(s[1])
	if not host or port <= 0:
		usage()
	return host, port

def main():
	host, port = parse_args()
	s = None
	try:
		s = socket.create_connection((host, port), SOCK_CONN_TIMEOUT)
		s.settimeout(SOCK_READ_TIMEOUT)
		banner = s.recv(1024).strip()
		out.head('# general')
		out.good('[info] banner: ' + banner.decode())
		if banner.decode().startswith('SSH-1.99-'):
			out.fail('[fail] protocol SSH1 enabled')
		s.send(SSH_BANNER.encode() + b'\r\n')
		packet_type, payload = read_ssh_packet(s)
		if packet_type != 20:
			out.fail('[exception] did not receive MSG_KEXINIT (20), instead received unknown message ({0})'.format(packet_type))
			sys.exit(1)
		kex = Kex.parse(payload)
		process_kex(kex)
	except Exception as e:
		out.fail('[fail] {}'.format(e))
		sys.exit(1)
	finally:
		if s:
			s.close()

if __name__ == '__main__':
	out = Output()
	main()
