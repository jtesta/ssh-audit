#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest


class TestSSH1(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.ssh = ssh_audit.SSH
		self.ssh1 = ssh_audit.SSH1
		self.rbuf = ssh_audit.ReadBuf
		self.wbuf = ssh_audit.WriteBuf
	
	def test_crc32(self):
		assert self.ssh1.crc32(b'') == 0x00
		assert self.ssh1.crc32(b'The quick brown fox jumps over the lazy dog') == 0xb9c60808
	
	def _server_key(self):
		return (1024, 0x10001, 0xee6552da432e0ac2c422df1a51287507748bfe3b5e3e4fa989a8f49fdc163a17754939ef18ef8a667ea3b71036a151fcd7f5e01ceef1e4439864baf3ac569047582c69d6c128212e0980dcb3168f00d371004039983f6033cd785b8b8f85096c7d9405cbfdc664e27c966356a6b4eb6ee20ad43414b50de18b22829c1880b551)
	
	def _host_key(self):
		return (2048, 0x10001, 0xdfa20cd2a530ccc8c870aa60d9feb3b35deeab81c3215a96557abbd683d21f4600f38e475d87100da9a4404220eeb3bb5584e5a2b5b48ffda58530ea19104a32577d7459d91e76aa711b241050f4cc6d5327ccce254f371acad3be56d46eb5919b73f20dbdb1177b700f00891c5bf4ed128bb90ed541b778288285bcfa28432ab5cbcb8321b6e24760e998e0daa519f093a631e44276d7dd252ce0c08c75e2ab28a7349ead779f97d0f20a6d413bf3623cd216dc35375f6366690bcc41e3b2d5465840ec7ee0dc7e3f1c101d674a0c7dbccbc3942788b111396add2f8153b46a0e4b50d66e57ee92958f1c860dd97cc0e40e32febff915343ed53573142bdf4b)
	
	def _pkm_payload(self):
		w = self.wbuf()
		w.write(b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
		b, e, m = self._server_key()
		w.write_int(b).write_mpint1(e).write_mpint1(m)
		b, e, m = self._host_key()
		w.write_int(b).write_mpint1(e).write_mpint1(m)
		w.write_int(2)
		w.write_int(72)
		w.write_int(36)
		return w.write_flush()
	
	def test_fingerprint(self):
		b, e, m = self._host_key()
		fpd = self.wbuf._create_mpint(m, False)
		fpd += self.wbuf._create_mpint(e, False)
		fp = self.ssh.Fingerprint(fpd)
		assert fp.md5 == 'MD5:9d:26:f8:39:fc:20:9d:9b:ca:cc:4a:0f:e1:93:f5:96'
		assert fp.sha256 == 'SHA256:vZdx3mhzbvVJmn08t/ruv8WDhJ9jfKYsCTuSzot+QIs'
	
	def test_pkm_read(self):
		pkm = self.ssh1.PublicKeyMessage.parse(self._pkm_payload())
		assert pkm is not None
		assert pkm.cookie == b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
		b, e, m = self._server_key()
		assert pkm.server_key_bits == b
		assert pkm.server_key_public_exponent == e
		assert pkm.server_key_public_modulus == m
		b, e, m = self._host_key()
		assert pkm.host_key_bits == b
		assert pkm.host_key_public_exponent == e
		assert pkm.host_key_public_modulus == m
		fp = self.ssh.Fingerprint(pkm.host_key_fingerprint_data)
		assert pkm.protocol_flags == 2
		assert pkm.supported_ciphers_mask == 72
		assert pkm.supported_ciphers == ['3des', 'blowfish']
		assert pkm.supported_authentications_mask == 36
		assert pkm.supported_authentications == ['rsa', 'tis']
		assert fp.md5 == 'MD5:9d:26:f8:39:fc:20:9d:9b:ca:cc:4a:0f:e1:93:f5:96'
		assert fp.sha256 == 'SHA256:vZdx3mhzbvVJmn08t/ruv8WDhJ9jfKYsCTuSzot+QIs'
	
	def test_pkm_payload(self):
		cookie = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff' 
		skey = self._server_key()
		hkey = self._host_key()
		pflags = 2
		cmask = 72
		amask = 36
		pkm1 = self.ssh1.PublicKeyMessage(cookie, skey, hkey, pflags, cmask, amask)
		pkm2 = self.ssh1.PublicKeyMessage.parse(self._pkm_payload())
		assert pkm1.payload == pkm2.payload
