#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest


class TestSSH2(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.ssh = ssh_audit.SSH
		self.ssh2 = ssh_audit.SSH2
		self.rbuf = ssh_audit.ReadBuf
		self.wbuf = ssh_audit.WriteBuf
	
	def _kex_payload(self):
		w = self.wbuf()
		w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
		w.write_list([u'curve25519-sha256@libssh.org', u'ecdh-sha2-nistp256', u'ecdh-sha2-nistp384', u'ecdh-sha2-nistp521', u'diffie-hellman-group-exchange-sha256', u'diffie-hellman-group14-sha1'])
		w.write_list([u'ssh-rsa', u'rsa-sha2-512', u'rsa-sha2-256', u'ssh-ed25519'])
		w.write_list([u'chacha20-poly1305@openssh.com', u'aes128-ctr', u'aes192-ctr', u'aes256-ctr', u'aes128-gcm@openssh.com', u'aes256-gcm@openssh.com', u'aes128-cbc', u'aes192-cbc', u'aes256-cbc'])
		w.write_list([u'chacha20-poly1305@openssh.com', u'aes128-ctr', u'aes192-ctr', u'aes256-ctr', u'aes128-gcm@openssh.com', u'aes256-gcm@openssh.com', u'aes128-cbc', u'aes192-cbc', u'aes256-cbc'])
		w.write_list([u'umac-64-etm@openssh.com', u'umac-128-etm@openssh.com', u'hmac-sha2-256-etm@openssh.com', u'hmac-sha2-512-etm@openssh.com', u'hmac-sha1-etm@openssh.com', u'umac-64@openssh.com', u'umac-128@openssh.com', u'hmac-sha2-256', u'hmac-sha2-512', u'hmac-sha1'])
		w.write_list([u'umac-64-etm@openssh.com', u'umac-128-etm@openssh.com', u'hmac-sha2-256-etm@openssh.com', u'hmac-sha2-512-etm@openssh.com', u'hmac-sha1-etm@openssh.com', u'umac-64@openssh.com', u'umac-128@openssh.com', u'hmac-sha2-256', u'hmac-sha2-512', u'hmac-sha1'])
		w.write_list([u'none', u'zlib@openssh.com'])
		w.write_list([u'none', u'zlib@openssh.com'])
		w.write_list([u''])
		w.write_list([u''])
		w.write_byte(False)
		w.write_int(0)
		return w.write_flush()
	
	def test_kex_read(self):
		kex = self.ssh2.Kex.parse(self._kex_payload())
		assert kex is not None
		assert kex.cookie == b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
		assert kex.kex_algorithms == [u'curve25519-sha256@libssh.org', u'ecdh-sha2-nistp256', u'ecdh-sha2-nistp384', u'ecdh-sha2-nistp521', u'diffie-hellman-group-exchange-sha256', u'diffie-hellman-group14-sha1']
		assert kex.key_algorithms == [u'ssh-rsa', u'rsa-sha2-512', u'rsa-sha2-256', u'ssh-ed25519']
		assert kex.client is not None
		assert kex.server is not None
		assert kex.client.encryption == [u'chacha20-poly1305@openssh.com', u'aes128-ctr', u'aes192-ctr', u'aes256-ctr', u'aes128-gcm@openssh.com', u'aes256-gcm@openssh.com', u'aes128-cbc', u'aes192-cbc', u'aes256-cbc']
		assert kex.server.encryption == [u'chacha20-poly1305@openssh.com', u'aes128-ctr', u'aes192-ctr', u'aes256-ctr', u'aes128-gcm@openssh.com', u'aes256-gcm@openssh.com', u'aes128-cbc', u'aes192-cbc', u'aes256-cbc']
		assert kex.client.mac == [u'umac-64-etm@openssh.com', u'umac-128-etm@openssh.com', u'hmac-sha2-256-etm@openssh.com', u'hmac-sha2-512-etm@openssh.com', u'hmac-sha1-etm@openssh.com', u'umac-64@openssh.com', u'umac-128@openssh.com', u'hmac-sha2-256', u'hmac-sha2-512', u'hmac-sha1']
		assert kex.server.mac == [u'umac-64-etm@openssh.com', u'umac-128-etm@openssh.com', u'hmac-sha2-256-etm@openssh.com', u'hmac-sha2-512-etm@openssh.com', u'hmac-sha1-etm@openssh.com', u'umac-64@openssh.com', u'umac-128@openssh.com', u'hmac-sha2-256', u'hmac-sha2-512', u'hmac-sha1']
		assert kex.client.compression == [u'none', u'zlib@openssh.com']
		assert kex.server.compression == [u'none', u'zlib@openssh.com']
		assert kex.client.languages == [u'']
		assert kex.server.languages == [u'']
		assert kex.follows is False
		assert kex.unused == 0
