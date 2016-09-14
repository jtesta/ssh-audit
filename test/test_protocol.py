#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest
import re


class TestProtocol(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.rbuf = ssh_audit.ReadBuf
		self.wbuf = ssh_audit.WriteBuf
	
	def _b(self, v):
		v = re.sub(r'\s', '', v)
		data = [int(v[i * 2:i * 2 + 2], 16) for i in range(len(v) // 2)]
		return bytes(bytearray(data))
	
	def test_mpint2_write(self):
		wbuf, _b = self.wbuf(), self._b
		mpint = lambda x: wbuf.write_mpint2(x).write_flush()
		assert mpint(0x0)               == _b('00 00 00 00')
		assert mpint(0x80)              == _b('00 00 00 02 00 80')
		assert mpint(0x9a378f9b2e332a7) == _b('00 00 00 08 09 a3 78 f9 b2 e3 32 a7')
		assert mpint(-0x1234)           == _b('00 00 00 02 ed cc')
		assert mpint(-0xdeadbeef)       == _b('00 00 00 05 ff 21 52 41 11')
		assert mpint(-0x80)             == _b('00 00 00 01 80')
	
	def test_mpint2_read(self):
		rbuf, _b = self.rbuf, self._b
		mpint = lambda x: rbuf(x).read_mpint2()
		assert mpint(_b('00 00 00 00'))                         == 0x00
		assert mpint(_b('00 00 00 02 00 80'))                   == 0x80
		assert mpint(_b('00 00 00 08 09 a3 78 f9 b2 e3 32 a7')) == 0x9a378f9b2e332a7
		assert mpint(_b('00 00 00 02 ed cc'))                   == -0x1234
		assert mpint(_b('00 00 00 05 ff 21 52 41 11'))          == -0xdeadbeef
		assert mpint(_b('00 00 00 01 80'))                      == -0x80
		assert mpint(_b('00 00 00 02 ff 80'))                   == -0x80
