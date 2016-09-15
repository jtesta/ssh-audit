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
	
	def test_mpint1(self):
		mpint1w = lambda x: self.wbuf().write_mpint1(x).write_flush()
		mpint1r = lambda x: self.rbuf(x).read_mpint1()
		tc = [(0x0,     '00 00'),
		      (0x1234,  '00 0d 12 34'),
		      (0x12345, '00 11 01 23 45')]
		for p in tc:
			assert mpint1w(p[0]) == self._b(p[1])
			assert mpint1r(self._b(p[1])) == p[0]
	
	def test_mpint2(self):
		mpint2w = lambda x: self.wbuf().write_mpint2(x).write_flush()
		mpint2r = lambda x: self.rbuf(x).read_mpint2()
		tc = [(0x0,               '00 00 00 00'),
		      (0x80,              '00 00 00 02 00 80'),
		      (0x9a378f9b2e332a7, '00 00 00 08 09 a3 78 f9 b2 e3 32 a7'),
		      (-0x1234,           '00 00 00 02 ed cc'),
		      (-0xdeadbeef,       '00 00 00 05 ff 21 52 41 11'),
		      (-0x8000,           '00 00 00 02 80 00'),
		      (-0x80,             '00 00 00 01 80')]
		for p in tc:
			assert mpint2w(p[0]) == self._b(p[1])
			assert mpint2r(self._b(p[1])) == p[0]
		assert mpint2r(self._b('00 00 00 02 ff 80')) == -0x80
