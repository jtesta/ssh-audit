#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest, os, sys, io, socket


if sys.version_info[0] == 2:
	import StringIO
	StringIO = StringIO.StringIO
else:
	StringIO = io.StringIO


@pytest.fixture(scope='module')
def ssh_audit():
	__rdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
	sys.path.append(os.path.abspath(__rdir))
	return __import__('ssh-audit')


class _OutputSpy(list):
	def begin(self):
		self.__out = StringIO()
		self.__old_stdout = sys.stdout
		sys.stdout = self.__out
		
	def flush(self):
		lines = self.__out.getvalue().splitlines()
		sys.stdout = self.__old_stdout
		self.__out = None
		return lines


@pytest.fixture(scope='module')
def output_spy():
	return _OutputSpy()


class _VirtualSocket(object):
	def __init__(self):
		self.sock_address = ('127.0.0.1', 0)
		self.peer_address = None
		self._connected = False
		self.timeout = -1.0
		self.rdata = []
		self.sdata = []
		self.errors = {}
	
	def _check_err(self, method):
		method_error = self.errors.get(method)
		if method_error:
			raise method_error
	
	def _connect(self, address):
		self.peer_address = address
		self._connected = True
		self._check_err('connect')
		return self
	
	def settimeout(self, timeout):
		self.timeout = timeout
	
	def gettimeout(self):
		return self.timeout
	
	def getpeername(self):
		if self.peer_address is None or not self._connected:
			raise socket.error(57, 'Socket is not connected')
		return self.peer_address
	
	def getsockname(self):
		return self.sock_address
	
	def bind(self, address):
		self.sock_address = address
	
	def listen(self, backlog):
		pass
	
	def accept(self):
		conn = _VirtualSocket()
		conn.sock_address = self.sock_address
		conn.peer_address = ('127.0.0.1', 0)
		conn._connected = True
		return conn, conn.peer_address
	
	def recv(self, bufsize, flags=0):
		if not self._connected:
			raise socket.error(54, 'Connection reset by peer')
		if not len(self.rdata) > 0:
			return b''
		data = self.rdata.pop(0)
		if isinstance(data, Exception):
			raise data
		return data
	
	def send(self, data):
		if self.peer_address is None or not self._connected:
			raise socket.error(32, 'Broken pipe')
		self._check_err('send')
		self.sdata.append(data)


@pytest.fixture()
def virtual_socket(monkeypatch):
	vsocket = _VirtualSocket()
	def _c(address):
		return vsocket._connect(address)
	def _cc(address, timeout=0, source_address=None):
		return vsocket._connect(address)
	monkeypatch.setattr(socket, 'create_connection', _cc)
	monkeypatch.setattr(socket.socket, 'connect', _c)
	return vsocket
