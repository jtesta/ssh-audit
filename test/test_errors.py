#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest, socket


class TestErrors(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.AuditConf = ssh_audit.AuditConf
		self.audit = ssh_audit.audit
	
	def _conf(self):
		conf = self.AuditConf('localhost', 22)
		conf.batch = True
		return conf
	
	def test_connection_refused(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.errors['connect'] = socket.error(61, 'Connection refused')
		output_spy.begin()
		with pytest.raises(SystemExit):
			self.audit(self._conf())
		lines = output_spy.flush()
		assert len(lines) == 1
		assert 'Connection refused' in lines[-1]
	
	def test_connection_closed_before_banner(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.rdata.append(socket.error(54, 'Connection reset by peer'))
		output_spy.begin()
		with pytest.raises(SystemExit):
			self.audit(self._conf())
		lines = output_spy.flush()
		assert len(lines) == 1
		assert 'did not receive banner' in lines[-1]
	
	def test_connection_closed_after_header(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.rdata.append(b'header line 1\n')
		vsocket.rdata.append(b'header line 2\n')
		vsocket.rdata.append(socket.error(54, 'Connection reset by peer'))
		output_spy.begin()
		with pytest.raises(SystemExit):
			self.audit(self._conf())
		lines = output_spy.flush()
		assert len(lines) == 3
		assert 'did not receive banner' in lines[-1]
	
	def test_connection_closed_after_banner(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
		vsocket.rdata.append(socket.error(54, 'Connection reset by peer'))
		output_spy.begin()
		with pytest.raises(SystemExit):
			self.audit(self._conf())
		lines = output_spy.flush()
		assert len(lines) == 2
		assert 'error reading packet' in lines[-1]
		assert 'reset by peer' in lines[-1]
	
	def test_empty_data_after_banner(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
		output_spy.begin()
		with pytest.raises(SystemExit):
			self.audit(self._conf())
		lines = output_spy.flush()
		assert len(lines) == 2
		assert 'error reading packet' in lines[-1]
		assert 'empty' in lines[-1]
	
	def test_wrong_data_after_banner(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
		vsocket.rdata.append(b'xxx\n')
		output_spy.begin()
		with pytest.raises(SystemExit):
			self.audit(self._conf())
		lines = output_spy.flush()
		assert len(lines) == 2
		assert 'error reading packet' in lines[-1]
		assert 'xxx' in lines[-1]
	
	def test_nonutf8_data_after_banner(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
		vsocket.rdata.append(b'\x81\xff\n')
		output_spy.begin()
		with pytest.raises(SystemExit):
			self.audit(self._conf())
		lines = output_spy.flush()
		assert len(lines) == 2
		assert 'error reading packet' in lines[-1]
		assert '\\x81\\xff' in lines[-1]
	
	def test_protocol_mismatch_by_conf(self, output_spy, virtual_socket):
		vsocket = virtual_socket
		vsocket.rdata.append(b'SSH-1.3-ssh-audit-test\r\n')
		vsocket.rdata.append(b'Protocol major versions differ.\n')
		output_spy.begin()
		with pytest.raises(SystemExit):
			conf = self._conf()
			conf.ssh1, conf.ssh2 = True, False
			self.audit(conf)
		lines = output_spy.flush()
		assert len(lines) == 3
		assert 'error reading packet' in lines[-1]
		assert 'major versions differ' in lines[-1]
