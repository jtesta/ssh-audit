#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest


class TestAuditConf(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.AuditConf = ssh_audit.AuditConf
	
	def test_audit_conf_defaults(self):
		conf = self.AuditConf()
		assert conf.host is None
		assert conf.port == 22
		assert conf.ssh1 is True
		assert conf.ssh2 is True
		assert conf.batch is False
		assert conf.colors is True
		assert conf.verbose is False
		assert conf.minlevel == 'info'
	
	def test_audit_conf_booleans(self):
		conf = self.AuditConf()
		for p in ['ssh1', 'ssh2', 'batch', 'colors', 'verbose']:
			for v in [True, 1]:
				setattr(conf, p, v)
				assert getattr(conf, p) is True
			for v in [False, 0]:
				setattr(conf, p, v)
				assert getattr(conf, p) is False
	
	def test_audit_conf_port(self):
		conf = self.AuditConf()
		for port in [22, 2222]:
			conf.port = port
			assert conf.port == port
		for port in [-1, 0, 65536, 99999]:
			with pytest.raises(ValueError) as excinfo:
				conf.port = port
			excinfo.match(r'.*invalid port.*')
	
	def test_audit_conf_minlevel(self):
		conf = self.AuditConf()
		for level in ['info', 'warn', 'fail']:
			conf.minlevel = level
			assert conf.minlevel == level
		for level in ['head', 'good', 'unknown', None]:
			with pytest.raises(ValueError) as excinfo:
				conf.minlevel = level
			excinfo.match(r'.*invalid level.*')
