#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest


class TestAuditConf(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.AuditConf = ssh_audit.AuditConf
		self.usage = ssh_audit.usage
	
	def _test_conf(self, conf, **kwargs):
		options = {
			'host': None,
			'port': 22,
			'ssh1': True,
			'ssh2': True,
			'batch': False,
			'colors': True,
			'verbose': False,
			'minlevel': 'info'
		}
		for k, v in kwargs.items():
			options[k] = v
		assert conf.host == options['host']
		assert conf.port == options['port']
		assert conf.ssh1 is options['ssh1']
		assert conf.ssh2 is options['ssh2']
		assert conf.batch is options['batch']
		assert conf.colors is options['colors']
		assert conf.verbose is options['verbose']
		assert conf.minlevel == options['minlevel']
	
	def test_audit_conf_defaults(self):
		conf = self.AuditConf()
		self._test_conf(conf)
	
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
	
	def test_audit_conf_cmdline(self):
		c = lambda x: self.AuditConf.from_cmdline(x.split(), self.usage)
		with pytest.raises(SystemExit):
			conf = c('')
		with pytest.raises(SystemExit):
			conf = c('-x')
		with pytest.raises(SystemExit):
			conf = c('-h')
		with pytest.raises(SystemExit):
			conf = c('--help')
		with pytest.raises(SystemExit):
			conf = c(':')
		with pytest.raises(SystemExit):
			conf = c(':22')
		conf = c('localhost')
		self._test_conf(conf, host='localhost')
		conf = c('github.com')
		self._test_conf(conf, host='github.com')
		conf = c('localhost:2222')
		self._test_conf(conf, host='localhost', port=2222)
		with pytest.raises(SystemExit):
			conf = c('localhost:')
		with pytest.raises(SystemExit):
			conf = c('localhost:abc')
		with pytest.raises(SystemExit):
			conf = c('localhost:-22')
		with pytest.raises(SystemExit):
			conf = c('localhost:99999')
		conf = c('-1 localhost')
		self._test_conf(conf, host='localhost', ssh1=True, ssh2=False)
		conf = c('-2 localhost')
		self._test_conf(conf, host='localhost', ssh1=False, ssh2=True)
		conf = c('-12 localhost')
		self._test_conf(conf, host='localhost', ssh1=True, ssh2=True)
		conf = c('-b localhost')
		self._test_conf(conf, host='localhost', batch=True, verbose=True)
		conf = c('-n localhost')
		self._test_conf(conf, host='localhost', colors=False)
		conf = c('-v localhost')
		self._test_conf(conf, host='localhost', verbose=True)
		conf = c('-l info localhost')
		self._test_conf(conf, host='localhost', minlevel='info')
		conf = c('-l warn localhost')
		self._test_conf(conf, host='localhost', minlevel='warn')
		conf = c('-l fail localhost')
		self._test_conf(conf, host='localhost', minlevel='fail')
		with pytest.raises(SystemExit):
			conf = c('-l something localhost')
