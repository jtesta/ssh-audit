#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest


# pylint: disable=attribute-defined-outside-init
class TestSSHAlgorithm(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.ssh = ssh_audit.SSH
	
	def _tf(self, v, s=None):
		return self.ssh.Algorithm.Timeframe().update(v, s)
	
	def test_get_ssh_version(self):
		def ver(v):
			return self.ssh.Algorithm.get_ssh_version(v)
		
		assert ver('7.5') == ('OpenSSH', '7.5', False)
		assert ver('7.5C') == ('OpenSSH', '7.5', True)
		assert ver('d2016.74') == ('Dropbear SSH', '2016.74', False)
		assert ver('l10.7.4') == ('libssh', '0.7.4', False)
		assert ver('')[1] == ''
	
	def test_get_since_text(self):
		def gst(v):
			return self.ssh.Algorithm.get_since_text(v)
		
		assert gst(['7.5']) == 'available since OpenSSH 7.5'
		assert gst(['7.5C']) == 'available since OpenSSH 7.5 (client only)'
		assert gst(['7.5,']) == 'available since OpenSSH 7.5'
		assert gst(['d2016.73']) == 'available since Dropbear SSH 2016.73'
		assert gst(['7.5,d2016.73']) == 'available since OpenSSH 7.5, Dropbear SSH 2016.73'
		assert gst(['l10.7.4']) is None
		assert gst([]) is None
	
	def test_timeframe_creation(self):
		# pylint: disable=line-too-long,too-many-statements
		def cmp_tf(v, s, r):
			assert str(self._tf(v, s)) == str(r)
		
		cmp_tf(['6.2'], None, {'OpenSSH': ['6.2', None, '6.2', None]})
		cmp_tf(['6.2'], True, {'OpenSSH': ['6.2', None, None, None]})
		cmp_tf(['6.2'], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.2C'], None, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.2C'], True, {})
		cmp_tf(['6.2C'], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.1,6.2C'], None, {'OpenSSH': ['6.1', None, '6.2', None]})
		cmp_tf(['6.1,6.2C'], True, {'OpenSSH': ['6.1', None, None, None]})
		cmp_tf(['6.1,6.2C'], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.2C,6.1'], None, {'OpenSSH': ['6.1', None, '6.2', None]})
		cmp_tf(['6.2C,6.1'], True, {'OpenSSH': ['6.1', None, None, None]})
		cmp_tf(['6.2C,6.1'], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.3,6.2C'], None, {'OpenSSH': ['6.3', None, '6.2', None]})
		cmp_tf(['6.3,6.2C'], True, {'OpenSSH': ['6.3', None, None, None]})
		cmp_tf(['6.3,6.2C'], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.2C,6.3'], None, {'OpenSSH': ['6.3', None, '6.2', None]})
		cmp_tf(['6.2C,6.3'], True, {'OpenSSH': ['6.3', None, None, None]})
		cmp_tf(['6.2C,6.3'], False, {'OpenSSH': [None, None, '6.2', None]})
		
		cmp_tf(['6.2', '6.6'], None, {'OpenSSH': ['6.2', '6.6', '6.2', '6.6']})
		cmp_tf(['6.2', '6.6'], True, {'OpenSSH': ['6.2', '6.6', None, None]})
		cmp_tf(['6.2', '6.6'], False, {'OpenSSH': [None, None, '6.2', '6.6']})
		cmp_tf(['6.2C', '6.6'], None, {'OpenSSH': [None, '6.6', '6.2', '6.6']})
		cmp_tf(['6.2C', '6.6'], True, {'OpenSSH': [None, '6.6', None, None]})
		cmp_tf(['6.2C', '6.6'], False, {'OpenSSH': [None, None, '6.2', '6.6']})
		cmp_tf(['6.1,6.2C', '6.6'], None, {'OpenSSH': ['6.1', '6.6', '6.2', '6.6']})
		cmp_tf(['6.1,6.2C', '6.6'], True, {'OpenSSH': ['6.1', '6.6', None, None]})
		cmp_tf(['6.1,6.2C', '6.6'], False, {'OpenSSH': [None, None, '6.2', '6.6']})
		cmp_tf(['6.2C,6.1', '6.6'], None, {'OpenSSH': ['6.1', '6.6', '6.2', '6.6']})
		cmp_tf(['6.2C,6.1', '6.6'], True, {'OpenSSH': ['6.1', '6.6', None, None]})
		cmp_tf(['6.2C,6.1', '6.6'], False, {'OpenSSH': [None, None, '6.2', '6.6']})
		cmp_tf(['6.3,6.2C', '6.6'], None, {'OpenSSH': ['6.3', '6.6', '6.2', '6.6']})
		cmp_tf(['6.3,6.2C', '6.6'], True, {'OpenSSH': ['6.3', '6.6', None, None]})
		cmp_tf(['6.3,6.2C', '6.6'], False, {'OpenSSH': [None, None, '6.2', '6.6']})
		cmp_tf(['6.2C,6.3', '6.6'], None, {'OpenSSH': ['6.3', '6.6', '6.2', '6.6']})
		cmp_tf(['6.2C,6.3', '6.6'], True, {'OpenSSH': ['6.3', '6.6', None, None]})
		cmp_tf(['6.2C,6.3', '6.6'], False, {'OpenSSH': [None, None, '6.2', '6.6']})
		
		cmp_tf(['6.2', '6.6', None], None, {'OpenSSH': ['6.2', '6.6', '6.2', None]})
		cmp_tf(['6.2', '6.6', None], True, {'OpenSSH': ['6.2', '6.6', None, None]})
		cmp_tf(['6.2', '6.6', None], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.2C', '6.6', None], None, {'OpenSSH': [None, '6.6', '6.2', None]})
		cmp_tf(['6.2C', '6.6', None], True, {'OpenSSH': [None, '6.6', None, None]})
		cmp_tf(['6.2C', '6.6', None], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.1,6.2C', '6.6', None], None, {'OpenSSH': ['6.1', '6.6', '6.2', None]})
		cmp_tf(['6.1,6.2C', '6.6', None], True, {'OpenSSH': ['6.1', '6.6', None, None]})
		cmp_tf(['6.1,6.2C', '6.6', None], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.2C,6.1', '6.6', None], None, {'OpenSSH': ['6.1', '6.6', '6.2', None]})
		cmp_tf(['6.2C,6.1', '6.6', None], True, {'OpenSSH': ['6.1', '6.6', None, None]})
		cmp_tf(['6.2C,6.1', '6.6', None], False, {'OpenSSH': [None, None, '6.2', None]})
		cmp_tf(['6.2,6.3C', '6.6', None], None, {'OpenSSH': ['6.2', '6.6', '6.3', None]})
		cmp_tf(['6.2,6.3C', '6.6', None], True, {'OpenSSH': ['6.2', '6.6', None, None]})
		cmp_tf(['6.2,6.3C', '6.6', None], False, {'OpenSSH': [None, None, '6.3', None]})
		cmp_tf(['6.3C,6.2', '6.6', None], None, {'OpenSSH': ['6.2', '6.6', '6.3', None]})
		cmp_tf(['6.3C,6.2', '6.6', None], True, {'OpenSSH': ['6.2', '6.6', None, None]})
		cmp_tf(['6.3C,6.2', '6.6', None], False, {'OpenSSH': [None, None, '6.3', None]})
		
		cmp_tf(['6.2', '6.6', '7.1'], None, {'OpenSSH': ['6.2', '6.6', '6.2', '7.1']})
		cmp_tf(['6.2', '6.6', '7.1'], True, {'OpenSSH': ['6.2', '6.6', None, None]})
		cmp_tf(['6.2', '6.6', '7.1'], False, {'OpenSSH': [None, None, '6.2', '7.1']})
		cmp_tf(['6.1,6.2C', '6.6', '7.1'], None, {'OpenSSH': ['6.1', '6.6', '6.2', '7.1']})
		cmp_tf(['6.1,6.2C', '6.6', '7.1'], True, {'OpenSSH': ['6.1', '6.6', None, None]})
		cmp_tf(['6.1,6.2C', '6.6', '7.1'], False, {'OpenSSH': [None, None, '6.2', '7.1']})
		cmp_tf(['6.2C,6.1', '6.6', '7.1'], None, {'OpenSSH': ['6.1', '6.6', '6.2', '7.1']})
		cmp_tf(['6.2C,6.1', '6.6', '7.1'], True, {'OpenSSH': ['6.1', '6.6', None, None]})
		cmp_tf(['6.2C,6.1', '6.6', '7.1'], False, {'OpenSSH': [None, None, '6.2', '7.1']})
		cmp_tf(['6.2,6.3C', '6.6', '7.1'], None, {'OpenSSH': ['6.2', '6.6', '6.3', '7.1']})
		cmp_tf(['6.2,6.3C', '6.6', '7.1'], True, {'OpenSSH': ['6.2', '6.6', None, None]})
		cmp_tf(['6.2,6.3C', '6.6', '7.1'], False, {'OpenSSH': [None, None, '6.3', '7.1']})
		cmp_tf(['6.3C,6.2', '6.6', '7.1'], None, {'OpenSSH': ['6.2', '6.6', '6.3', '7.1']})
		cmp_tf(['6.3C,6.2', '6.6', '7.1'], True, {'OpenSSH': ['6.2', '6.6', None, None]})
		cmp_tf(['6.3C,6.2', '6.6', '7.1'], False, {'OpenSSH': [None, None, '6.3', '7.1']})
		
		tf1 = self._tf(['6.1,d2016.72,6.2C', '6.6,d2016.73', '7.1,d2016.74'])
		tf2 = self._tf(['d2016.72,6.2C,6.1', 'd2016.73,6.6', 'd2016.74,7.1'])
		tf3 = self._tf(['d2016.72,6.2C,6.1', '6.6,d2016.73', '7.1,d2016.74'])
		# check without caring for output order
		ov = "'OpenSSH': ['6.1', '6.6', '6.2', '7.1']"
		dv = "'Dropbear SSH': ['2016.72', '2016.73', '2016.72', '2016.74']"
		assert len(str(tf1)) == len(str(tf2)) == len(str(tf3))
		assert ov in str(tf1) and ov in str(tf2) and ov in str(tf3)
		assert dv in str(tf1) and dv in str(tf2) and dv in str(tf3)
		assert ov in repr(tf1) and ov in repr(tf2) and ov in repr(tf3)
		assert dv in repr(tf1) and dv in repr(tf2) and dv in repr(tf3)
	
	def test_timeframe_object(self):
		tf = self._tf(['6.1,6.2C', '6.6', '7.1'])
		assert 'OpenSSH' in tf
		assert 'Dropbear SSH' not in tf
		assert 'libssh' not in tf
		assert 'unknown' not in tf
		assert tf['OpenSSH'] == ('6.1', '6.6', '6.2', '7.1')
		assert tf['Dropbear SSH'] == (None, None, None, None)
		assert tf['libssh'] == (None, None, None, None)
		assert tf['unknown'] == (None, None, None, None)
		assert tf.get_from('OpenSSH', True) == '6.1'
		assert tf.get_till('OpenSSH', True) == '6.6'
		assert tf.get_from('OpenSSH', False) == '6.2'
		assert tf.get_till('OpenSSH', False) == '7.1'
		
		tf = self._tf(['6.1,d2016.72,6.2C', '6.6,d2016.73', '7.1,d2016.74'])
		assert 'OpenSSH' in tf
		assert 'Dropbear SSH' in tf
		assert 'libssh' not in tf
		assert 'unknown' not in tf
		assert tf['OpenSSH'] == ('6.1', '6.6', '6.2', '7.1')
		assert tf['Dropbear SSH'] == ('2016.72', '2016.73', '2016.72', '2016.74')
		assert tf['libssh'] == (None, None, None, None)
		assert tf['unknown'] == (None, None, None, None)
		assert tf.get_from('OpenSSH', True) == '6.1'
		assert tf.get_till('OpenSSH', True) == '6.6'
		assert tf.get_from('OpenSSH', False) == '6.2'
		assert tf.get_till('OpenSSH', False) == '7.1'
		assert tf.get_from('Dropbear SSH', True) == '2016.72'
		assert tf.get_till('Dropbear SSH', True) == '2016.73'
		assert tf.get_from('Dropbear SSH', False) == '2016.72'
		assert tf.get_till('Dropbear SSH', False) == '2016.74'
		ov = "'OpenSSH': ['6.1', '6.6', '6.2', '7.1']"
		dv = "'Dropbear SSH': ['2016.72', '2016.73', '2016.72', '2016.74']"
		assert ov in str(tf)
		assert dv in str(tf)
		assert ov in repr(tf)
		assert dv in repr(tf)
