#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import pytest, io, sys


if sys.version_info[0] == 2:
	import StringIO
	StringIO = StringIO.StringIO
else:
	StringIO = io.StringIO


class TestOutput(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.Output = ssh_audit.Output
		self.OutputBuffer = ssh_audit.OutputBuffer
	
	def _begin(self):
		self.__out = StringIO()
		self.__old_stdout = sys.stdout
		sys.stdout = self.__out
		
	def _flush(self):
		lines = self.__out.getvalue().splitlines()
		sys.stdout = self.__old_stdout
		self.__out = None
		return lines
	
	def test_output_buffer_no_lines(self):
		self._begin()
		with self.OutputBuffer() as obuf:
			pass
		assert self._flush() == []
		self._begin()
		with self.OutputBuffer() as obuf:
			pass
		obuf.flush()
		assert self._flush() == []
	
	def test_output_buffer_no_flush(self):
		self._begin()
		with self.OutputBuffer() as obuf:
			print(u'abc')
		assert self._flush() == []
	
	def test_output_buffer_flush(self):
		self._begin()
		with self.OutputBuffer() as obuf:
			print(u'abc')
			print()
			print(u'def')
		obuf.flush()
		assert self._flush() == [u'abc', u'', u'def']
	
	def test_output_defaults(self):
		out = self.Output()
		# default: on
		assert out.batch == False
		assert out.colors == True
		assert out.minlevel == 'info'
	
	def test_output_colors(self):
		out = self.Output()
		# test without colors
		out.colors = False
		self._begin()
		out.info('info color')
		assert self._flush() == [u'info color']
		self._begin()
		out.head('head color')
		assert self._flush() == [u'head color']
		self._begin()
		out.good('good color')
		assert self._flush() == [u'good color']
		self._begin()
		out.warn('warn color')
		assert self._flush() == [u'warn color']
		self._begin()
		out.fail('fail color')
		assert self._flush() == [u'fail color']
		# test with colors
		out.colors = True
		self._begin()
		out.info('info color')
		assert self._flush() == [u'info color']
		self._begin()
		out.head('head color')
		assert self._flush() == [u'\x1b[0;36mhead color\x1b[0m']
		self._begin()
		out.good('good color')
		assert self._flush() == [u'\x1b[0;32mgood color\x1b[0m']
		self._begin()
		out.warn('warn color')
		assert self._flush() == [u'\x1b[0;33mwarn color\x1b[0m']
		self._begin()
		out.fail('fail color')
		assert self._flush() == [u'\x1b[0;31mfail color\x1b[0m']
	
	def test_output_sep(self):
		out = self.Output()
		self._begin()
		out.sep()
		out.sep()
		out.sep()
		assert self._flush() == [u'', u'', u'']
	
	def test_output_levels(self):
		out = self.Output()
		assert out.getlevel('info') == 0
		assert out.getlevel('good') == 0
		assert out.getlevel('warn') == 1
		assert out.getlevel('fail') == 2
		assert out.getlevel('unknown') > 2
	
	def test_output_minlevel_property(self):
		out = self.Output()
		out.minlevel = 'info'
		assert out.minlevel == 'info'
		out.minlevel = 'good'
		assert out.minlevel == 'info'
		out.minlevel = 'warn'
		assert out.minlevel == 'warn'
		out.minlevel = 'fail'
		assert out.minlevel == 'fail'
		out.minlevel = 'invalid level'
		assert out.minlevel == 'unknown'
	
	def test_output_minlevel(self):
		out = self.Output()
		# visible: all
		out.minlevel = 'info'
		self._begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(self._flush()) == 5
		# visible: head, warn, fail
		out.minlevel = 'warn'
		self._begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(self._flush()) == 3
		# visible: head, fail
		out.minlevel = 'fail'
		self._begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(self._flush()) == 2
		# visible: head
		out.minlevel = 'invalid level'
		self._begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(self._flush()) == 1
	
	def test_output_batch(self):
		out = self.Output()
		# visible: all
		self._begin()
		out.minlevel = 'info'
		out.batch = False
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(self._flush()) == 5
		# visible: all except head
		self._begin()
		out.minlevel = 'info'
		out.batch = True
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(self._flush()) == 4
