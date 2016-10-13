#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import pytest, io, sys


class TestOutput(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.Output = ssh_audit.Output
		self.OutputBuffer = ssh_audit.OutputBuffer
	
	def test_output_buffer_no_lines(self, output_spy):
		output_spy.begin()
		with self.OutputBuffer() as obuf:
			pass
		assert output_spy.flush() == []
		output_spy.begin()
		with self.OutputBuffer() as obuf:
			pass
		obuf.flush()
		assert output_spy.flush() == []
	
	def test_output_buffer_no_flush(self, output_spy):
		output_spy.begin()
		with self.OutputBuffer() as obuf:
			print(u'abc')
		assert output_spy.flush() == []
	
	def test_output_buffer_flush(self, output_spy):
		output_spy.begin()
		with self.OutputBuffer() as obuf:
			print(u'abc')
			print()
			print(u'def')
		obuf.flush()
		assert output_spy.flush() == [u'abc', u'', u'def']
	
	def test_output_defaults(self):
		out = self.Output()
		# default: on
		assert out.batch is False
		assert out.colors is True
		assert out.minlevel == 'info'
	
	def test_output_colors(self, output_spy):
		out = self.Output()
		# test without colors
		out.colors = False
		output_spy.begin()
		out.info('info color')
		assert output_spy.flush() == [u'info color']
		output_spy.begin()
		out.head('head color')
		assert output_spy.flush() == [u'head color']
		output_spy.begin()
		out.good('good color')
		assert output_spy.flush() == [u'good color']
		output_spy.begin()
		out.warn('warn color')
		assert output_spy.flush() == [u'warn color']
		output_spy.begin()
		out.fail('fail color')
		assert output_spy.flush() == [u'fail color']
		# test with colors
		out.colors = True
		output_spy.begin()
		out.info('info color')
		assert output_spy.flush() == [u'info color']
		output_spy.begin()
		out.head('head color')
		assert output_spy.flush() == [u'\x1b[0;36mhead color\x1b[0m']
		output_spy.begin()
		out.good('good color')
		assert output_spy.flush() == [u'\x1b[0;32mgood color\x1b[0m']
		output_spy.begin()
		out.warn('warn color')
		assert output_spy.flush() == [u'\x1b[0;33mwarn color\x1b[0m']
		output_spy.begin()
		out.fail('fail color')
		assert output_spy.flush() == [u'\x1b[0;31mfail color\x1b[0m']
	
	def test_output_sep(self, output_spy):
		out = self.Output()
		output_spy.begin()
		out.sep()
		out.sep()
		out.sep()
		assert output_spy.flush() == [u'', u'', u'']
	
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
	
	def test_output_minlevel(self, output_spy):
		out = self.Output()
		# visible: all
		out.minlevel = 'info'
		output_spy.begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(output_spy.flush()) == 5
		# visible: head, warn, fail
		out.minlevel = 'warn'
		output_spy.begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(output_spy.flush()) == 3
		# visible: head, fail
		out.minlevel = 'fail'
		output_spy.begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(output_spy.flush()) == 2
		# visible: head
		out.minlevel = 'invalid level'
		output_spy.begin()
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(output_spy.flush()) == 1
	
	def test_output_batch(self, output_spy):
		out = self.Output()
		# visible: all
		output_spy.begin()
		out.minlevel = 'info'
		out.batch = False
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(output_spy.flush()) == 5
		# visible: all except head
		output_spy.begin()
		out.minlevel = 'info'
		out.batch = True
		out.info('info color')
		out.head('head color')
		out.good('good color')
		out.warn('warn color')
		out.fail('fail color')
		assert len(output_spy.flush()) == 4
