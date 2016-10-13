#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest, os, sys, io


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
