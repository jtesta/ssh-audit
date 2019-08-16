#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import pytest


# pylint: disable=attribute-defined-outside-init
class TestUtils(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.utils = ssh_audit.Utils
		self.PY3 = sys.version_info >= (3,)
	
	def test_to_bytes_py2(self):
		if self.PY3:
			return
		# binary_type (native str, bytes as str)
		assert self.utils.to_bytes('fran\xc3\xa7ais') == 'fran\xc3\xa7ais'
		assert self.utils.to_bytes(b'fran\xc3\xa7ais') == 'fran\xc3\xa7ais'
		# text_type (unicode)
		assert self.utils.to_bytes(u'fran\xe7ais') == 'fran\xc3\xa7ais'
		# other
		with pytest.raises(TypeError):
			self.utils.to_bytes(123)
	
	def test_to_bytes_py3(self):
		if not self.PY3:
			return
		# binary_type (bytes)
		assert self.utils.to_bytes(b'fran\xc3\xa7ais') == b'fran\xc3\xa7ais'
		# text_type (native str as unicode, unicode)
		assert self.utils.to_bytes('fran\xe7ais') == b'fran\xc3\xa7ais'
		assert self.utils.to_bytes(u'fran\xe7ais') == b'fran\xc3\xa7ais'
		# other
		with pytest.raises(TypeError):
			self.utils.to_bytes(123)
	
	def test_to_utext_py2(self):
		if self.PY3:
			return
		# binary_type (native str, bytes as str)
		assert self.utils.to_utext('fran\xc3\xa7ais') == u'fran\xe7ais'
		assert self.utils.to_utext(b'fran\xc3\xa7ais') == u'fran\xe7ais'
		# text_type (unicode)
		assert self.utils.to_utext(u'fran\xe7ais') == u'fran\xe7ais'
		# other
		with pytest.raises(TypeError):
			self.utils.to_utext(123)
	
	def test_to_utext_py3(self):
		if not self.PY3:
			return
		# binary_type (bytes)
		assert self.utils.to_utext(b'fran\xc3\xa7ais') == u'fran\xe7ais'
		# text_type (native str as unicode, unicode)
		assert self.utils.to_utext('fran\xe7ais') == 'fran\xe7ais'
		assert self.utils.to_utext(u'fran\xe7ais') == u'fran\xe7ais'
		# other
		with pytest.raises(TypeError):
			self.utils.to_utext(123)
	
	def test_to_ntext_py2(self):
		if self.PY3:
			return
		# str (native str, bytes as str)
		assert self.utils.to_ntext('fran\xc3\xa7ais') == 'fran\xc3\xa7ais'
		assert self.utils.to_ntext(b'fran\xc3\xa7ais') == 'fran\xc3\xa7ais'
		# text_type (unicode)
		assert self.utils.to_ntext(u'fran\xe7ais') == 'fran\xc3\xa7ais'
		# other
		with pytest.raises(TypeError):
			self.utils.to_ntext(123)
	
	def test_to_ntext_py3(self):
		if not self.PY3:
			return
		# str (native str)
		assert self.utils.to_ntext('fran\xc3\xa7ais') == 'fran\xc3\xa7ais'
		assert self.utils.to_ntext(u'fran\xe7ais') == 'fran\xe7ais'
		# binary_type (bytes)
		assert self.utils.to_ntext(b'fran\xc3\xa7ais') == 'fran\xe7ais'
		# other
		with pytest.raises(TypeError):
			self.utils.to_ntext(123)
	
	def test_is_ascii_py2(self):
		if self.PY3:
			return
		# text_type (unicode)
		assert self.utils.is_ascii(u'francais') is True
		assert self.utils.is_ascii(u'fran\xe7ais') is False
		# str
		assert self.utils.is_ascii('francais') is True
		assert self.utils.is_ascii('fran\xc3\xa7ais') is False
		# other
		assert self.utils.is_ascii(123) is False
	
	def test_is_ascii_py3(self):
		if not self.PY3:
			return
		# text_type (str)
		assert self.utils.is_ascii('francais') is True
		assert self.utils.is_ascii(u'francais') is True
		assert self.utils.is_ascii('fran\xe7ais') is False
		assert self.utils.is_ascii(u'fran\xe7ais') is False
		# other
		assert self.utils.is_ascii(123) is False
	
	def test_to_ascii_py2(self):
		if self.PY3:
			return
		# text_type (unicode)
		assert self.utils.to_ascii(u'francais') == 'francais'
		assert self.utils.to_ascii(u'fran\xe7ais') == 'fran?ais'
		assert self.utils.to_ascii(u'fran\xe7ais', 'ignore') == 'franais'
		# str
		assert self.utils.to_ascii('francais') == 'francais'
		assert self.utils.to_ascii('fran\xc3\xa7ais') == 'fran??ais'
		assert self.utils.to_ascii('fran\xc3\xa7ais', 'ignore') == 'franais'
		with pytest.raises(TypeError):
			self.utils.to_ascii(123)
	
	def test_to_ascii_py3(self):
		if not self.PY3:
			return
		# text_type (str)
		assert self.utils.to_ascii('francais') == 'francais'
		assert self.utils.to_ascii(u'francais') == 'francais'
		assert self.utils.to_ascii('fran\xe7ais') == 'fran?ais'
		assert self.utils.to_ascii('fran\xe7ais', 'ignore') == 'franais'
		assert self.utils.to_ascii(u'fran\xe7ais') == 'fran?ais'
		assert self.utils.to_ascii(u'fran\xe7ais', 'ignore') == 'franais'
		with pytest.raises(TypeError):
			self.utils.to_ascii(123)
	
	def test_is_print_ascii_py2(self):
		if self.PY3:
			return
		# text_type (unicode)
		assert self.utils.is_print_ascii(u'francais') is True
		assert self.utils.is_print_ascii(u'francais\n') is False
		assert self.utils.is_print_ascii(u'fran\xe7ais') is False
		assert self.utils.is_print_ascii(u'fran\xe7ais\n') is False
		# str
		assert self.utils.is_print_ascii('francais') is True
		assert self.utils.is_print_ascii('francais\n') is False
		assert self.utils.is_print_ascii('fran\xc3\xa7ais') is False
		# other
		assert self.utils.is_print_ascii(123) is False
	
	def test_is_print_ascii_py3(self):
		if not self.PY3:
			return
		# text_type (str)
		assert self.utils.is_print_ascii('francais') is True
		assert self.utils.is_print_ascii('francais\n') is False
		assert self.utils.is_print_ascii(u'francais') is True
		assert self.utils.is_print_ascii(u'francais\n') is False
		assert self.utils.is_print_ascii('fran\xe7ais') is False
		assert self.utils.is_print_ascii(u'fran\xe7ais') is False
		# other
		assert self.utils.is_print_ascii(123) is False
	
	def test_to_print_ascii_py2(self):
		if self.PY3:
			return
		# text_type (unicode)
		assert self.utils.to_print_ascii(u'francais') == 'francais'
		assert self.utils.to_print_ascii(u'francais\n') == 'francais?'
		assert self.utils.to_print_ascii(u'fran\xe7ais') == 'fran?ais'
		assert self.utils.to_print_ascii(u'fran\xe7ais\n') == 'fran?ais?'
		assert self.utils.to_print_ascii(u'fran\xe7ais', 'ignore') == 'franais'
		assert self.utils.to_print_ascii(u'fran\xe7ais\n', 'ignore') == 'franais'
		# str
		assert self.utils.to_print_ascii('francais') == 'francais'
		assert self.utils.to_print_ascii('francais\n') == 'francais?'
		assert self.utils.to_print_ascii('fran\xc3\xa7ais') == 'fran??ais'
		assert self.utils.to_print_ascii('fran\xc3\xa7ais\n') == 'fran??ais?'
		assert self.utils.to_print_ascii('fran\xc3\xa7ais', 'ignore') == 'franais'
		assert self.utils.to_print_ascii('fran\xc3\xa7ais\n', 'ignore') == 'franais'
		with pytest.raises(TypeError):
			self.utils.to_print_ascii(123)
	
	def test_to_print_ascii_py3(self):
		if not self.PY3:
			return
		# text_type (str)
		assert self.utils.to_print_ascii('francais') == 'francais'
		assert self.utils.to_print_ascii('francais\n') == 'francais?'
		assert self.utils.to_print_ascii(u'francais') == 'francais'
		assert self.utils.to_print_ascii(u'francais\n') == 'francais?'
		assert self.utils.to_print_ascii('fran\xe7ais') == 'fran?ais'
		assert self.utils.to_print_ascii('fran\xe7ais\n') == 'fran?ais?'
		assert self.utils.to_print_ascii('fran\xe7ais', 'ignore') == 'franais'
		assert self.utils.to_print_ascii('fran\xe7ais\n', 'ignore') == 'franais'
		assert self.utils.to_print_ascii(u'fran\xe7ais') == 'fran?ais'
		assert self.utils.to_print_ascii(u'fran\xe7ais\n') == 'fran?ais?'
		assert self.utils.to_print_ascii(u'fran\xe7ais', 'ignore') == 'franais'
		assert self.utils.to_print_ascii(u'fran\xe7ais\n', 'ignore') == 'franais'
		with pytest.raises(TypeError):
			self.utils.to_print_ascii(123)
	
	def test_ctoi(self):
		assert self.utils.ctoi(123) == 123
		assert self.utils.ctoi('ABC') == 65
	
	def test_parse_int(self):
		assert self.utils.parse_int(123) == 123
		assert self.utils.parse_int('123') == 123
		assert self.utils.parse_int(-123) == -123
		assert self.utils.parse_int('-123') == -123
		assert self.utils.parse_int('abc') == 0
	
	def test_unique_seq(self):
		assert self.utils.unique_seq((1, 2, 2, 3, 3, 3)) == (1, 2, 3)
		assert self.utils.unique_seq((3, 3, 3, 2, 2, 1)) == (3, 2, 1)
		assert self.utils.unique_seq([1, 2, 2, 3, 3, 3]) == [1, 2, 3]
		assert self.utils.unique_seq([3, 3, 3, 2, 2, 1]) == [3, 2, 1]
