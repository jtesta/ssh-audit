#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os, sys
import pytest

@pytest.fixture(scope='module')
def ssh_audit():
	__rdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
	sys.path.append(os.path.abspath(__rdir))
	return __import__('ssh-audit')
