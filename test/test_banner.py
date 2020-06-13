#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest


# pylint: disable=line-too-long,attribute-defined-outside-init
class TestBanner(object):
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.ssh = ssh_audit.SSH

    def test_simple_banners(self):
        banner = lambda x: self.ssh.Banner.parse(x)  # noqa
        b = banner('SSH-2.0-OpenSSH_7.3')
        assert b.protocol == (2, 0)
        assert b.software == 'OpenSSH_7.3'
        assert b.comments is None
        assert str(b) == 'SSH-2.0-OpenSSH_7.3'
        b = banner('SSH-1.99-Sun_SSH_1.1.3')
        assert b.protocol == (1, 99)
        assert b.software == 'Sun_SSH_1.1.3'
        assert b.comments is None
        assert str(b) == 'SSH-1.99-Sun_SSH_1.1.3'
        b = banner('SSH-1.5-Cisco-1.25')
        assert b.protocol == (1, 5)
        assert b.software == 'Cisco-1.25'
        assert b.comments is None
        assert str(b) == 'SSH-1.5-Cisco-1.25'

    def test_invalid_banners(self):
        b = lambda x: self.ssh.Banner.parse(x)  # noqa
        assert b('Something') is None
        assert b('SSH-XXX-OpenSSH_7.3') is None

    def test_banners_with_spaces(self):
        b = lambda x: self.ssh.Banner.parse(x)  # noqa
        s = 'SSH-2.0-OpenSSH_4.3p2'
        assert str(b('SSH-2.0-OpenSSH_4.3p2    ')) == s
        assert str(b('SSH-2.0-    OpenSSH_4.3p2')) == s
        assert str(b('SSH-2.0-  OpenSSH_4.3p2  ')) == s
        s = 'SSH-2.0-OpenSSH_4.3p2 Debian-9etch3 on i686-pc-linux-gnu'
        assert str(b('SSH-2.0-  OpenSSH_4.3p2 Debian-9etch3   on i686-pc-linux-gnu')) == s
        assert str(b('SSH-2.0-OpenSSH_4.3p2 Debian-9etch3 on i686-pc-linux-gnu  ')) == s
        assert str(b('SSH-2.0-  OpenSSH_4.3p2 Debian-9etch3   on   i686-pc-linux-gnu  ')) == s

    def test_banners_without_software(self):
        b = lambda x: self.ssh.Banner.parse(x)  # noqa
        assert b('SSH-2.0').protocol == (2, 0)
        assert b('SSH-2.0').software is None
        assert b('SSH-2.0').comments is None
        assert str(b('SSH-2.0')) == 'SSH-2.0'
        assert b('SSH-2.0-').protocol == (2, 0)
        assert b('SSH-2.0-').software == ''
        assert b('SSH-2.0-').comments is None
        assert str(b('SSH-2.0-')) == 'SSH-2.0-'

    def test_banners_with_comments(self):
        b = lambda x: self.ssh.Banner.parse(x)  # noqa
        assert repr(b('SSH-2.0-OpenSSH_7.2p2 Ubuntu-1')) == '<Banner(protocol=2.0, software=OpenSSH_7.2p2, comments=Ubuntu-1)>'
        assert repr(b('SSH-1.99-OpenSSH_3.4p1 Debian 1:3.4p1-1.woody.3')) == '<Banner(protocol=1.99, software=OpenSSH_3.4p1, comments=Debian 1:3.4p1-1.woody.3)>'
        assert repr(b('SSH-1.5-1.3.7 F-SECURE SSH')) == '<Banner(protocol=1.5, software=1.3.7, comments=F-SECURE SSH)>'

    def test_banners_with_multiple_protocols(self):
        b = lambda x: self.ssh.Banner.parse(x)  # noqa
        assert str(b('SSH-1.99-SSH-1.99-OpenSSH_3.6.1p2')) == 'SSH-1.99-OpenSSH_3.6.1p2'
        assert str(b('SSH-2.0-SSH-2.0-OpenSSH_4.3p2 Debian-9')) == 'SSH-2.0-OpenSSH_4.3p2 Debian-9'
        assert str(b('SSH-1.99-SSH-2.0-dropbear_0.5')) == 'SSH-1.99-dropbear_0.5'
        assert str(b('SSH-2.0-SSH-1.99-OpenSSH_4.2p1 SSH Secure Shell (non-commercial)')) == 'SSH-1.99-OpenSSH_4.2p1 SSH Secure Shell (non-commercial)'
        assert str(b('SSH-1.99-SSH-1.99-SSH-1.99-OpenSSH_3.9p1')) == 'SSH-1.99-OpenSSH_3.9p1'
