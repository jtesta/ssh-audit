#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest


# pylint: disable=line-too-long,attribute-defined-outside-init
class TestSoftware(object):
	@pytest.fixture(autouse=True)
	def init(self, ssh_audit):
		self.ssh = ssh_audit.SSH
	
	def test_unknown_software(self):
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		assert ps('SSH-1.5') is None
		assert ps('SSH-1.99-AlfaMegaServer') is None
		assert ps('SSH-2.0-BetaMegaServer 0.0.1') is None
	
	def test_openssh_software(self):
		# pylint: disable=too-many-statements
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		# common
		s = ps('SSH-2.0-OpenSSH_7.3')
		assert s.vendor is None
		assert s.product == 'OpenSSH'
		assert s.version == '7.3'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'OpenSSH 7.3'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(product=OpenSSH, version=7.3)>'
		# common, portable
		s = ps('SSH-2.0-OpenSSH_7.2p1')
		assert s.vendor is None
		assert s.product == 'OpenSSH'
		assert s.version == '7.2'
		assert s.patch == 'p1'
		assert s.os is None
		assert str(s) == 'OpenSSH 7.2p1'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'OpenSSH 7.2'
		assert repr(s) == '<Software(product=OpenSSH, version=7.2, patch=p1)>'
		# dot instead of underline
		s = ps('SSH-2.0-OpenSSH.6.6')
		assert s.vendor is None
		assert s.product == 'OpenSSH'
		assert s.version == '6.6'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'OpenSSH 6.6'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(product=OpenSSH, version=6.6)>'
		# dash instead of underline
		s = ps('SSH-2.0-OpenSSH-3.9p1')
		assert s.vendor is None
		assert s.product == 'OpenSSH'
		assert s.version == '3.9'
		assert s.patch == 'p1'
		assert s.os is None
		assert str(s) == 'OpenSSH 3.9p1'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'OpenSSH 3.9'
		assert repr(s) == '<Software(product=OpenSSH, version=3.9, patch=p1)>'
		# patch prefix with dash
		s = ps('SSH-2.0-OpenSSH_7.2-hpn14v5')
		assert s.vendor is None
		assert s.product == 'OpenSSH'
		assert s.version == '7.2'
		assert s.patch == 'hpn14v5'
		assert s.os is None
		assert str(s) == 'OpenSSH 7.2 (hpn14v5)'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'OpenSSH 7.2'
		assert repr(s) == '<Software(product=OpenSSH, version=7.2, patch=hpn14v5)>'
		# patch prefix with underline
		s = ps('SSH-1.5-OpenSSH_6.6.1_hpn13v11')
		assert s.vendor is None
		assert s.product == 'OpenSSH'
		assert s.version == '6.6.1'
		assert s.patch == 'hpn13v11'
		assert s.os is None
		assert str(s) == 'OpenSSH 6.6.1 (hpn13v11)'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'OpenSSH 6.6.1'
		assert repr(s) == '<Software(product=OpenSSH, version=6.6.1, patch=hpn13v11)>'
		# patch prefix with dot
		s = ps('SSH-2.0-OpenSSH_5.9.CASPUR')
		assert s.vendor is None
		assert s.product == 'OpenSSH'
		assert s.version == '5.9'
		assert s.patch == 'CASPUR'
		assert s.os is None
		assert str(s) == 'OpenSSH 5.9 (CASPUR)'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'OpenSSH 5.9'
		assert repr(s) == '<Software(product=OpenSSH, version=5.9, patch=CASPUR)>'
	
	def test_dropbear_software(self):
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		# common
		s = ps('SSH-2.0-dropbear_2016.74')
		assert s.vendor is None
		assert s.product == 'Dropbear SSH'
		assert s.version == '2016.74'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'Dropbear SSH 2016.74'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(product=Dropbear SSH, version=2016.74)>'
		# common, patch
		s = ps('SSH-2.0-dropbear_0.44test4')
		assert s.vendor is None
		assert s.product == 'Dropbear SSH'
		assert s.version == '0.44'
		assert s.patch == 'test4'
		assert s.os is None
		assert str(s) == 'Dropbear SSH 0.44 (test4)'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'Dropbear SSH 0.44'
		assert repr(s) == '<Software(product=Dropbear SSH, version=0.44, patch=test4)>'
		# patch prefix with dash
		s = ps('SSH-2.0-dropbear_0.44-Freesco-p49')
		assert s.vendor is None
		assert s.product == 'Dropbear SSH'
		assert s.version == '0.44'
		assert s.patch == 'Freesco-p49'
		assert s.os is None
		assert str(s) == 'Dropbear SSH 0.44 (Freesco-p49)'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'Dropbear SSH 0.44'
		assert repr(s) == '<Software(product=Dropbear SSH, version=0.44, patch=Freesco-p49)>'
		# patch prefix with underline
		s = ps('SSH-2.0-dropbear_2014.66_agbn_1')
		assert s.vendor is None
		assert s.product == 'Dropbear SSH'
		assert s.version == '2014.66'
		assert s.patch == 'agbn_1'
		assert s.os is None
		assert str(s) == 'Dropbear SSH 2014.66 (agbn_1)'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == 'Dropbear SSH 2014.66'
		assert repr(s) == '<Software(product=Dropbear SSH, version=2014.66, patch=agbn_1)>'
	
	def test_libssh_software(self):
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		# common
		s = ps('SSH-2.0-libssh-0.2')
		assert s.vendor is None
		assert s.product == 'libssh'
		assert s.version == '0.2'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'libssh 0.2'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(product=libssh, version=0.2)>'
		s = ps('SSH-2.0-libssh-0.7.4')
		assert s.vendor is None
		assert s.product == 'libssh'
		assert s.version == '0.7.4'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'libssh 0.7.4'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(product=libssh, version=0.7.4)>'
	
	def test_romsshell_software(self):
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		# common
		s = ps('SSH-2.0-RomSShell_5.40')
		assert s.vendor == 'Allegro Software'
		assert s.product == 'RomSShell'
		assert s.version == '5.40'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'Allegro Software RomSShell 5.40'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(vendor=Allegro Software, product=RomSShell, version=5.40)>'
	
	def test_hp_ilo_software(self):
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		# common
		s = ps('SSH-2.0-mpSSH_0.2.1')
		assert s.vendor == 'HP'
		assert s.product == 'iLO (Integrated Lights-Out) sshd'
		assert s.version == '0.2.1'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'HP iLO (Integrated Lights-Out) sshd 0.2.1'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(vendor=HP, product=iLO (Integrated Lights-Out) sshd, version=0.2.1)>'
	
	def test_cisco_software(self):
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		# common
		s = ps('SSH-1.5-Cisco-1.25')
		assert s.vendor == 'Cisco'
		assert s.product == 'IOS/PIX sshd'
		assert s.version == '1.25'
		assert s.patch is None
		assert s.os is None
		assert str(s) == 'Cisco IOS/PIX sshd 1.25'
		assert str(s) == s.display()
		assert s.display(True) == str(s)
		assert s.display(False) == str(s)
		assert repr(s) == '<Software(vendor=Cisco, product=IOS/PIX sshd, version=1.25)>'
	
	def test_software_os(self):
		ps = lambda x: self.ssh.Software.parse(self.ssh.Banner.parse(x))  # noqa
		# unknown
		s = ps('SSH-2.0-OpenSSH_3.7.1 MegaOperatingSystem 123')
		assert s.os is None
		# NetBSD
		s = ps('SSH-1.99-OpenSSH_2.5.1 NetBSD_Secure_Shell-20010614')
		assert s.os == 'NetBSD (2001-06-14)'
		assert str(s) == 'OpenSSH 2.5.1 running on NetBSD (2001-06-14)'
		assert repr(s) == '<Software(product=OpenSSH, version=2.5.1, os=NetBSD (2001-06-14))>'
		s = ps('SSH-1.99-OpenSSH_5.0 NetBSD_Secure_Shell-20080403+-hpn13v1')
		assert s.os == 'NetBSD (2008-04-03)'
		assert str(s) == 'OpenSSH 5.0 running on NetBSD (2008-04-03)'
		assert repr(s) == '<Software(product=OpenSSH, version=5.0, os=NetBSD (2008-04-03))>'
		s = ps('SSH-2.0-OpenSSH_6.6.1_hpn13v11 NetBSD-20100308')
		assert s.os == 'NetBSD (2010-03-08)'
		assert str(s) == 'OpenSSH 6.6.1 (hpn13v11) running on NetBSD (2010-03-08)'
		assert repr(s) == '<Software(product=OpenSSH, version=6.6.1, patch=hpn13v11, os=NetBSD (2010-03-08))>'
		s = ps('SSH-2.0-OpenSSH_4.4 NetBSD')
		assert s.os == 'NetBSD'
		assert str(s) == 'OpenSSH 4.4 running on NetBSD'
		assert repr(s) == '<Software(product=OpenSSH, version=4.4, os=NetBSD)>'
		s = ps('SSH-2.0-OpenSSH_3.0.2 NetBSD Secure Shell')
		assert s.os == 'NetBSD'
		assert str(s) == 'OpenSSH 3.0.2 running on NetBSD'
		assert repr(s) == '<Software(product=OpenSSH, version=3.0.2, os=NetBSD)>'
		# FreeBSD
		s = ps('SSH-2.0-OpenSSH_7.2 FreeBSD-20160310')
		assert s.os == 'FreeBSD (2016-03-10)'
		assert str(s) == 'OpenSSH 7.2 running on FreeBSD (2016-03-10)'
		assert repr(s) == '<Software(product=OpenSSH, version=7.2, os=FreeBSD (2016-03-10))>'
		s = ps('SSH-1.99-OpenSSH_2.9 FreeBSD localisations 20020307')
		assert s.os == 'FreeBSD (2002-03-07)'
		assert str(s) == 'OpenSSH 2.9 running on FreeBSD (2002-03-07)'
		assert repr(s) == '<Software(product=OpenSSH, version=2.9, os=FreeBSD (2002-03-07))>'
		s = ps('SSH-2.0-OpenSSH_2.3.0 green@FreeBSD.org 20010321')
		assert s.os == 'FreeBSD (2001-03-21)'
		assert str(s) == 'OpenSSH 2.3.0 running on FreeBSD (2001-03-21)'
		assert repr(s) == '<Software(product=OpenSSH, version=2.3.0, os=FreeBSD (2001-03-21))>'
		s = ps('SSH-1.99-OpenSSH_4.4p1 FreeBSD-openssh-portable-overwrite-base-4.4.p1_1,1')
		assert s.os == 'FreeBSD'
		assert str(s) == 'OpenSSH 4.4p1 running on FreeBSD'
		assert repr(s) == '<Software(product=OpenSSH, version=4.4, patch=p1, os=FreeBSD)>'
		s = ps('SSH-2.0-OpenSSH_7.2-OVH-rescue FreeBSD')
		assert s.os == 'FreeBSD'
		assert str(s) == 'OpenSSH 7.2 (OVH-rescue) running on FreeBSD'
		assert repr(s) == '<Software(product=OpenSSH, version=7.2, patch=OVH-rescue, os=FreeBSD)>'
		# Windows
		s = ps('SSH-2.0-OpenSSH_3.7.1 in RemotelyAnywhere 5.21.422')
		assert s.os == 'Microsoft Windows (RemotelyAnywhere 5.21.422)'
		assert str(s) == 'OpenSSH 3.7.1 running on Microsoft Windows (RemotelyAnywhere 5.21.422)'
		assert repr(s) == '<Software(product=OpenSSH, version=3.7.1, os=Microsoft Windows (RemotelyAnywhere 5.21.422))>'
		s = ps('SSH-2.0-OpenSSH_3.8 in DesktopAuthority 7.1.091')
		assert s.os == 'Microsoft Windows (DesktopAuthority 7.1.091)'
		assert str(s) == 'OpenSSH 3.8 running on Microsoft Windows (DesktopAuthority 7.1.091)'
		assert repr(s) == '<Software(product=OpenSSH, version=3.8, os=Microsoft Windows (DesktopAuthority 7.1.091))>'
		s = ps('SSH-2.0-OpenSSH_3.8 in RemoteSupportManager 1.0.023')
		assert s.os == 'Microsoft Windows (RemoteSupportManager 1.0.023)'
		assert str(s) == 'OpenSSH 3.8 running on Microsoft Windows (RemoteSupportManager 1.0.023)'
		assert repr(s) == '<Software(product=OpenSSH, version=3.8, os=Microsoft Windows (RemoteSupportManager 1.0.023))>'
