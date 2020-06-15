import pytest


# pylint: disable=attribute-defined-outside-init
class TestVersionCompare:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.ssh = ssh_audit.SSH

    def get_dropbear_software(self, v):
        b = self.ssh.Banner.parse('SSH-2.0-dropbear_{}'.format(v))
        return self.ssh.Software.parse(b)

    def get_openssh_software(self, v):
        b = self.ssh.Banner.parse('SSH-2.0-OpenSSH_{}'.format(v))
        return self.ssh.Software.parse(b)

    def get_libssh_software(self, v):
        b = self.ssh.Banner.parse('SSH-2.0-libssh-{}'.format(v))
        return self.ssh.Software.parse(b)

    def test_dropbear_compare_version_pre_years(self):
        s = self.get_dropbear_software('0.44')
        assert s.compare_version(None) == 1
        assert s.compare_version('') == 1
        assert s.compare_version('0.43') > 0
        assert s.compare_version('0.44') == 0
        assert s.compare_version(s) == 0
        assert s.compare_version('0.45') < 0
        assert s.between_versions('0.43', '0.45')
        assert s.between_versions('0.43', '0.43') is False
        assert s.between_versions('0.45', '0.43') is False

    def test_dropbear_compare_version_with_years(self):
        s = self.get_dropbear_software('2015.71')
        assert s.compare_version(None) == 1
        assert s.compare_version('') == 1
        assert s.compare_version('2014.66') > 0
        assert s.compare_version('2015.71') == 0
        assert s.compare_version(s) == 0
        assert s.compare_version('2016.74') < 0
        assert s.between_versions('2014.66', '2016.74')
        assert s.between_versions('2014.66', '2015.69') is False
        assert s.between_versions('2016.74', '2014.66') is False

    def test_dropbear_compare_version_mixed(self):
        s = self.get_dropbear_software('0.53.1')
        assert s.compare_version(None) == 1
        assert s.compare_version('') == 1
        assert s.compare_version('0.53') > 0
        assert s.compare_version('0.53.1') == 0
        assert s.compare_version(s) == 0
        assert s.compare_version('2011.54') < 0
        assert s.between_versions('0.53', '2011.54')
        assert s.between_versions('0.53', '0.53') is False
        assert s.between_versions('2011.54', '0.53') is False

    def test_dropbear_compare_version_patchlevel(self):
        s1 = self.get_dropbear_software('0.44')
        s2 = self.get_dropbear_software('0.44test3')
        assert s1.compare_version(None) == 1
        assert s1.compare_version('') == 1
        assert s1.compare_version('0.44') == 0
        assert s1.compare_version(s1) == 0
        assert s1.compare_version('0.43') > 0
        assert s1.compare_version('0.44test4') > 0
        assert s1.between_versions('0.44test4', '0.45')
        assert s1.between_versions('0.43', '0.44test4') is False
        assert s1.between_versions('0.45', '0.44test4') is False
        assert s2.compare_version(None) == 1
        assert s2.compare_version('') == 1
        assert s2.compare_version('0.44test3') == 0
        assert s2.compare_version(s2) == 0
        assert s2.compare_version('0.44') < 0
        assert s2.compare_version('0.44test4') < 0
        assert s2.between_versions('0.43', '0.44')
        assert s2.between_versions('0.43', '0.44test2') is False
        assert s2.between_versions('0.44', '0.43') is False
        assert s1.compare_version(s2) > 0
        assert s2.compare_version(s1) < 0

    def test_dropbear_compare_version_sequential(self):
        versions = []
        for i in range(28, 44):
            versions.append('0.{}'.format(i))
        for i in range(1, 5):
            versions.append('0.44test{}'.format(i))
        for i in range(44, 49):
            versions.append('0.{}'.format(i))
        versions.append('0.48.1')
        for i in range(49, 54):
            versions.append('0.{}'.format(i))
        versions.append('0.53.1')
        for v in ['2011.54', '2012.55']:
            versions.append(v)
        for i in range(56, 61):
            versions.append('2013.{}'.format(i))
        for v in ['2013.61test', '2013.62']:
            versions.append(v)
        for i in range(63, 67):
            versions.append('2014.{}'.format(i))
        for i in range(67, 72):
            versions.append('2015.{}'.format(i))
        for i in range(72, 75):
            versions.append('2016.{}'.format(i))
        length = len(versions)
        for i in range(length):
            v = versions[i]
            s = self.get_dropbear_software(v)
            assert s.compare_version(v) == 0
            if i - 1 >= 0:
                vbefore = versions[i - 1]
                assert s.compare_version(vbefore) > 0
            if i + 1 < length:
                vnext = versions[i + 1]
                assert s.compare_version(vnext) < 0

    def test_openssh_compare_version_simple(self):
        s = self.get_openssh_software('3.7.1')
        assert s.compare_version(None) == 1
        assert s.compare_version('') == 1
        assert s.compare_version('3.7') > 0
        assert s.compare_version('3.7.1') == 0
        assert s.compare_version(s) == 0
        assert s.compare_version('3.8') < 0
        assert s.between_versions('3.7', '3.8')
        assert s.between_versions('3.6', '3.7') is False
        assert s.between_versions('3.8', '3.7') is False

    def test_openssh_compare_version_patchlevel(self):
        s1 = self.get_openssh_software('2.1.1')
        s2 = self.get_openssh_software('2.1.1p2')
        assert s1.compare_version(s1) == 0
        assert s2.compare_version(s2) == 0
        assert s1.compare_version('2.1.1p1') == 0
        assert s1.compare_version('2.1.1p2') == 0
        assert s2.compare_version('2.1.1') == 0
        assert s2.compare_version('2.1.1p1') > 0
        assert s2.compare_version('2.1.1p3') < 0
        assert s1.compare_version(s2) == 0
        assert s2.compare_version(s1) == 0

    def test_openbsd_compare_version_sequential(self):
        versions = []
        for v in ['1.2.3', '2.1.0', '2.1.1', '2.2.0', '2.3.0']:
            versions.append(v)
        for v in ['2.5.0', '2.5.1', '2.5.2', '2.9', '2.9.9']:
            versions.append(v)
        for v in ['3.0', '3.0.1', '3.0.2', '3.1', '3.2.2', '3.2.3']:
            versions.append(v)
        for i in range(3, 7):
            versions.append('3.{}'.format(i))
        for v in ['3.6.1', '3.7.0', '3.7.1']:
            versions.append(v)
        for i in range(8, 10):
            versions.append('3.{}'.format(i))
        for i in range(0, 10):
            versions.append('4.{}'.format(i))
        for i in range(0, 10):
            versions.append('5.{}'.format(i))
        for i in range(0, 10):
            versions.append('6.{}'.format(i))
        for i in range(0, 4):
            versions.append('7.{}'.format(i))
        length = len(versions)
        for i in range(length):
            v = versions[i]
            s = self.get_openssh_software(v)
            assert s.compare_version(v) == 0
            if i - 1 >= 0:
                vbefore = versions[i - 1]
                assert s.compare_version(vbefore) > 0
            if i + 1 < length:
                vnext = versions[i + 1]
                assert s.compare_version(vnext) < 0

    def test_libssh_compare_version_simple(self):
        s = self.get_libssh_software('0.3')
        assert s.compare_version(None) == 1
        assert s.compare_version('') == 1
        assert s.compare_version('0.2') > 0
        assert s.compare_version('0.3') == 0
        assert s.compare_version(s) == 0
        assert s.compare_version('0.3.1') < 0
        assert s.between_versions('0.2', '0.3.1')
        assert s.between_versions('0.1', '0.2') is False
        assert s.between_versions('0.3.1', '0.2') is False

    def test_libssh_compare_version_sequential(self):
        versions = []
        for v in ['0.2', '0.3']:
            versions.append(v)
        for i in range(1, 5):
            versions.append('0.3.{}'.format(i))
        for i in range(0, 9):
            versions.append('0.4.{}'.format(i))
        for i in range(0, 6):
            versions.append('0.5.{}'.format(i))
        for i in range(0, 6):
            versions.append('0.6.{}'.format(i))
        for i in range(0, 5):
            versions.append('0.7.{}'.format(i))
        length = len(versions)
        for i in range(length):
            v = versions[i]
            s = self.get_libssh_software(v)
            assert s.compare_version(v) == 0
            if i - 1 >= 0:
                vbefore = versions[i - 1]
                assert s.compare_version(vbefore) > 0
            if i + 1 < length:
                vnext = versions[i + 1]
                assert s.compare_version(vnext) < 0
