import os
import pytest

from ssh_audit.algorithms import Algorithms
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty


# pylint: disable=attribute-defined-outside-init
class TestAlgorithms:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        cli = SSH2_KexParty([], [], ['none'], [])
        srv = SSH2_KexParty([], [], ['none'], [])
        kex = SSH2_Kex(OutputBuffer(), os.urandom(16), ['mlkem768x25519-sha256'], ['ssh-ed25519'], cli, srv, False)
        self.algs = Algorithms(kex)

    def _key_additions(self, openssh_version):
        software = Software(None, Product.OpenSSH, openssh_version, None, None)
        _, rec = self.algs.get_recommendations(software)
        return rec[2]['key']['add']

    def test_mldsa44_ed25519_recommendations(self):
        '''Ensures that the experimental "@openssh.com" name is only recommended for OpenSSH 10.4 & 10.5, and the final name from 10.6 onwards.'''

        add = self._key_additions('10.3')
        assert 'ssh-mldsa44-ed25519@openssh.com' not in add
        assert 'ssh-mldsa44-ed25519' not in add

        for version in ['10.4', '10.5']:
            add = self._key_additions(version)
            assert 'ssh-mldsa44-ed25519@openssh.com' in add
            assert 'ssh-mldsa44-ed25519' not in add

        for version in ['10.6', '10.7']:
            add = self._key_additions(version)
            assert 'ssh-mldsa44-ed25519@openssh.com' not in add
            assert 'ssh-mldsa44-ed25519' in add
