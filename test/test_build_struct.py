import os
import pytest

from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty


@pytest.fixture
def kex(ssh_audit):
    kex_algs, key_algs = [], []
    enc, mac, compression, languages = [], [], ['none'], []
    cli = SSH2_KexParty(enc, mac, compression, languages)
    enc, mac, compression, languages = [], [], ['none'], []
    srv = SSH2_KexParty(enc, mac, compression, languages)
    cookie = os.urandom(16)
    kex = SSH2_Kex(OutputBuffer, cookie, kex_algs, key_algs, cli, srv, 0)
    return kex


def test_prevent_runtime_error_regression(ssh_audit, kex):
    """Prevent a regression of https://github.com/jtesta/ssh-audit/issues/41

    The following test setup does not contain any sensible data.
    It was made up to reproduce a situation when there are several host
    keys, and an error occurred when iterating and modifying them at the
    same time.
    """
    kex.set_host_key("ssh-rsa", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa1", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa2", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa3", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa4", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa5", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa6", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa7", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)
    kex.set_host_key("ssh-rsa8", b"\x00\x00\x00\x07ssh-rsa\x00\x00\x00", 1024, '', 0)

    rv = ssh_audit.build_struct('localhost', None, [], kex=kex)

    assert len(rv["fingerprints"]) == (9 * 2)  # Each host key generates two hash fingerprints: one using SHA256, and one using MD5.

    for key in ['banner', 'compression', 'enc', 'fingerprints', 'kex', 'key', 'mac']:
        assert key in rv
