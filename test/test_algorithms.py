import pytest

from ssh_audit.algorithms import Algorithms
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh2_kexparty import SSH2_KexParty


def recommendations(version, patch=None, for_server=True, keys=None):
    party = SSH2_KexParty([], [], ['none'], [])
    kex = SSH2_Kex(OutputBuffer(), b'\x00' * 16, [], keys or [], party, party, False)
    software = Software(None, Product.OpenSSH, version, patch, None)
    return Algorithms(kex).get_recommendations(software, for_server)[1]


@pytest.mark.parametrize('for_server', [True, False])
@pytest.mark.parametrize('version,patch,old_name,new_name', [
    ('10.3', None, False, False),
    ('10.4', None, True, False),
    ('10.5', None, True, False),
    ('10.5', 'p2', True, False),
    ('10.6', None, False, True),
    ('10.6', 'p2', False, True),
    ('10.7', None, False, True),
])
def test_mldsa_hostkey_recommendations(version, patch, old_name, new_name, for_server):
    additions = recommendations(version, patch, for_server)[2]['key']['add']
    assert ('ssh-mldsa44-ed25519@openssh.com' in additions) == old_name
    assert ('ssh-mldsa44-ed25519' in additions) == new_name


def test_advertised_removed_algorithm_is_still_audited(monkeypatch):
    monkeypatch.setitem(SSH2_KexDB.get_db()['key'], 'test-key', [['6.2', '6.6'], ['unsafe']])
    rec = recommendations('10.6', keys=['test-key'])
    assert 'test-key' in rec[2]['key']['del']


@pytest.mark.parametrize('for_server,expected', [(True, False), (False, True)])
def test_client_support_can_outlive_server_support(monkeypatch, for_server, expected):
    monkeypatch.setitem(SSH2_KexDB.get_db()['key'], 'test-key', [['6.2', '6.6', None]])
    additions = recommendations('7.0', for_server=for_server)[2]['key']['add']
    assert ('test-key' in additions) == expected
