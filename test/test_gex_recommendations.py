import copy

import pytest

from ssh_audit.algorithms import Algorithms
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.ssh_audit import get_algorithm_recommendations


@pytest.mark.parametrize('bits', [3072, 4096, 8192])
def test_pq_only_gex_warning_does_not_recommend_larger_modulus(monkeypatch, bits):
    database = copy.deepcopy(SSH2_KexDB.MASTER_DB)
    monkeypatch.setattr(SSH2_KexDB, 'get_db', lambda: database)
    party = SSH2_KexParty([], [], [], [])
    kex = SSH2_Kex(OutputBuffer(), b'\0' * 16,
                   ['diffie-hellman-group-exchange-sha256'], [], party, party, False)
    kex.set_dh_modulus_size('diffie-hellman-group-exchange-sha256', bits)
    software = Software(None, Product.OpenSSH, '9.9', None, None)
    recommendations = get_algorithm_recommendations(Algorithms(kex), [], software)
    assert recommendations['warning']['del']['kex'] == [
        {'name': 'diffie-hellman-group-exchange-sha256', 'notes': ''}]
    assert 'chg' not in recommendations['warning']


@pytest.mark.parametrize('bits,level', [(1024, 'critical'), (1536, 'critical'), (2048, 'warning')])
def test_gex_small_modulus_retains_change_recommendation(monkeypatch, bits, level):
    database = copy.deepcopy(SSH2_KexDB.MASTER_DB)
    if bits < 2048:
        database['kex']['diffie-hellman-group-exchange-sha256'][1] = [
            'using small %d-bit modulus' % bits]
    else:
        database['kex']['diffie-hellman-group-exchange-sha256'][2].append(
            SSH2_KexDB.WARN_2048BIT_MODULUS)
    monkeypatch.setattr(SSH2_KexDB, 'get_db', lambda: database)
    party = SSH2_KexParty([], [], [], [])
    kex = SSH2_Kex(OutputBuffer(), b'\0' * 16,
                   ['diffie-hellman-group-exchange-sha256'], [], party, party, False)
    kex.set_dh_modulus_size('diffie-hellman-group-exchange-sha256', bits)
    software = Software(None, Product.OpenSSH, '9.9', None, None)
    recommendations = get_algorithm_recommendations(Algorithms(kex), [], software)
    assert recommendations[level]['chg']['kex'] == [
        {'name': 'diffie-hellman-group-exchange-sha256',
         'notes': 'increase modulus size to 3072 bits or larger'}]


@pytest.mark.parametrize('key', [
    'rsa-sha2-256', 'rsa-sha2-512',
    'rsa-sha2-256-cert-v01@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com'])
def test_rsa_small_modulus_retains_change_recommendation(monkeypatch, key):
    database = copy.deepcopy(SSH2_KexDB.MASTER_DB)
    while len(database['key'][key]) < 3:
        database['key'][key].append([])
    database['key'][key][2].append(SSH2_KexDB.WARN_2048BIT_MODULUS)
    monkeypatch.setattr(SSH2_KexDB, 'get_db', lambda: database)
    party = SSH2_KexParty([], [], [], [])
    kex = SSH2_Kex(OutputBuffer(), b'\0' * 16, [], [key], party, party, False)
    software = Software(None, Product.OpenSSH, '9.9', None, None)
    recommendations = get_algorithm_recommendations(Algorithms(kex), [], software)
    assert recommendations['warning']['chg']['key'] == [
        {'name': key, 'notes': 'increase modulus size to 3072 bits or larger'}]


def test_gex_openssh_fallback_suppression_is_preserved(monkeypatch):
    database = copy.deepcopy(SSH2_KexDB.MASTER_DB)
    monkeypatch.setattr(SSH2_KexDB, 'get_db', lambda: database)
    party = SSH2_KexParty([], [], [], [])
    name = 'diffie-hellman-group-exchange-sha256'
    kex = SSH2_Kex(OutputBuffer(), b'\0' * 16, [name], [], party, party, False)
    software = Software(None, Product.OpenSSH, '9.9', None, None)
    recommendations = get_algorithm_recommendations(Algorithms(kex), [name], software)
    assert name not in str(recommendations)


@pytest.mark.parametrize('fixture', [
    'openssh_8.0p1_test1', 'openssh_8.0p1_test2', 'openssh_8.0p1_test3',
    'openssh_5.6p1_test1', 'openssh_5.6p1_test2', 'openssh_5.6p1_test3',
    'openssh_5.6p1_test4', 'openssh_5.6p1_test5'])
def test_recommendations_from_recorded_ssh_findings(monkeypatch, fixture):
    # Replay recorded findings through the real recommendation engine. This is
    # not a replacement for negotiating with the Docker SSH servers.
    import json
    from pathlib import Path
    findings_path = Path(__file__).parent / 'docker' / 'expected_results' / (fixture + '.json')
    findings = json.loads(findings_path.read_text())
    database = copy.deepcopy(SSH2_KexDB.MASTER_DB)
    for kind in ['kex', 'key', 'enc', 'mac']:
        for entry in findings[kind]:
            name = entry['algorithm']
            versions = database[kind].get(name, [[]])[0]
            notes = entry['notes']
            database[kind][name] = [versions, notes.get('fail', []), notes.get('warn', [])]
    monkeypatch.setattr(SSH2_KexDB, 'get_db', lambda: database)
    party = SSH2_KexParty([x['algorithm'] for x in findings['enc']],
                          [x['algorithm'] for x in findings['mac']], findings['compression'], [])
    kex = SSH2_Kex(OutputBuffer(), b'\0' * 16,
                   [x['algorithm'] for x in findings['kex']],
                   [x['algorithm'] for x in findings['key']], party, party, False)
    version = findings['banner']['software'].split('_', 1)[1]
    software = Software(None, Product.OpenSSH, version, None, None)
    recommendations = get_algorithm_recommendations(Algorithms(kex), [], software)
    assert recommendations == findings['recommendations']
