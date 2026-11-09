import json
import struct
from unittest.mock import Mock

import pytest

from ssh_audit import exitcodes
from ssh_audit.auditconf import AuditConf
from ssh_audit.clientgextest import ClientGEXTest
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.ssh_audit import process_commandline


@pytest.mark.parametrize('strength', [128, 192, 256])
def test_cli_client_strength(strength):
    conf = process_commandline(OutputBuffer(), ['-c', '--client-gex-test', str(strength)])
    assert conf.client_audit
    assert conf.client_gex_test == strength


@pytest.mark.parametrize('arguments', [
    ['--client-gex-test', '128', 'localhost'],
    ['-c', '--client-gex-test', '64'],
    ['-c', '--client-gex-test', '128', '-g', '2048'],
    ['-c', '--client-gex-test', '128', '--dheat', '1'],
    ['-c', '--client-gex-test', '128', '--conn-rate-test', '1'],
    ['-c', '--client-gex-test', '128', '-M', 'policy.txt'],
    ['-c', '--client-gex-test', '128', '-T', 'targets.txt'],
])
def test_cli_rejects_wrong_mode(arguments):
    with pytest.raises(SystemExit):
        process_commandline(OutputBuffer(), arguments)


@pytest.mark.parametrize('payload', [
    b'', b'\0' * 11, b'\0' * 13,
    struct.pack('>III', 0, 2048, 8192), struct.pack('>III', 4096, 2048, 8192),
    struct.pack('>III', 2048, 8192, 4096)])
def test_rejects_malformed_request(payload):
    with pytest.raises(ValueError):
        ClientGEXTest.parse_request(payload)


def fixture_kex(algorithms=None, keys=None, follows=False, cipher='aes128-ctr'):
    party = SSH2_KexParty([cipher], ['hmac-sha2-256'], ['none'], [''])
    return SSH2_Kex(OutputBuffer(), b'0' * 16,
                    algorithms or [ClientGEXTest.ALGORITHMS[0]],
                    keys or ['ssh-ed25519'], party, party, follows)


def test_valid_request_json(capsys):
    sock = Mock()
    sock.read_packet.return_value = (34, struct.pack('>III', 2048, 3072, 8192))
    conf = AuditConf()
    conf.client_gex_test = 128
    conf.json = True
    out = OutputBuffer()
    assert ClientGEXTest.run(out, sock, fixture_kex(), conf) == exitcodes.GOOD
    out.write()
    result = json.loads(capsys.readouterr().out)['client-gex-request']
    assert result == dict(minimum=2048, preferred=3072, maximum=8192,
                          cipher='aes128-ctr', kex=ClientGEXTest.ALGORITHMS[0])
    sock.close.assert_called_once()


def test_wrong_optimistic_guess_is_discarded():
    sock = Mock()
    sock.read_packet.side_effect = [(30, b'wrong guess'), (34, struct.pack('>III', 2048, 3072, 8192))]
    conf = AuditConf()
    conf.client_gex_test = 128
    kex = fixture_kex(['curve25519-sha256', ClientGEXTest.ALGORITHMS[0]], follows=True)
    assert ClientGEXTest.run(OutputBuffer(), sock, kex, conf) == exitcodes.GOOD
    assert sock.read_packet.call_count == 2


@pytest.mark.parametrize('packet_type,payload', [(1, b'disconnect'), (-1, b'timeout'), (30, b'old request'), (34, b'invalid')])
def test_protocol_failure_closes_socket(packet_type, payload):
    sock = Mock()
    sock.read_packet.return_value = (packet_type, payload)
    conf = AuditConf()
    conf.client_gex_test = 128
    assert ClientGEXTest.run(OutputBuffer(), sock, fixture_kex(), conf) == exitcodes.CONNECTION_ERROR
    sock.close.assert_called_once()


def test_correct_optimistic_guess_is_not_discarded():
    sock = Mock()
    sock.read_packet.return_value = (34, struct.pack('>III', 2048, 3072, 8192))
    conf = AuditConf()
    conf.client_gex_test = 128
    assert ClientGEXTest.run(OutputBuffer(), sock, fixture_kex(follows=True), conf) == exitcodes.GOOD
    sock.read_packet.assert_called_once()


def test_wrong_hostkey_guess_is_discarded():
    sock = Mock()
    sock.read_packet.side_effect = [(30, b'wrong guess'), (34, struct.pack('>III', 2048, 3072, 8192))]
    conf = AuditConf()
    conf.client_gex_test = 128
    kex = fixture_kex(keys=['unsupported-key', 'ssh-ed25519'], follows=True)
    assert ClientGEXTest.run(OutputBuffer(), sock, kex, conf) == exitcodes.GOOD
    assert sock.read_packet.call_count == 2


@pytest.mark.parametrize('kex', [
    fixture_kex(['curve25519-sha256']),
    fixture_kex(keys=['unknown-key']), fixture_kex(cipher='aes256-ctr')])
def test_incompatible_offer_is_not_reported_as_success(kex):
    sock = Mock()
    conf = AuditConf()
    conf.client_gex_test = 128
    assert ClientGEXTest.run(OutputBuffer(), sock, kex, conf) == exitcodes.CONNECTION_ERROR
    sock.read_packet.assert_not_called()
    sock.close.assert_called_once()


@pytest.mark.parametrize('strength', [128, 192, 256])
def test_audit_uses_restricted_offer(monkeypatch, strength):
    import ssh_audit.ssh_audit as module
    from ssh_audit.banner import Banner
    sock = Mock()
    sock.get_banner.return_value = (Banner.parse('SSH-2.0-OpenSSH_9.6'), [], None)
    sock.read_packet.side_effect = [(20, fixture_kex(cipher='aes%d-ctr' % strength).payload),
                                    (34, struct.pack('>III', 2048, 3072, 8192))]
    monkeypatch.setattr(module, 'SSH_Socket', Mock(return_value=sock))
    conf = AuditConf()
    conf.client_audit = True
    conf.client_gex_test = strength
    assert module.audit(OutputBuffer(), conf) == exitcodes.GOOD
    sock.listen_and_accept.assert_called_once()
    sock.send_kexinit.assert_called_once_with(key_exchanges=ClientGEXTest.ALGORITHMS,
                                              ciphers=['aes%d-ctr' % strength])
    sock.close.assert_called_once()


def test_failed_optimistic_guess_read_stops_probe():
    sock = Mock()
    sock.read_packet.return_value = (-1, b'timeout')
    conf = AuditConf()
    conf.client_gex_test = 128
    kex = fixture_kex(['curve25519-sha256', ClientGEXTest.ALGORITHMS[0]], follows=True)
    assert ClientGEXTest.run(OutputBuffer(), sock, kex, conf) == exitcodes.CONNECTION_ERROR
    sock.read_packet.assert_called_once()
    sock.close.assert_called_once()
