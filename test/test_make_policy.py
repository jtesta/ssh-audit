import builtins
import struct

import pytest

from ssh_audit import exitcodes
from ssh_audit.auditconf import AuditConf
from ssh_audit.banner import Banner
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.protocol import Protocol
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexparty import SSH2_KexParty
from ssh_audit.ssh_audit import audit, make_policy
from ssh_audit.writebuf import WriteBuf


# pylint: disable=line-too-long,attribute-defined-outside-init,unused-argument
class TestMakePolicy:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.ssh_audit_module = ssh_audit
        self.OutputBuffer = OutputBuffer
        self.protocol = Protocol
        self.wbuf = WriteBuf
        self.banner_cls = Banner
        self.ssh2_kex = SSH2_Kex
        self.ssh2_kexparty = SSH2_KexParty
        self.audit = audit
        self.make_policy = make_policy
        self.AuditConf = AuditConf

    def _conf(self, policy_file):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        conf.verbose = True
        conf.ssh1 = False
        conf.ssh2 = True
        conf.skip_rate_test = True
        conf.make_policy = True
        conf.policy_file = str(policy_file)
        return conf

    def _banner(self):
        return self.banner_cls.parse('SSH-2.0-OpenSSH_7.3 ssh-audit-test')

    def _kex(self):
        enc = ['chacha20-poly1305@openssh.com']
        mac = ['hmac-sha2-256']
        comp = ['none']
        langs = ['']
        cli = self.ssh2_kexparty(enc, mac, comp, langs)
        srv = self.ssh2_kexparty(list(enc), list(mac), list(comp), list(langs))
        return self.ssh2_kex(self.OutputBuffer, b'\x00' * 16, ['bogus_kex1'], ['ssh-ed25519'], cli, srv, 0)

    @classmethod
    def _create_ssh2_packet(cls, payload):
        padding = -(len(payload) + 5) % 8
        if padding < 4:
            padding += 8
        plen = len(payload) + padding + 1
        pad_bytes = b'\x00' * padding
        return struct.pack('>Ib', plen, padding) + payload + pad_bytes

    def _kex_payload(self):
        w = self.wbuf()
        w.write(b'\x00' * 16)
        w.write_list(['bogus_kex1', 'bogus_kex2'])
        w.write_list(['ssh-ed25519'])
        w.write_list(['chacha20-poly1305@openssh.com'])
        w.write_list(['chacha20-poly1305@openssh.com'])
        w.write_list(['hmac-sha2-256'])
        w.write_list(['hmac-sha2-256'])
        w.write_list(['none'])
        w.write_list(['none'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return w.write_flush()

    def _feed(self, vsocket):
        w = self.wbuf()
        w.write_byte(self.protocol.MSG_KEXINIT)
        w.write(self._kex_payload())
        vsocket.rdata.append(b'SSH-2.0-OpenSSH_7.3 ssh-audit-test\r\n')
        vsocket.rdata.append(self._create_ssh2_packet(w.write_flush()))

    def test_make_policy_writes_new_file(self, output_spy, tmp_path):
        policy_file = tmp_path / 'policy.txt'
        output_spy.begin()
        ret = self.make_policy(self._conf(policy_file), self._banner(), self._kex(), 'localhost')
        lines = output_spy.flush()

        assert ret == exitcodes.GOOD
        assert policy_file.is_file()
        data = policy_file.read_text(encoding='utf-8')
        assert 'host keys = ssh-ed25519' in data
        assert 'ciphers = chacha20-poly1305@openssh.com' in data
        assert 'key exchanges = bogus_kex1' in data
        assert any('Wrote policy to %s' % policy_file in line for line in lines)

    def test_make_policy_keeps_existing_file_and_fails(self, output_spy, tmp_path):
        policy_file = tmp_path / 'policy.txt'
        original = b'# pre-existing file contents\n'
        policy_file.write_bytes(original)
        output_spy.begin()
        ret = self.make_policy(self._conf(policy_file), self._banner(), self._kex(), 'localhost')
        lines = output_spy.flush()

        assert ret == exitcodes.UNKNOWN_ERROR
        assert policy_file.read_bytes() == original
        assert any('file already exists' in line for line in lines)

    def test_make_policy_handled_permission_error(self, output_spy, tmp_path, monkeypatch):
        policy_file = tmp_path / 'policy.txt'
        real_open = builtins.open

        def _fake_open(path, *args, **kwargs):
            if str(path) == str(policy_file):
                raise PermissionError(13, 'Permission denied', str(policy_file))
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(self.ssh_audit_module, 'SNAP_PACKAGE', False)
        monkeypatch.setattr(builtins, 'open', _fake_open)
        output_spy.begin()
        ret = self.make_policy(self._conf(policy_file), self._banner(), self._kex(), 'localhost')
        lines = output_spy.flush()

        assert ret == exitcodes.UNKNOWN_ERROR
        assert not policy_file.exists()
        assert any('insufficient permissions' in line for line in lines)

    def test_audit_propagates_policy_write_failure(self, output_spy, virtual_socket, tmp_path):
        policy_file = tmp_path / 'policy.txt'
        original = b'# pre-existing file contents\n'
        policy_file.write_bytes(original)
        self._feed(virtual_socket)
        output_spy.begin()
        out = self.OutputBuffer()
        ret = self.audit(out, self._conf(policy_file))
        out.write()
        lines = output_spy.flush()

        assert ret == exitcodes.UNKNOWN_ERROR
        assert policy_file.read_bytes() == original
        assert any('file already exists' in line for line in lines)

    def test_audit_returns_good_after_policy_creation(self, output_spy, virtual_socket, tmp_path):
        policy_file = tmp_path / 'policy.txt'
        self._feed(virtual_socket)
        output_spy.begin()
        out = self.OutputBuffer()
        ret = self.audit(out, self._conf(policy_file))
        out.write()
        lines = output_spy.flush()

        assert ret == exitcodes.GOOD
        assert policy_file.is_file()
        assert any('Wrote policy to %s' % policy_file in line for line in lines)
