import struct
import pytest

from ssh_audit.auditconf import AuditConf
from ssh_audit.fingerprint import Fingerprint
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.protocol import Protocol
from ssh_audit.readbuf import ReadBuf
from ssh_audit.ssh1 import SSH1
from ssh_audit.ssh1_publickeymessage import SSH1_PublicKeyMessage
from ssh_audit.ssh_audit import audit
from ssh_audit.writebuf import WriteBuf


# pylint: disable=line-too-long,attribute-defined-outside-init
class TestSSH1:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = OutputBuffer
        self.protocol = Protocol
        self.ssh1 = SSH1
        self.PublicKeyMessage = SSH1_PublicKeyMessage
        self.rbuf = ReadBuf
        self.wbuf = WriteBuf
        self.audit = audit
        self.AuditConf = AuditConf
        self.fingerprint = Fingerprint

    def _conf(self):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        conf.verbose = True
        conf.ssh1 = True
        conf.ssh2 = False
        conf.skip_rate_test = True
        return conf

    def _create_ssh1_packet(self, payload, valid_crc=True):
        padding = -(len(payload) + 4) % 8
        plen = len(payload) + 4
        pad_bytes = b'\x00' * padding
        cksum = self.ssh1.crc32(pad_bytes + payload) if valid_crc else 0
        data = struct.pack('>I', plen) + pad_bytes + payload + struct.pack('>I', cksum)
        return data

    @classmethod
    def _server_key(cls):
        return (1024, 0x10001, 0xee6552da432e0ac2c422df1a51287507748bfe3b5e3e4fa989a8f49fdc163a17754939ef18ef8a667ea3b71036a151fcd7f5e01ceef1e4439864baf3ac569047582c69d6c128212e0980dcb3168f00d371004039983f6033cd785b8b8f85096c7d9405cbfdc664e27c966356a6b4eb6ee20ad43414b50de18b22829c1880b551)

    @classmethod
    def _host_key(cls):
        return (2048, 0x10001, 0xdfa20cd2a530ccc8c870aa60d9feb3b35deeab81c3215a96557abbd683d21f4600f38e475d87100da9a4404220eeb3bb5584e5a2b5b48ffda58530ea19104a32577d7459d91e76aa711b241050f4cc6d5327ccce254f371acad3be56d46eb5919b73f20dbdb1177b700f00891c5bf4ed128bb90ed541b778288285bcfa28432ab5cbcb8321b6e24760e998e0daa519f093a631e44276d7dd252ce0c08c75e2ab28a7349ead779f97d0f20a6d413bf3623cd216dc35375f6366690bcc41e3b2d5465840ec7ee0dc7e3f1c101d674a0c7dbccbc3942788b111396add2f8153b46a0e4b50d66e57ee92958f1c860dd97cc0e40e32febff915343ed53573142bdf4b)

    def _pkm_payload(self):
        w = self.wbuf()
        w.write(b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        b, e, m = self._server_key()
        w.write_int(b).write_mpint1(e).write_mpint1(m)
        b, e, m = self._host_key()
        w.write_int(b).write_mpint1(e).write_mpint1(m)
        w.write_int(2)
        w.write_int(72)
        w.write_int(36)
        return w.write_flush()

    def test_crc32(self):
        assert self.ssh1.crc32(b'') == 0x00
        assert self.ssh1.crc32(b'The quick brown fox jumps over the lazy dog') == 0xb9c60808

    def test_fingerprint(self):
        # pylint: disable=protected-access
        b, e, m = self._host_key()
        fpd = self.wbuf._create_mpint(m, False)
        fpd += self.wbuf._create_mpint(e, False)
        fp = self.fingerprint(fpd)
        assert b == 2048
        assert fp.md5 == 'MD5:9d:26:f8:39:fc:20:9d:9b:ca:cc:4a:0f:e1:93:f5:96'
        assert fp.sha256 == 'SHA256:vZdx3mhzbvVJmn08t/ruv8WDhJ9jfKYsCTuSzot+QIs'

    def _assert_pkm_keys(self, pkm, skey, hkey):
        b, e, m = skey
        assert pkm.server_key_bits == b
        assert pkm.server_key_public_exponent == e
        assert pkm.server_key_public_modulus == m
        b, e, m = hkey
        assert pkm.host_key_bits == b
        assert pkm.host_key_public_exponent == e
        assert pkm.host_key_public_modulus == m

    def _assert_pkm_fields(self, pkm, skey, hkey):
        assert pkm is not None
        assert pkm.cookie == b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        self._assert_pkm_keys(pkm, skey, hkey)
        assert pkm.protocol_flags == 2
        assert pkm.supported_ciphers_mask == 72
        assert pkm.supported_ciphers == ['3des', 'blowfish']
        assert pkm.supported_authentications_mask == 36
        assert pkm.supported_authentications == ['rsa', 'tis']
        fp = self.fingerprint(pkm.host_key_fingerprint_data)
        assert fp.md5 == 'MD5:9d:26:f8:39:fc:20:9d:9b:ca:cc:4a:0f:e1:93:f5:96'
        assert fp.sha256 == 'SHA256:vZdx3mhzbvVJmn08t/ruv8WDhJ9jfKYsCTuSzot+QIs'

    def test_pkm_init(self):
        cookie = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        pflags, cmask, amask = 2, 72, 36
        skey, hkey = self._server_key(), self._host_key()
        pkm = self.PublicKeyMessage(cookie, skey, hkey, pflags, cmask, amask)
        self._assert_pkm_fields(pkm, skey, hkey)
        for skey2 in ([], [0], [0, 1], [0, 1, 2, 3]):
            with pytest.raises(ValueError):
                pkm = self.PublicKeyMessage(cookie, skey2, hkey, pflags, cmask, amask)
        for hkey2 in ([], [0], [0, 1], [0, 1, 2, 3]):
            with pytest.raises(ValueError):
                print(hkey2)
                pkm = self.PublicKeyMessage(cookie, skey, hkey2, pflags, cmask, amask)

    def test_pkm_read(self):
        pkm = self.PublicKeyMessage.parse(self._pkm_payload())
        self._assert_pkm_fields(pkm, self._server_key(), self._host_key())

    def test_pkm_payload(self):
        cookie = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        skey, hkey = self._server_key(), self._host_key()
        pflags, cmask, amask = 2, 72, 36
        pkm1 = self.PublicKeyMessage(cookie, skey, hkey, pflags, cmask, amask)
        pkm2 = self.PublicKeyMessage.parse(self._pkm_payload())
        assert pkm1.payload == pkm2.payload

    def test_ssh1_server_simple(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        w = self.wbuf()
        w.write_byte(self.protocol.SMSG_PUBLIC_KEY)
        w.write(self._pkm_payload())
        vsocket.rdata.append(b'SSH-1.5-OpenSSH_7.2 ssh-audit-test\r\n')
        vsocket.rdata.append(self._create_ssh1_packet(w.write_flush()))
        output_spy.begin()
        out = self.OutputBuffer()
        self.audit(out, self._conf())
        out.write()
        lines = output_spy.flush()
        assert len(lines) == 21

    def test_ssh1_server_invalid_first_packet(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        w = self.wbuf()
        w.write_byte(self.protocol.SMSG_PUBLIC_KEY + 1)
        w.write(self._pkm_payload())
        vsocket.rdata.append(b'SSH-1.5-OpenSSH_7.2 ssh-audit-test\r\n')
        vsocket.rdata.append(self._create_ssh1_packet(w.write_flush()))
        output_spy.begin()
        out = self.OutputBuffer()
        ret = self.audit(out, self._conf())
        out.write()
        assert ret != 0
        lines = output_spy.flush()
        assert len(lines) == 14
        assert 'unknown message' in lines[-1]

    def test_ssh1_server_invalid_checksum(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        w = self.wbuf()
        w.write_byte(self.protocol.SMSG_PUBLIC_KEY + 1)
        w.write(self._pkm_payload())
        vsocket.rdata.append(b'SSH-1.5-OpenSSH_7.2 ssh-audit-test\r\n')
        vsocket.rdata.append(self._create_ssh1_packet(w.write_flush(), False))
        output_spy.begin()
        out = self.OutputBuffer()
        with pytest.raises(SystemExit):
            self.audit(out, self._conf())
        out.write()
        lines = output_spy.flush()
        assert len(lines) == 3
        assert ('checksum' in lines[0]) or ('checksum' in lines[1]) or ('checksum' in lines[2])
