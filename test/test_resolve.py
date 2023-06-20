import socket
import pytest


# pylint: disable=attribute-defined-outside-init,protected-access
class TestResolve:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.AuditConf = ssh_audit.AuditConf
        self.audit = ssh_audit.audit
        self.OutputBuffer = ssh_audit.OutputBuffer
        self.ssh_socket = ssh_audit.SSH_Socket

    def _conf(self):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        return conf

    def test_resolve_error(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.gsock.addrinfodata['localhost#22'] = socket.gaierror(8, 'hostname nor servname provided, or not known')
        conf = self._conf()
        s = self.ssh_socket(self.OutputBuffer(), 'localhost', 22, conf.ip_version_preference)
        # output_spy.begin()
        with pytest.raises(socket.gaierror):
            list(s._resolve())
        # lines = output_spy.flush()
        # assert len(lines) == 1
        # assert 'hostname nor servname provided' in lines[-1]

    def test_resolve_hostname_without_records(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.gsock.addrinfodata['localhost#22'] = []
        conf = self._conf()
        s = self.ssh_socket(self.OutputBuffer(), 'localhost', 22, conf.ip_version_preference)
        output_spy.begin()
        r = list(s._resolve())
        assert len(r) == 0

    def test_resolve_ipv4(self, virtual_socket):
        conf = self._conf()
        conf.ipv4 = True
        s = self.ssh_socket(self.OutputBuffer(), 'localhost', 22, conf.ip_version_preference)
        r = list(s._resolve())
        assert len(r) == 1
        assert r[0] == (socket.AF_INET, ('127.0.0.1', 22))

    def test_resolve_ipv6(self, virtual_socket):
        conf = self._conf()
        conf.ipv6 = True
        s = self.ssh_socket(self.OutputBuffer(), 'localhost', 22, conf.ip_version_preference)
        r = list(s._resolve())
        assert len(r) == 1
        assert r[0] == (socket.AF_INET6, ('::1', 22))

    def test_resolve_ipv46_both(self, virtual_socket):
        conf = self._conf()
        s = self.ssh_socket(self.OutputBuffer(), 'localhost', 22, conf.ip_version_preference)
        r = list(s._resolve())
        assert len(r) == 2
        assert r[0] == (socket.AF_INET, ('127.0.0.1', 22))
        assert r[1] == (socket.AF_INET6, ('::1', 22))

    def test_resolve_ipv46_order(self, virtual_socket):
        conf = self._conf()
        conf.ipv4 = True
        conf.ipv6 = True
        s = self.ssh_socket(self.OutputBuffer(), 'localhost', 22, conf.ip_version_preference)
        r = list(s._resolve())
        assert len(r) == 2
        assert r[0] == (socket.AF_INET, ('127.0.0.1', 22))
        assert r[1] == (socket.AF_INET6, ('::1', 22))
        conf = self._conf()
        conf.ipv6 = True
        conf.ipv4 = True
        s = self.ssh_socket(self.OutputBuffer(), 'localhost', 22, conf.ip_version_preference)
        r = list(s._resolve())
        assert len(r) == 2
        assert r[0] == (socket.AF_INET6, ('::1', 22))
        assert r[1] == (socket.AF_INET, ('127.0.0.1', 22))
