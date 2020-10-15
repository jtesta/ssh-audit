import pytest

from ssh_audit.ssh_socket import SSH_Socket


# pylint: disable=attribute-defined-outside-init
class TestSocket:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.ssh_socket = SSH_Socket

    def test_invalid_host(self, virtual_socket):
        with pytest.raises(ValueError):
            self.ssh_socket(None, 22)

    def test_invalid_port(self, virtual_socket):
        with pytest.raises(ValueError):
            self.ssh_socket('localhost', 'abc')
        with pytest.raises(ValueError):
            self.ssh_socket('localhost', -1)
        with pytest.raises(ValueError):
            self.ssh_socket('localhost', 0)
        with pytest.raises(ValueError):
            self.ssh_socket('localhost', 65536)

    def test_not_connected_socket(self, virtual_socket):
        sock = self.ssh_socket('localhost', 22)
        banner, header, err = sock.get_banner()
        assert banner is None
        assert len(header) == 0
        assert err == 'not connected'
        s, e = sock.recv()
        assert s == -1
        assert e == 'not connected'
        s, e = sock.send('nothing')
        assert s == -1
        assert e == 'not connected'
        s, e = sock.send_packet()
        assert s == -1
        assert e == 'not connected'
