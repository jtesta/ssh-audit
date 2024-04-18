import io
import sys
import socket
import pytest


@pytest.fixture(scope='module')
def ssh_audit():
    import ssh_audit.ssh_audit
    return ssh_audit.ssh_audit


# pylint: disable=attribute-defined-outside-init
class _OutputSpy(list):
    def begin(self):
        self.__out = io.StringIO()
        self.__old_stdout = sys.stdout
        sys.stdout = self.__out

    def flush(self):
        lines = self.__out.getvalue().splitlines()
        sys.stdout = self.__old_stdout
        self.__out = None
        return lines


@pytest.fixture(scope='module')
def output_spy():
    return _OutputSpy()


class _VirtualGlobalSocket:
    def __init__(self, vsocket):
        self.vsocket = vsocket
        self.addrinfodata = {}

    # pylint: disable=unused-argument
    def create_connection(self, address, timeout=0, source_address=None):
        # pylint: disable=protected-access
        return self.vsocket._connect(address, True)

    # pylint: disable=unused-argument
    def socket(self,
               family=socket.AF_INET,
               socktype=socket.SOCK_STREAM,
               proto=0,
               fileno=None):
        return self.vsocket

    def getaddrinfo(self, host, port, family=0, socktype=0, proto=0, flags=0):
        key = '{}#{}'.format(host, port)
        if key in self.addrinfodata:
            data = self.addrinfodata[key]
            if isinstance(data, Exception):
                raise data
            return data
        if host == 'localhost':
            r = []
            if family in (0, socket.AF_INET):
                r.append((socket.AF_INET, 1, 6, '', ('127.0.0.1', port)))
            if family in (0, socket.AF_INET6):
                r.append((socket.AF_INET6, 1, 6, '', ('::1', port)))
            return r
        return []


class _VirtualSocket:
    def __init__(self):
        self.sock_address = ('127.0.0.1', 0)
        self.peer_address = None
        self._connected = False
        self.timeout = -1.0
        self.rdata = []
        self.sdata = []
        self.errors = {}
        self.blocking = False
        self.gsock = _VirtualGlobalSocket(self)

    def _check_err(self, method):
        method_error = self.errors.get(method)
        if method_error:
            raise method_error

    def connect(self, address):
        return self._connect(address, False)

    def connect_ex(self, address):
        return self.connect(address)

    def _connect(self, address, ret=True):
        self.peer_address = address
        self._connected = True
        self._check_err('connect')
        return self if ret else None

    def setblocking(self, r: bool):
        self.blocking = r

    def settimeout(self, timeout):
        self.timeout = timeout

    def gettimeout(self):
        return self.timeout

    def getpeername(self):
        if self.peer_address is None or not self._connected:
            raise OSError(57, 'Socket is not connected')
        return self.peer_address

    def getsockname(self):
        return self.sock_address

    def bind(self, address):
        self.sock_address = address

    def listen(self, backlog):
        pass

    def accept(self):
        # pylint: disable=protected-access
        conn = _VirtualSocket()
        conn.sock_address = self.sock_address
        conn.peer_address = ('127.0.0.1', 0)
        conn._connected = True
        return conn, conn.peer_address

    def recv(self, bufsize, flags=0):
        # pylint: disable=unused-argument
        if not self._connected:
            raise OSError(54, 'Connection reset by peer')
        if not len(self.rdata) > 0:
            return b''
        data = self.rdata.pop(0)
        if isinstance(data, Exception):
            raise data
        return data

    def send(self, data):
        if self.peer_address is None or not self._connected:
            raise OSError(32, 'Broken pipe')
        self._check_err('send')
        self.sdata.append(data)


@pytest.fixture()
def virtual_socket(monkeypatch):
    vsocket = _VirtualSocket()
    gsock = vsocket.gsock
    monkeypatch.setattr(socket, 'create_connection', gsock.create_connection)
    monkeypatch.setattr(socket, 'socket', gsock.socket)
    monkeypatch.setattr(socket, 'getaddrinfo', gsock.getaddrinfo)
    return vsocket
