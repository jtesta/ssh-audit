import socket
import errno
import pytest

from ssh_audit.outputbuffer import OutputBuffer


# pylint: disable=attribute-defined-outside-init
class TestErrors:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.AuditConf = ssh_audit.AuditConf
        self.OutputBuffer = ssh_audit.OutputBuffer
        self.audit = ssh_audit.audit

    def _conf(self):
        conf = self.AuditConf('localhost', 22)
        conf.colors = False
        conf.batch = True
        conf.skip_rate_test = True
        return conf

    def _audit(self, spy, conf=None, exit_expected=False):
        if conf is None:
            conf = self._conf()
        spy.begin()

        out = OutputBuffer()
        if exit_expected:
            with pytest.raises(SystemExit):
                self.audit(out, conf)
        else:
            ret = self.audit(out, conf)
            assert ret != 0

        out.write()
        lines = spy.flush()

        # If the last line is empty, delete it.
        if len(lines) > 1 and lines[-1] == '':
            del lines[-1]

        return lines

    def test_connection_unresolved(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.gsock.addrinfodata['localhost#22'] = []
        lines = self._audit(output_spy, exit_expected=True)
        assert len(lines) == 1
        assert 'has no DNS records' in lines[-1]

    def test_connection_refused(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.errors['connect'] = socket.error(errno.ECONNREFUSED, 'Connection refused')
        lines = self._audit(output_spy, exit_expected=True)
        assert len(lines) == 1
        assert 'Connection refused' in lines[-1]

    def test_connection_timeout(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.errors['connect'] = socket.timeout('timed out')
        lines = self._audit(output_spy, exit_expected=True)
        assert len(lines) == 1
        assert 'timed out' in lines[-1]

    def test_recv_empty(self, output_spy, virtual_socket):
        lines = self._audit(output_spy)
        assert len(lines) == 1
        assert 'did not receive banner' in lines[-1]

    def test_recv_timeout(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(socket.timeout('timed out'))
        lines = self._audit(output_spy)
        assert len(lines) == 1
        assert 'did not receive banner' in lines[-1]
        assert 'timed out' in lines[-1]

    def test_recv_retry_till_timeout(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(socket.error(errno.EAGAIN, 'Resource temporarily unavailable'))
        vsocket.rdata.append(socket.error(errno.EWOULDBLOCK, 'Resource temporarily unavailable'))
        vsocket.rdata.append(socket.error(errno.EAGAIN, 'Resource temporarily unavailable'))
        vsocket.rdata.append(socket.timeout('timed out'))
        lines = self._audit(output_spy)
        assert len(lines) == 1
        assert 'did not receive banner' in lines[-1]
        assert 'timed out' in lines[-1]

    def test_recv_retry_till_reset(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(socket.error(errno.EAGAIN, 'Resource temporarily unavailable'))
        vsocket.rdata.append(socket.error(errno.EWOULDBLOCK, 'Resource temporarily unavailable'))
        vsocket.rdata.append(socket.error(errno.EAGAIN, 'Resource temporarily unavailable'))
        vsocket.rdata.append(socket.error(errno.ECONNRESET, 'Connection reset by peer'))
        lines = self._audit(output_spy)
        assert len(lines) == 1
        assert 'did not receive banner' in lines[-1]
        assert 'reset by peer' in lines[-1]

    def test_connection_closed_before_banner(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(socket.error(errno.ECONNRESET, 'Connection reset by peer'))
        lines = self._audit(output_spy)
        assert len(lines) == 1
        assert 'did not receive banner' in lines[-1]
        assert 'reset by peer' in lines[-1]

    def test_connection_closed_after_header(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(b'header line 1\n')
        vsocket.rdata.append(b'\n')
        vsocket.rdata.append(b'header line 2\n')
        vsocket.rdata.append(socket.error(errno.ECONNRESET, 'Connection reset by peer'))
        lines = self._audit(output_spy)
        assert len(lines) == 3
        assert 'did not receive banner' in lines[-1]
        assert 'reset by peer' in lines[-1]

    def test_connection_closed_after_banner(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        vsocket.rdata.append(socket.error(54, 'Connection reset by peer'))
        lines = self._audit(output_spy)
        assert len(lines) == 2
        assert 'error reading packet' in lines[-1]
        assert 'reset by peer' in lines[-1]

    def test_empty_data_after_banner(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        lines = self._audit(output_spy)
        assert len(lines) == 2
        assert 'error reading packet' in lines[-1]
        assert 'empty' in lines[-1]

    def test_wrong_data_after_banner(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        vsocket.rdata.append(b'xxx\n')
        lines = self._audit(output_spy)
        assert len(lines) == 2
        assert 'error reading packet' in lines[-1]
        assert 'xxx' in lines[-1]

    def test_non_ascii_banner(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\xc3\xbc\r\n')
        lines = self._audit(output_spy)
        assert len(lines) == 3
        assert 'error reading packet' in lines[-1]
        assert 'ASCII' in lines[-2]
        assert lines[-3].endswith('SSH-2.0-ssh-audit-test?')

    def test_nonutf8_data_after_banner(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(b'SSH-2.0-ssh-audit-test\r\n')
        vsocket.rdata.append(b'\x81\xff\n')
        lines = self._audit(output_spy)
        assert len(lines) == 2
        assert 'error reading packet' in lines[-1]
        assert '\\x81\\xff' in lines[-1]

    def test_protocol_mismatch_by_conf(self, output_spy, virtual_socket):
        vsocket = virtual_socket
        vsocket.rdata.append(b'SSH-1.3-ssh-audit-test\r\n')
        vsocket.rdata.append(b'Protocol major versions differ.\n')
        conf = self._conf()
        lines = self._audit(output_spy, conf)
        assert len(lines) == 4
        assert 'error reading packet' in lines[-1]
        assert 'major versions differ' in lines[-1]
