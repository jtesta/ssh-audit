import re
import pytest


# pylint: disable=attribute-defined-outside-init,bad-whitespace
class TestBuffer:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.rbuf = ssh_audit.ReadBuf
        self.wbuf = ssh_audit.WriteBuf
        self.utf8rchar = b'\xef\xbf\xbd'

    @classmethod
    def _b(cls, v):
        v = re.sub(r'\s', '', v)
        data = [int(v[i * 2:i * 2 + 2], 16) for i in range(len(v) // 2)]
        return bytes(bytearray(data))

    def test_unread(self):
        w = self.wbuf().write_byte(1).write_int(2).write_flush()
        r = self.rbuf(w)
        assert r.unread_len == 5
        r.read_byte()
        assert r.unread_len == 4
        r.read_int()
        assert r.unread_len == 0

    def test_byte(self):
        w = lambda x: self.wbuf().write_byte(x).write_flush()  # noqa
        r = lambda x: self.rbuf(x).read_byte()  # noqa
        tc = [(0x00, '00'),
              (0x01, '01'),
              (0x10, '10'),
              (0xff, 'ff')]
        for p in tc:
            assert w(p[0]) == self._b(p[1])
            assert r(self._b(p[1])) == p[0]

    def test_bool(self):
        w = lambda x: self.wbuf().write_bool(x).write_flush()  # noqa
        r = lambda x: self.rbuf(x).read_bool()  # noqa
        tc = [(True,  '01'),
              (False, '00')]
        for p in tc:
            assert w(p[0]) == self._b(p[1])
            assert r(self._b(p[1])) == p[0]

    def test_int(self):
        w = lambda x: self.wbuf().write_int(x).write_flush()  # noqa
        r = lambda x: self.rbuf(x).read_int()  # noqa
        tc = [(0x00,       '00 00 00 00'),
              (0x01,       '00 00 00 01'),
              (0xabcd,     '00 00 ab cd'),
              (0xffffffff, 'ff ff ff ff')]
        for p in tc:
            assert w(p[0]) == self._b(p[1])
            assert r(self._b(p[1])) == p[0]

    def test_string(self):
        w = lambda x: self.wbuf().write_string(x).write_flush()  # noqa
        r = lambda x: self.rbuf(x).read_string()  # noqa
        tc = [('abc1',  '00 00 00 04 61 62 63 31'),
              (b'abc2',  '00 00 00 04 61 62 63 32')]
        for p in tc:
            v = p[0]
            assert w(v) == self._b(p[1])
            if not isinstance(v, bytes):
                v = bytes(bytearray(v, 'utf-8'))
            assert r(self._b(p[1])) == v

    def test_list(self):
        w = lambda x: self.wbuf().write_list(x).write_flush()  # noqa
        r = lambda x: self.rbuf(x).read_list()  # noqa
        tc = [(['d', 'ef', 'ault'], '00 00 00 09 64 2c 65 66 2c 61 75 6c 74')]
        for p in tc:
            assert w(p[0]) == self._b(p[1])
            assert r(self._b(p[1])) == p[0]

    def test_list_nonutf8(self):
        r = lambda x: self.rbuf(x).read_list()  # noqa
        src = self._b('00 00 00 04 de ad be ef')
        dst = [(b'\xde\xad' + self.utf8rchar + self.utf8rchar).decode('utf-8')]
        assert r(src) == dst

    def test_line(self):
        w = lambda x: self.wbuf().write_line(x).write_flush()  # noqa
        r = lambda x: self.rbuf(x).read_line()  # noqa
        tc = [('example line', '65 78 61 6d 70 6c 65 20 6c 69 6e 65 0d 0a')]
        for p in tc:
            assert w(p[0]) == self._b(p[1])
            assert r(self._b(p[1])) == p[0]

    def test_line_nonutf8(self):
        r = lambda x: self.rbuf(x).read_line()  # noqa
        src = self._b('de ad be af')
        dst = (b'\xde\xad' + self.utf8rchar + self.utf8rchar).decode('utf-8')
        assert r(src) == dst

    def test_bitlen(self):
        # pylint: disable=protected-access
        class Py26Int(int):
            def bit_length(self):
                raise AttributeError
        assert self.wbuf._bitlength(42) == 6
        assert self.wbuf._bitlength(Py26Int(42)) == 6

    def test_mpint1(self):
        mpint1w = lambda x: self.wbuf().write_mpint1(x).write_flush()  # noqa
        mpint1r = lambda x: self.rbuf(x).read_mpint1()  # noqa
        tc = [(0x0,     '00 00'),
              (0x1234,  '00 0d 12 34'),
              (0x12345, '00 11 01 23 45'),
              (0xdeadbeef, '00 20 de ad be ef')]
        for p in tc:
            assert mpint1w(p[0]) == self._b(p[1])
            assert mpint1r(self._b(p[1])) == p[0]

    def test_mpint2(self):
        mpint2w = lambda x: self.wbuf().write_mpint2(x).write_flush()  # noqa
        mpint2r = lambda x: self.rbuf(x).read_mpint2()  # noqa
        tc = [(0x0,               '00 00 00 00'),
              (0x80,              '00 00 00 02 00 80'),
              (0x9a378f9b2e332a7, '00 00 00 08 09 a3 78 f9 b2 e3 32 a7'),
              (-0x1234,           '00 00 00 02 ed cc'),
              (-0xdeadbeef,       '00 00 00 05 ff 21 52 41 11'),
              (-0x8000,           '00 00 00 02 80 00'),
              (-0x80,             '00 00 00 01 80')]
        for p in tc:
            assert mpint2w(p[0]) == self._b(p[1])
            assert mpint2r(self._b(p[1])) == p[0]
        assert mpint2r(self._b('00 00 00 02 ff 80')) == -0x80
