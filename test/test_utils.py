import pytest


# pylint: disable=attribute-defined-outside-init
class TestUtils:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.utils = ssh_audit.Utils

    def test_to_bytes(self):
        assert self.utils.to_bytes(b'fran\xc3\xa7ais') == b'fran\xc3\xa7ais'
        assert self.utils.to_bytes('fran\xe7ais') == b'fran\xc3\xa7ais'
        # other
        with pytest.raises(TypeError):
            self.utils.to_bytes(123)

    def test_to_text(self):
        assert self.utils.to_text(b'fran\xc3\xa7ais') == 'fran\xe7ais'
        assert self.utils.to_text('fran\xe7ais') == 'fran\xe7ais'
        # other
        with pytest.raises(TypeError):
            self.utils.to_text(123)

    def test_is_ascii(self):
        assert self.utils.is_ascii('francais') is True
        assert self.utils.is_ascii('fran\xe7ais') is False
        # other
        assert self.utils.is_ascii(123) is False

    def test_to_ascii(self):
        assert self.utils.to_ascii('francais') == 'francais'
        assert self.utils.to_ascii('fran\xe7ais') == 'fran?ais'
        assert self.utils.to_ascii('fran\xe7ais', 'ignore') == 'franais'
        with pytest.raises(TypeError):
            self.utils.to_ascii(123)

    def test_is_print_ascii(self):
        assert self.utils.is_print_ascii('francais') is True
        assert self.utils.is_print_ascii('francais\n') is False
        assert self.utils.is_print_ascii('fran\xe7ais') is False
        # other
        assert self.utils.is_print_ascii(123) is False

    def test_to_print_ascii(self):
        assert self.utils.to_print_ascii('francais') == 'francais'
        assert self.utils.to_print_ascii('francais\n') == 'francais?'
        assert self.utils.to_print_ascii('fran\xe7ais') == 'fran?ais'
        assert self.utils.to_print_ascii('fran\xe7ais\n') == 'fran?ais?'
        assert self.utils.to_print_ascii('fran\xe7ais', 'ignore') == 'franais'
        assert self.utils.to_print_ascii('fran\xe7ais\n', 'ignore') == 'franais'
        with pytest.raises(TypeError):
            self.utils.to_print_ascii(123)

    def test_ctoi(self):
        assert self.utils.ctoi(123) == 123
        assert self.utils.ctoi('ABC') == 65

    def test_parse_int(self):
        assert self.utils.parse_int(123) == 123
        assert self.utils.parse_int('123') == 123
        assert self.utils.parse_int(-123) == -123
        assert self.utils.parse_int('-123') == -123
        assert self.utils.parse_int('abc') == 0

    def test_unique_seq(self):
        assert self.utils.unique_seq((1, 2, 2, 3, 3, 3)) == (1, 2, 3)
        assert self.utils.unique_seq((3, 3, 3, 2, 2, 1)) == (3, 2, 1)
        assert self.utils.unique_seq([1, 2, 2, 3, 3, 3]) == [1, 2, 3]
        assert self.utils.unique_seq([3, 3, 3, 2, 2, 1]) == [3, 2, 1]

    def test_parse_float(self):
        assert self.utils.parse_float('5.x') == -1.0

    def test_ipv6address(self):
        assert self.utils.is_ipv6_address('1.2.3.4') is False
        assert self.utils.is_ipv6_address('2600:1f18:420a:b500:bc4:c9c6:1d6:e3e4') is True
