import pytest


# pylint: disable=attribute-defined-outside-init
class TestOutput:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.Output = ssh_audit.Output
        self.OutputBuffer = ssh_audit.OutputBuffer

    def test_output_buffer_no_lines(self, output_spy):
        output_spy.begin()
        with self.OutputBuffer() as obuf:
            pass
        assert output_spy.flush() == []
        output_spy.begin()
        with self.OutputBuffer() as obuf:
            pass
        obuf.flush()
        assert output_spy.flush() == []

    def test_output_buffer_no_flush(self, output_spy):
        output_spy.begin()
        with self.OutputBuffer():
            print('abc')
        assert output_spy.flush() == []

    def test_output_buffer_flush(self, output_spy):
        output_spy.begin()
        with self.OutputBuffer() as obuf:
            print('abc')
            print()
            print('def')
        obuf.flush()
        assert output_spy.flush() == ['abc', '', 'def']

    def test_output_defaults(self):
        out = self.Output()
        # default: on
        assert out.batch is False
        assert out.use_colors is True
        assert out.level == 'info'

    def test_output_colors(self, output_spy):
        out = self.Output()
        # test without colors
        out.use_colors = False
        output_spy.begin()
        out.info('info color')
        assert output_spy.flush() == ['info color']
        output_spy.begin()
        out.head('head color')
        assert output_spy.flush() == ['head color']
        output_spy.begin()
        out.good('good color')
        assert output_spy.flush() == ['good color']
        output_spy.begin()
        out.warn('warn color')
        assert output_spy.flush() == ['warn color']
        output_spy.begin()
        out.fail('fail color')
        assert output_spy.flush() == ['fail color']
        if not out.colors_supported:
            return
        # test with colors
        out.use_colors = True
        output_spy.begin()
        out.info('info color')
        assert output_spy.flush() == ['info color']
        output_spy.begin()
        out.head('head color')
        assert output_spy.flush() == ['\x1b[0;36mhead color\x1b[0m']
        output_spy.begin()
        out.good('good color')
        assert output_spy.flush() == ['\x1b[0;32mgood color\x1b[0m']
        output_spy.begin()
        out.warn('warn color')
        assert output_spy.flush() == ['\x1b[0;33mwarn color\x1b[0m']
        output_spy.begin()
        out.fail('fail color')
        assert output_spy.flush() == ['\x1b[0;31mfail color\x1b[0m']

    def test_output_sep(self, output_spy):
        out = self.Output()
        output_spy.begin()
        out.sep()
        out.sep()
        out.sep()
        assert output_spy.flush() == ['', '', '']

    def test_output_levels(self):
        out = self.Output()
        assert out.get_level('info') == 0
        assert out.get_level('good') == 0
        assert out.get_level('warn') == 1
        assert out.get_level('fail') == 2
        assert out.get_level('unknown') > 2

    def test_output_level_property(self):
        out = self.Output()
        out.level = 'info'
        assert out.level == 'info'
        out.level = 'good'
        assert out.level == 'info'
        out.level = 'warn'
        assert out.level == 'warn'
        out.level = 'fail'
        assert out.level == 'fail'
        out.level = 'invalid level'
        assert out.level == 'unknown'

    def test_output_level(self, output_spy):
        out = self.Output()
        # visible: all
        out.level = 'info'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        assert len(output_spy.flush()) == 5
        # visible: head, warn, fail
        out.level = 'warn'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        assert len(output_spy.flush()) == 3
        # visible: head, fail
        out.level = 'fail'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        assert len(output_spy.flush()) == 2
        # visible: head
        out.level = 'invalid level'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        assert len(output_spy.flush()) == 1

    def test_output_batch(self, output_spy):
        out = self.Output()
        # visible: all
        output_spy.begin()
        out.level = 'info'
        out.batch = False
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        assert len(output_spy.flush()) == 5
        # visible: all except head
        output_spy.begin()
        out.level = 'info'
        out.batch = True
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        assert len(output_spy.flush()) == 4
