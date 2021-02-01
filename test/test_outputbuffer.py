import pytest


# pylint: disable=attribute-defined-outside-init
class TestOutputBuffer:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = ssh_audit.OutputBuffer

    def test_outputbuffer_no_lines(self, output_spy):
        output_spy.begin()
        obuf = self.OutputBuffer()
        obuf.write()
        assert output_spy.flush() == ['']
        output_spy.begin()

    def test_outputbuffer_defaults(self):
        obuf = self.OutputBuffer()
        # default: on
        assert obuf.batch is False
        assert obuf.use_colors is True
        assert obuf.level == 'info'

    def test_outputbuffer_colors(self, output_spy):
        out = self.OutputBuffer()

        # Test without colors.
        out.use_colors = False

        output_spy.begin()
        out.info('info color')
        out.write()
        assert output_spy.flush() == ['info color']

        output_spy.begin()
        out.head('head color')
        out.write()
        assert output_spy.flush() == ['head color']

        output_spy.begin()
        out.good('good color')
        out.write()
        assert output_spy.flush() == ['good color']

        output_spy.begin()
        out.warn('warn color')
        out.write()
        assert output_spy.flush() == ['warn color']

        output_spy.begin()
        out.fail('fail color')
        out.write()
        assert output_spy.flush() == ['fail color']

        # If colors aren't supported by this system, skip the color tests.
        if not out.colors_supported:
            return

        # Test with colors.
        out.use_colors = True

        output_spy.begin()
        out.info('info color')
        out.write()
        assert output_spy.flush() == ['info color']

        output_spy.begin()
        out.head('head color')
        out.write()
        assert output_spy.flush() in [['\x1b[0;36mhead color\x1b[0m'], ['\x1b[0;96mhead color\x1b[0m']]

        output_spy.begin()
        out.good('good color')
        out.write()
        assert output_spy.flush() in [['\x1b[0;32mgood color\x1b[0m'], ['\x1b[0;92mgood color\x1b[0m']]

        output_spy.begin()
        out.warn('warn color')
        out.write()
        assert output_spy.flush() in [['\x1b[0;33mwarn color\x1b[0m'], ['\x1b[0;93mwarn color\x1b[0m']]

        output_spy.begin()
        out.fail('fail color')
        out.write()
        assert output_spy.flush() in [['\x1b[0;31mfail color\x1b[0m'], ['\x1b[0;91mfail color\x1b[0m']]

    def test_outputbuffer_sep(self, output_spy):
        out = self.OutputBuffer()
        output_spy.begin()
        out.sep()
        out.sep()
        out.sep()
        out.write()
        assert output_spy.flush() == ['', '', '']

    def test_outputbuffer_levels(self):
        out = self.OutputBuffer()
        assert out.get_level('info') == 0
        assert out.get_level('good') == 0
        assert out.get_level('warn') == 1
        assert out.get_level('fail') == 2
        assert out.get_level('unknown') > 2

    def test_outputbuffer_level_property(self):
        out = self.OutputBuffer()
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

    def test_outputbuffer_level(self, output_spy):
        out = self.OutputBuffer()
        # visible: all
        out.level = 'info'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        out.write()
        assert len(output_spy.flush()) == 5
        # visible: head, warn, fail
        out.level = 'warn'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        out.write()
        assert len(output_spy.flush()) == 3
        # visible: head, fail
        out.level = 'fail'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        out.write()
        assert len(output_spy.flush()) == 2
        # visible: head
        out.level = 'invalid level'
        output_spy.begin()
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        out.write()
        assert len(output_spy.flush()) == 1

    def test_outputbuffer_batch(self, output_spy):
        out = self.OutputBuffer()
        # visible: all
        output_spy.begin()
        out.level = 'info'
        out.batch = False
        out.info('info color')
        out.head('head color')
        out.good('good color')
        out.warn('warn color')
        out.fail('fail color')
        out.write()
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
        out.write()
        assert len(output_spy.flush()) == 4
