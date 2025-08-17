import pytest
from ssh_audit.ssh_audit import process_commandline


# pylint: disable=attribute-defined-outside-init
class TestHardeningGuides:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = ssh_audit.OutputBuffer()
        self.process_commandline = process_commandline

    @staticmethod
    def _test_conf(conf, **kwargs):
        options = {
            'get_hardening_guides': '',
        }
        for k, v in kwargs.items():
            options[k] = v
        assert conf.get_hardening_guides == options['get_hardening_guides']

    def test_printconfig_conf_process_commandline(self):
        # pylint: disable=too-many-statements
        c = lambda x: self.process_commandline(self.OutputBuffer, x.split())  # noqa
        with pytest.raises(SystemExit):
            conf = c('')
        with pytest.raises(SystemExit):
            conf = c('--get-hardening-guides')
            self._test_conf(conf)
        with pytest.raises(SystemExit):
            conf = c('--list-hardening-guides')
            self._test_conf(conf)

        for vendor in ["Amazon", "Debian", "Rocky", "Mint", "Ubuntu", "NoOS", " "]:
            vendor = vendor
            for os_ver in ["2404", "2204", "2004", "1804", "2023", "22", "21", "20", "9", "Bookworm", "Bullseye", "NoVersion", ""]:
                os_ver = os_ver
                for cs_type in ["Client", "Server", "Mistake", ""]:
                    cs_type = cs_type
                    with pytest.raises(SystemExit):
                        conf = c(f'--get-hardening-guides {vendor} {os_ver} {cs_type}')
                        self._test_conf(conf)
