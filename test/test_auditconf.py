import pytest
from ssh_audit.ssh_audit import process_commandline


# pylint: disable=attribute-defined-outside-init
class TestAuditConf:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.AuditConf = ssh_audit.AuditConf
        self.OutputBuffer = ssh_audit.OutputBuffer()
        self.usage = ssh_audit.usage
        self.process_commandline = process_commandline

    @staticmethod
    def _test_conf(conf, **kwargs):
        options = {
            'host': '',
            'port': 22,
            'ssh1': True,
            'ssh2': True,
            'batch': False,
            'colors': True,
            'verbose': False,
            'level': 'info',
            'ipv4': False,
            'ipv6': False
        }
        for k, v in kwargs.items():
            options[k] = v
        assert conf.host == options['host']
        assert conf.port == options['port']
        assert conf.ssh1 is options['ssh1']
        assert conf.ssh2 is options['ssh2']
        assert conf.batch is options['batch']
        assert conf.colors is options['colors']
        assert conf.verbose is options['verbose']
        assert conf.level == options['level']
        assert conf.ipv4 == options['ipv4']
        assert conf.ipv6 == options['ipv6']

    def test_audit_conf_defaults(self):
        conf = self.AuditConf()
        self._test_conf(conf)

    def test_audit_conf_booleans(self):
        conf = self.AuditConf()
        for p in ['ssh1', 'ssh2', 'batch', 'colors', 'verbose']:
            for v in [True, 1]:
                setattr(conf, p, v)
                assert getattr(conf, p) is True
            for v in [False, 0]:
                setattr(conf, p, v)
                assert getattr(conf, p) is False

    def test_audit_conf_port(self):
        conf = self.AuditConf()
        for port in [22, 2222]:
            conf.port = port
            assert conf.port == port
        for port in [-1, 0, 65536, 99999]:
            with pytest.raises(ValueError) as excinfo:
                conf.port = port
            excinfo.match(r'.*invalid port.*')

    def test_audit_conf_ip_version_preference(self):
        # ipv4-only
        conf = self.AuditConf()
        conf.ipv4 = True
        assert conf.ipv4 is True
        assert conf.ipv6 is False
        assert conf.ip_version_preference == [4]
        # ipv6-only
        conf = self.AuditConf()
        conf.ipv6 = True
        assert conf.ipv4 is False
        assert conf.ipv6 is True
        assert conf.ip_version_preference == [6]
        # ipv4-preferred
        conf = self.AuditConf()
        conf.ipv4 = True
        conf.ipv6 = True
        assert conf.ipv4 is True
        assert conf.ipv6 is True
        assert conf.ip_version_preference == [4, 6]
        # ipv6-preferred
        conf = self.AuditConf()
        conf.ipv6 = True
        conf.ipv4 = True
        assert conf.ipv4 is True
        assert conf.ipv6 is True
        assert conf.ip_version_preference == [6, 4]
        # defaults
        conf = self.AuditConf()
        assert conf.ipv4 is False
        assert conf.ipv6 is False
        assert conf.ip_version_preference == []

    def test_audit_conf_level(self):
        conf = self.AuditConf()
        for level in ['info', 'warn', 'fail']:
            conf.level = level
            assert conf.level == level
        for level in ['head', 'good', 'unknown', None]:
            with pytest.raises(ValueError) as excinfo:
                conf.level = level
            excinfo.match(r'.*invalid level.*')

    def test_audit_conf_process_commandline(self):
        # pylint: disable=too-many-statements
        c = lambda x: self.process_commandline(self.OutputBuffer, x.split(), self.usage)  # noqa
        with pytest.raises(SystemExit):
            conf = c('')
        with pytest.raises(SystemExit):
            conf = c('-x')
        with pytest.raises(SystemExit):
            conf = c('-h')
        with pytest.raises(SystemExit):
            conf = c('--help')
        with pytest.raises(SystemExit):
            conf = c(':')
        with pytest.raises(SystemExit):
            conf = c(':22')
        conf = c('localhost')
        self._test_conf(conf, host='localhost')
        conf = c('github.com')
        self._test_conf(conf, host='github.com')
        conf = c('localhost:2222')
        self._test_conf(conf, host='localhost', port=2222)
        conf = c('-p 2222 localhost')
        self._test_conf(conf, host='localhost', port=2222)
        conf = c('2001:4860:4860::8888')
        self._test_conf(conf, host='2001:4860:4860::8888')
        conf = c('[2001:4860:4860::8888]:22')
        self._test_conf(conf, host='2001:4860:4860::8888')
        conf = c('[2001:4860:4860::8888]:2222')
        self._test_conf(conf, host='2001:4860:4860::8888', port=2222)
        conf = c('-p 2222 2001:4860:4860::8888')
        self._test_conf(conf, host='2001:4860:4860::8888', port=2222)
        with pytest.raises(ValueError):
            conf = c('localhost:abc')
        with pytest.raises(SystemExit):
            conf = c('-p abc localhost')
        with pytest.raises(ValueError):
            conf = c('localhost:-22')
        with pytest.raises(SystemExit):
            conf = c('-p -22 localhost')
        with pytest.raises(ValueError):
            conf = c('localhost:99999')
        with pytest.raises(SystemExit):
            conf = c('-p 99999 localhost')
        conf = c('-1 localhost')
        self._test_conf(conf, host='localhost', ssh1=True, ssh2=False)
        conf = c('-2 localhost')
        self._test_conf(conf, host='localhost', ssh1=False, ssh2=True)
        conf = c('-12 localhost')
        self._test_conf(conf, host='localhost', ssh1=True, ssh2=True)
        conf = c('-4 localhost')
        self._test_conf(conf, host='localhost', ipv4=True, ipv6=False, ipvo=(4,))
        conf = c('-6 localhost')
        self._test_conf(conf, host='localhost', ipv4=False, ipv6=True, ipvo=(6,))
        conf = c('-46 localhost')
        self._test_conf(conf, host='localhost', ipv4=True, ipv6=True, ipvo=(4, 6))
        conf = c('-64 localhost')
        self._test_conf(conf, host='localhost', ipv4=True, ipv6=True, ipvo=(6, 4))
        conf = c('-b localhost')
        self._test_conf(conf, host='localhost', batch=True, verbose=True)
        conf = c('-n localhost')
        self._test_conf(conf, host='localhost', colors=False)
        conf = c('-v localhost')
        self._test_conf(conf, host='localhost', verbose=True)
        conf = c('-l info localhost')
        self._test_conf(conf, host='localhost', level='info')
        conf = c('-l warn localhost')
        self._test_conf(conf, host='localhost', level='warn')
        conf = c('-l fail localhost')
        self._test_conf(conf, host='localhost', level='fail')
        with pytest.raises(SystemExit):
            conf = c('-l something localhost')
