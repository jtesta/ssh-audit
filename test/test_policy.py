import hashlib
import pytest
from datetime import date

from ssh_audit.policy import Policy
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.writebuf import WriteBuf


class TestPolicy:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.Policy = Policy
        self.wbuf = WriteBuf
        self.ssh2_kex = SSH2_Kex


    def _get_kex(self):
        '''Returns an SSH2.Kex object to simulate a server connection.'''

        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(['kex_alg1', 'kex_alg2'])
        w.write_list(['key_alg1', 'key_alg2'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list(['comp_alg1', 'comp_alg2'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        return self.ssh2_kex.parse(w.write_flush())


    def test_builtin_policy_consistency(self):
        '''Ensure that the BUILTIN_POLICIES struct is consistent.'''

        for policy_name in Policy.BUILTIN_POLICIES:
            # Ensure that the policy name ends with " (version X)", where X is the 'version' field.
            version_str = " (version %s)" % Policy.BUILTIN_POLICIES[policy_name]['version']
            assert policy_name.endswith(version_str)

            # Ensure that each built-in policy can be loaded with Policy.load_builtin_policy().
            assert Policy.load_builtin_policy(policy_name) is not None

        # Ensure that both server and client policy names are returned.
        server_policy_names, client_policy_names = Policy.list_builtin_policies()
        assert len(server_policy_names) > 0
        assert len(client_policy_names) > 0


    def test_policy_basic(self):
        '''Ensure that a basic policy can be parsed correctly.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        assert str(policy) == "Name: [Test Policy]\nVersion: [1]\nBanner: {undefined}\nCompressions: comp_alg1\nHost Keys: key_alg1\nOptional Host Keys: {undefined}\nKey Exchanges: kex_alg1, kex_alg2\nCiphers: cipher_alg1, cipher_alg2, cipher_alg3\nMACs: mac_alg1, mac_alg2, mac_alg3\nHost Key Sizes: {undefined}\nCA Key Sizes: {undefined}\nDH Modulus Sizes: {undefined}\nServer Policy: True"


    def test_policy_invalid_1(self):
        '''Basic policy, but with 'ciphersx' instead of 'ciphers'.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphersx = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_2(self):
        '''Basic policy, but is missing the required name field.'''

        policy_data = '''# This is a comment
#name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_3(self):
        '''Basic policy, but is missing the required version field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
#version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_4(self):
        '''Basic policy, but is missing quotes in the name field.'''

        policy_data = '''# This is a comment
name = Test Policy
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_5(self):
        '''Basic policy, but is missing quotes in the banner field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

banner = 0mg
compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_invalid_6(self):
        '''Basic policy, but is missing quotes in the header field.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

header = 0mg
compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        failed = False
        try:
            self.Policy(policy_data=policy_data)
        except ValueError:
            failed = True

        assert failed, "Invalid policy did not cause Policy object to throw exception"


    def test_policy_create_1(self):
        '''Creates a policy from a kex and ensures it is generated exactly as expected.'''

        kex = self._get_kex()
        pol_data = self.Policy.create('www.l0l.com', 'bannerX', kex, False)

        # Today's date is embedded in the policy, so filter it out to get repeatable results.
        pol_data = pol_data.replace(date.today().strftime('%Y/%m/%d'), '[todays date]')

        # Instead of writing out the entire expected policy--line by line--just check that it has the expected hash.
        assert hashlib.sha256(pol_data.encode('ascii')).hexdigest() == '4af7777fb57a1dad0cf438c899a11d4f625fd9276ea3bb5ef5c9fe8806cb47dc'


    def test_policy_evaluate_passing_1(self):
        '''Creates a policy and evaluates it against the same server'''

        kex = self._get_kex()
        policy_data = self.Policy.create('www.l0l.com', None, kex, False)
        policy = self.Policy(policy_data=policy_data)

        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0
        print(error_str)
        assert len(error_str) == 0


    def test_policy_evaluate_failing_1(self):
        '''Ensure that a policy with a specified banner fails against a server with a different banner'''

        policy_data = '''name = "Test Policy"
version = 1
banner = "XXX mismatched banner XXX"
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Banner did not match.') != -1


    def test_policy_evaluate_failing_2(self):
        '''Ensure that a mismatched compressions list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = XXXmismatchedXXX, comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Compression did not match.') != -1


    def test_policy_evaluate_failing_3(self):
        '''Ensure that a mismatched host keys results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = XXXmismatchedXXX, key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Host keys did not match.') != -1


    def test_policy_evaluate_failing_4(self):
        '''Ensure that a mismatched key exchange list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = XXXmismatchedXXX, kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Key exchanges did not match.') != -1


    def test_policy_evaluate_failing_5(self):
        '''Ensure that a mismatched cipher list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, XXXmismatched, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('Ciphers did not match.') != -1


    def test_policy_evaluate_failing_6(self):
        '''Ensure that a mismatched MAC list results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, XXXmismatched, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find('MACs did not match.') != -1


    def test_policy_evaluate_failing_7(self):
        '''Ensure that a mismatched host keys and MACs results in a failure'''

        policy_data = '''name = "Test Policy"
version = 1
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2, XXXmismatchedXXX
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, XXXmismatchedXXX, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 2
        assert error_str.find('Host keys did not match.') != -1
        assert error_str.find('MACs did not match.') != -1
