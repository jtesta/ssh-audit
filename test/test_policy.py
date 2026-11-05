import hashlib
import pytest
from datetime import date

from ssh_audit.builtin_policies import BUILTIN_POLICIES
from ssh_audit.outputbuffer import OutputBuffer
from ssh_audit.policy import Policy
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.writebuf import WriteBuf


class TestPolicy:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = OutputBuffer
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
        return self.ssh2_kex.parse(self.OutputBuffer, w.write_flush())


    def test_builtin_policy_consistency(self):
        '''Ensure that the BUILTIN_POLICIES struct is consistent.'''

        for policy_name in BUILTIN_POLICIES:

            # Ensure that all required fields are present.
            required_fields = ['version', 'changelog', 'banner', 'compressions', 'host_keys', 'optional_host_keys', 'kex', 'ciphers', 'macs', 'hostkey_sizes', 'dh_modulus_sizes', 'server_policy']
            for field in required_fields:
                assert field in BUILTIN_POLICIES[policy_name]

            # Ensure that the policy name ends with " (version X)", where X is the 'version' field.
            version_str = " (version %s)" % BUILTIN_POLICIES[policy_name]['version']
            assert policy_name.endswith(version_str)

            # Ensure version field is a string, but can be parsed as an integer.
            version_field = BUILTIN_POLICIES[policy_name]['version']
            assert type(version_field) is str
            try:
                int(version_field)
            except ValueError:
                assert False, "version field of %s policy is not parseable as an integer." % policy_name

            # Ensure that the changelog field is a string and non-empty.
            assert type(BUILTIN_POLICIES[policy_name]['changelog']) is str
            assert len(BUILTIN_POLICIES[policy_name]['changelog']) > 0

            # Ensure that at least one host key is defined.
            assert type(BUILTIN_POLICIES[policy_name]['host_keys']) is list
            assert len(BUILTIN_POLICIES[policy_name]['host_keys']) > 0

            # Ensure that at least one key exchange is defined.
            assert type(BUILTIN_POLICIES[policy_name]['kex']) is list
            assert len(BUILTIN_POLICIES[policy_name]['kex']) > 0

            # Ensure that at least one cipher is defined.
            assert type(BUILTIN_POLICIES[policy_name]['ciphers']) is list
            assert len(BUILTIN_POLICIES[policy_name]['ciphers']) > 0

            # Ensure that at least one MAC is defined
            assert type(BUILTIN_POLICIES[policy_name]['macs']) is list
            assert len(BUILTIN_POLICIES[policy_name]['macs']) > 0

            # These tests apply to server policies only.
            if BUILTIN_POLICIES[policy_name]['server_policy']:
                assert type(BUILTIN_POLICIES[policy_name]['hostkey_sizes']) is dict
                assert len(BUILTIN_POLICIES[policy_name]['hostkey_sizes']) > 0

                # Examine all the hostkey_sizes entries...
                for hostkey_type in BUILTIN_POLICIES[policy_name]['hostkey_sizes']:
                    hostkey_data = BUILTIN_POLICIES[policy_name]['hostkey_sizes'][hostkey_type]

                    # Ensure that 'hostkey_size' is always included and that it is an integer.
                    assert 'hostkey_size' in hostkey_data
                    assert type(hostkey_data['hostkey_size']) is int

                    # If this is an ed25519 host key, ensure its size is fixed at 256.  If its an RSA host key, ensure the size is 4096.
                    if hostkey_type.find('ed25519') != -1:
                        assert int(hostkey_data['hostkey_size']) == 256
                    elif hostkey_type.startswith('rsa-'):
                        assert int(hostkey_data['hostkey_size']) == 4096
                    else:  # Catch unexpected host key types.
                        assert False

                    # Ensure either that 'ca_key_type' and 'ca_key_size' are both present, or neither are.  Fail cases when only one of the fields are present.
                    assert (('ca_key_type' in hostkey_data) and ('ca_key_size' in hostkey_data)) or (('ca_key_type' not in hostkey_data) and ('ca_key_size' not in hostkey_data))

                    # Ensure that the ca_key_type is either ssh-rsa or ssh-ed25519.
                    if 'ca_key_type' in hostkey_data:
                        assert hostkey_data['ca_key_type'] in ['ssh-rsa', 'ssh-ed25519']

                    # Ensure RSA CA key sizes are fixed at 4096.  Ensure ED25519 CA keys are 256.
                    if 'ca_key_size' in hostkey_data:
                        if 'ca_key_type' == 'ssh-rsa':
                            assert hostkey_data['ca_key_size'] == 4096
                        elif 'ca_key_type' == 'ssh-ed25519':
                            assert hostkey_data['ca_key_size'] == 256

                # Ensure that the 'dh_modulus_size' field is a dict.
                assert type(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']) is dict

                # The 'dh_modulus_size' field should have either one entry, or be empty.
                assert len(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']) in range(0, 2)  # The endpoint in range() is not inclusive

                # If 'diffie-hellman-group-exchange-sha256' is in the kex list, ensure that it exists in the 'dh_modulus_sizes' entry.  That entry must be defined for 2048 bits or larger.
                if 'diffie-hellman-group-exchange-sha256' in BUILTIN_POLICIES[policy_name]['kex']:
                    assert 'diffie-hellman-group-exchange-sha256' in BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']
                    assert int(BUILTIN_POLICIES[policy_name]['dh_modulus_sizes']['diffie-hellman-group-exchange-sha256']) >= 2048

            else:  # Client-specific tests.

                # These must be set to None for client policies, since they have no meaning otherwise.
                assert BUILTIN_POLICIES[policy_name]['hostkey_sizes'] is None
                assert BUILTIN_POLICIES[policy_name]['dh_modulus_sizes'] is None

            # Ensure that each built-in policy can be loaded with Policy.load_builtin_policy().
            assert Policy.load_builtin_policy(policy_name) is not None

        # Ensure that both server and client policy names are returned.
        server_policy_names, client_policy_names = Policy.list_builtin_policies(False)
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
        assert str(policy) == "Name: [Test Policy]\nVersion: [1]\nAllow Algorithm Subset and/or Reordering: False\nAllow Host Key Subset and/or Reordering: False\nBanner: {undefined}\nCompressions: comp_alg1\nHost Keys: key_alg1\nOptional Host Keys: {undefined}\nKey Exchanges: kex_alg1, kex_alg2\nCiphers: cipher_alg1, cipher_alg2, cipher_alg3\nMACs: mac_alg1, mac_alg2, mac_alg3\nHost Key Sizes: {undefined}\nDH Modulus Sizes: {undefined}\nServer Policy: True"


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
        assert hashlib.sha256(pol_data.encode('ascii')).hexdigest() == '3862e56ea60c1ecba6dffbf724216c4391b6fe00a790b0075617477d4addf761'


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


    def test_policy_evaluate_subset_passing_1(self):
        '''Ensure that exact algorithm matches work even when subset parsing is enabled.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg1, key_alg2
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""


    def test_policy_evaluate_subset_passing_2(self):
        '''Ensure that subset parsing works.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is True
        assert len(errors) == 0
        assert error_str == ""


    def test_policy_evaluate_subset_failing_1(self):
        '''Ensure that subset parsing returns a failure.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg7, key_alg8, key_alg9
key exchanges = kex_alg7, kex_alg8, kex_alg9
ciphers = cipher_alg7, cipher_alg8, cipher_alg9, cipher_alg10
macs = mac_alg7, mac_alg8, mac_alg9, mac_alg10'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 4
        assert error_str.find("Ciphers did not match.") != -1
        assert error_str.find("Host keys did not match.") != -1
        assert error_str.find("MACs did not match") != -1
        assert error_str.find("Key exchanges did not match.") != -1


    def test_policy_evaluate_subset_failing_2(self):
        '''Ensure that subset parsing returns a failure when policy includes kex-strict-s-v00@openssh.com, but target does not.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2, kex-strict-s-v00@openssh.com
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find("Key exchanges did not match.") != -1


    def test_policy_evaluate_subset_failing_3(self):
        '''Ensure that subset parsing returns a failure when policy includes kex-strict-c-v00@openssh.com, but target does not.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg2, key_alg1, key_alg0
key exchanges = kex_alg3, kex_alg1, kex_alg2, kex-strict-c-v00@openssh.com
ciphers = cipher_alg0, cipher_alg3, cipher_alg2, cipher_alg1
macs = mac_alg2, mac_alg1, mac_alg3, mac_alg0'''
        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert error_str.find("Key exchanges did not match.") != -1

    # ------------------------------------------------------------------
    # Legacy hostkey_size_* / cakey_size_* directive regression tests.
    #
    # Each fixture below is a genuine product KEX object: the KEXINIT payload is
    # synthesized with the product's WriteBuf and parsed by SSH2_Kex.parse(), and
    # the host keys are registered through SSH2_Kex.set_host_key(), the same API
    # the live protocol handler uses.  No sockets are involved.
    # ------------------------------------------------------------------

    LEGACY_POLICY_HEADER = 'name = "Test Policy"\nversion = 1\n'


    def _legacy_policy(self, directives):
        '''Loads a policy that consists of the standard header plus the given legacy directives.'''

        return self.Policy(policy_data=self.LEGACY_POLICY_HEADER + directives)


    def _get_kex_with_host_keys(self, host_key_specs):
        '''Returns an SSH2_Kex object with real host key entries: (type, size, ca_type, ca_size) tuples.'''

        key_algs = [spec[0] for spec in host_key_specs]

        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(['kex_alg1', 'kex_alg2'])
        w.write_list(key_algs)
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['cipher_alg1', 'cipher_alg2', 'cipher_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['mac_alg1', 'mac_alg2', 'mac_alg3'])
        w.write_list(['none'])
        w.write_list(['none'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        kex = self.ssh2_kex.parse(self.OutputBuffer(), w.write_flush())

        for (key_type, hostkey_size, ca_key_type, ca_key_size) in host_key_specs:
            kex.set_host_key(key_type, b'\x00' * 8, hostkey_size, ca_key_type, ca_key_size)

        return kex


    def _hostkey_entry(self, policy, hostkey_type):
        '''Returns the parsed host key size entry for a type, with protected access made explicit.'''

        return policy._hostkey_sizes[hostkey_type]  # pylint: disable=protected-access


    def test_policy_legacy_cakey_size_only_loads_and_enforces_ca(self):
        '''A policy with only a cakey_size_ directive must load and keep enforcing the CA signature.'''

        policy = self._legacy_policy('cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n')
        entry = self._hostkey_entry(policy, 'ssh-rsa-cert-v01@openssh.com')
        assert entry['ca_key_type'] == 'ssh-rsa'
        assert entry['ca_key_size'] == 4096
        # No host key size was specified, so none may be invented for the CA-only entry.
        assert 'hostkey_size' not in entry

        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str


    def test_policy_legacy_cakey_size_only_ca_mismatch_detected(self):
        '''A CA-only policy must still detect a CA signature that is too small.'''

        policy = self._legacy_policy('cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 2048)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('CA signature size (ssh-rsa)') != -1
        # The CA-only entry must not produce a host key size error of its own.
        assert error_str.find('Host key (') == -1


    def test_policy_legacy_cakey_size_only_ca_type_mismatch_detected(self):
        '''A CA-only policy must still detect the wrong CA signature type.'''

        policy = self._legacy_policy('cakey_size_ssh-ed25519-cert-v01@openssh.com = 256\n')
        entry = self._hostkey_entry(policy, 'ssh-ed25519-cert-v01@openssh.com')
        assert entry['ca_key_type'] == 'ssh-ed25519'

        kex = self._get_kex_with_host_keys([('ssh-ed25519-cert-v01@openssh.com', 256, 'ssh-rsa', 4096)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('CA signature type') != -1


    def test_policy_legacy_foreign_hostkey_size_not_inherited(self):
        '''An unrelated hostkey_size_ line must not supply the size of a CA-only certificate type.'''

        policy = self._legacy_policy('hostkey_size_ssh-ed25519 = 256\n'
                                     'cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n')
        cert_entry = self._hostkey_entry(policy, 'ssh-rsa-cert-v01@openssh.com')
        assert cert_entry['ca_key_type'] == 'ssh-rsa'
        assert cert_entry['ca_key_size'] == 4096
        assert 'hostkey_size' not in cert_entry
        assert self._hostkey_entry(policy, 'ssh-ed25519')['hostkey_size'] == 256

        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096),
                                            ('ssh-ed25519', 256, '', 0)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str


    def test_policy_legacy_hostkey_then_cakey_same_type(self):
        '''hostkey_size_ followed by cakey_size_ for the same type keeps both constraints.'''

        policy = self._legacy_policy('hostkey_size_ssh-rsa-cert-v01@openssh.com = 2048\n'
                                     'cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n')
        entry = self._hostkey_entry(policy, 'ssh-rsa-cert-v01@openssh.com')
        assert entry['hostkey_size'] == 2048
        assert entry['ca_key_size'] == 4096

        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str

        # The host key size constraint written first is still enforced.
        policy = self._legacy_policy('hostkey_size_ssh-rsa-cert-v01@openssh.com = 2048\n'
                                     'cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 4096, 'ssh-rsa', 4096)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('Host key (ssh-rsa-cert-v01@openssh.com) sizes') != -1


    def test_policy_legacy_cakey_then_hostkey_same_type(self):
        '''cakey_size_ followed by hostkey_size_ for the same type must not lose the CA constraint.'''

        policy = self._legacy_policy('cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n'
                                     'hostkey_size_ssh-rsa-cert-v01@openssh.com = 2048\n')
        entry = self._hostkey_entry(policy, 'ssh-rsa-cert-v01@openssh.com')
        assert entry['hostkey_size'] == 2048
        assert entry['ca_key_type'] == 'ssh-rsa'
        assert entry['ca_key_size'] == 4096

        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str

        # The CA constraint written first is still enforced.
        policy = self._legacy_policy('cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n'
                                     'hostkey_size_ssh-rsa-cert-v01@openssh.com = 2048\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 2048)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('CA signature size (ssh-rsa)') != -1


    def test_policy_legacy_multiple_certificate_types(self):
        '''Each certificate type keeps its own CA constraint; values never cross types.'''

        policy = self._legacy_policy('cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n'
                                     'cakey_size_rsa-sha2-512-cert-v01@openssh.com = 4096\n'
                                     'cakey_size_ssh-ed25519-cert-v01@openssh.com = 256\n')
        assert self._hostkey_entry(policy, 'ssh-rsa-cert-v01@openssh.com')['ca_key_type'] == 'ssh-rsa'
        assert self._hostkey_entry(policy, 'rsa-sha2-512-cert-v01@openssh.com')['ca_key_type'] == 'ssh-rsa'
        assert self._hostkey_entry(policy, 'ssh-ed25519-cert-v01@openssh.com')['ca_key_type'] == 'ssh-ed25519'
        assert 'hostkey_size' not in self._hostkey_entry(policy, 'ssh-ed25519-cert-v01@openssh.com')

        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096),
                                            ('rsa-sha2-512-cert-v01@openssh.com', 3072, 'ssh-rsa', 4096),
                                            ('ssh-ed25519-cert-v01@openssh.com', 256, 'ssh-ed25519', 256)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str

        # Only the ed25519 certificate's CA is wrong here; exactly one error is expected.
        policy = self._legacy_policy('cakey_size_ssh-rsa-cert-v01@openssh.com = 4096\n'
                                     'cakey_size_rsa-sha2-512-cert-v01@openssh.com = 4096\n'
                                     'cakey_size_ssh-ed25519-cert-v01@openssh.com = 256\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096),
                                            ('rsa-sha2-512-cert-v01@openssh.com', 3072, 'ssh-rsa', 4096),
                                            ('ssh-ed25519-cert-v01@openssh.com', 256, 'ssh-ed25519', 4096)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('CA signature size (ssh-ed25519)') != -1
        assert error_str.find('CA signature size (ssh-rsa)') == -1


    def test_policy_legacy_hostkey_size_checks_preserved(self):
        '''The legacy hostkey_size_ directives keep their exact and allow_larger_keys semantics.'''

        policy = self._legacy_policy('hostkey_size_ssh-rsa = 4096\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa', 2048, '', 0)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('Host key (ssh-rsa) sizes') != -1

        policy = self._legacy_policy('allow_larger_keys = true\nhostkey_size_ssh-rsa = 2048\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa', 4096, '', 0)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str

        policy = self._legacy_policy('allow_larger_keys = true\nhostkey_size_ssh-rsa = 2048\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa', 1024, '', 0)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('Host key (ssh-rsa) sizes') != -1


    def test_policy_legacy_cakey_size_allow_larger_keys(self):
        '''A CA-only entry keeps the allow_larger_keys semantics for CA signature sizes.'''

        policy = self._legacy_policy('allow_larger_keys = true\n'
                                     'cakey_size_ssh-rsa-cert-v01@openssh.com = 2048\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str

        policy = self._legacy_policy('allow_larger_keys = true\n'
                                     'cakey_size_ssh-rsa-cert-v01@openssh.com = 2048\n')
        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 1024)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('CA signature size (ssh-rsa)') != -1


    def test_policy_new_hostkey_sizes_format_unchanged(self):
        '''The new host_key_sizes format still enforces both host key and CA sizes.'''

        policy_data = self.LEGACY_POLICY_HEADER + \
            'host_key_sizes = {"ssh-rsa-cert-v01@openssh.com": {"hostkey_size": 2048, "ca_key_type": "ssh-rsa", "ca_key_size": 4096}, ' \
            '"ssh-ed25519": {"hostkey_size": 256}}\n'
        policy = self.Policy(policy_data=policy_data)

        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 2048, 'ssh-rsa', 4096),
                                            ('ssh-ed25519', 256, '', 0)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is True
        assert len(errors) == 0, error_str

        kex = self._get_kex_with_host_keys([('ssh-rsa-cert-v01@openssh.com', 3072, 'ssh-rsa', 4096),
                                            ('ssh-ed25519', 256, '', 0)])
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', kex)
        assert ret is False
        assert len(errors) == 1, error_str
        assert error_str.find('Host key (ssh-rsa-cert-v01@openssh.com) sizes') != -1
