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


    UBUNTU_24_04_V2_POLICY = 'Hardened Ubuntu Server 24.04 LTS (version 2)'

    # Host key sizes and CA signatures that a real Ubuntu 24.04 OpenSSH server reports for the
    # host key types used by the built-in Ubuntu 24.04 LTS (version 2) policy.
    _HOST_KEY_META = {
        'ssh-ed25519': (256, '', 0),
        'rsa-sha2-512': (4096, '', 0),
        'rsa-sha2-256': (4096, '', 0),
        'sk-ssh-ed25519@openssh.com': (256, '', 0),
        'ssh-ed25519-cert-v01@openssh.com': (256, 'ssh-ed25519', 256),
        'sk-ssh-ed25519-cert-v01@openssh.com': (256, 'ssh-ed25519', 256),
        'rsa-sha2-256-cert-v01@openssh.com': (4096, 'ssh-rsa', 4096),
        'rsa-sha2-512-cert-v01@openssh.com': (4096, 'ssh-rsa', 4096),
    }


    def _get_builtin_ubuntu_24_04_kex(self, host_keys, kex_algs=None, ciphers=None, macs=None):
        '''Returns an SSH2_Kex object modeled on a real Ubuntu 24.04 OpenSSH server, with host key sizes populated.'''

        policy_struct = BUILTIN_POLICIES[self.UBUNTU_24_04_V2_POLICY]
        if kex_algs is None:
            kex_algs = policy_struct['kex']
        if ciphers is None:
            ciphers = policy_struct['ciphers']
        if macs is None:
            macs = policy_struct['macs']

        w = self.wbuf()
        w.write(b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff')
        w.write_list(kex_algs)
        w.write_list(host_keys)
        w.write_list(ciphers)
        w.write_list(ciphers)
        w.write_list(macs)
        w.write_list(macs)
        w.write_list(['none'])
        w.write_list(['none'])
        w.write_list([''])
        w.write_list([''])
        w.write_byte(False)
        w.write_int(0)
        kex = self.ssh2_kex.parse(self.OutputBuffer, w.write_flush())

        # Populate the host key sizes/CA signatures that a real server would report.  Without this,
        # Policy.evaluate() silently skips the host key size checks in the built-in policy.
        for key_type in host_keys:
            if key_type in self._HOST_KEY_META and key_type not in kex.host_keys():
                hostkey_size, ca_key_type, ca_key_size = self._HOST_KEY_META[key_type]
                kex.set_host_key(key_type, b'\x00' * 32, hostkey_size, ca_key_type, ca_key_size)

        return kex


    def test_policy_evaluate_builtin_ubuntu_24_04_required_only(self):
        '''A real Ubuntu 24.04 v2 server that presents only the required host keys still passes.'''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        kex = self._get_builtin_ubuntu_24_04_kex(BUILTIN_POLICIES[self.UBUNTU_24_04_V2_POLICY]['host_keys'])
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ''


    def test_policy_evaluate_builtin_ubuntu_24_04_required_plus_optional_reordered(self):
        '''A real Ubuntu 24.04 v2 server that also presents optional host keys (re-ordered and repeated) passes.

        The optional host keys are neither required nor forbidden by the policy, so they must be pruned
        before the subset check.  Otherwise a compliant server is reported as a false failure.
        '''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        host_keys = [
            'rsa-sha2-512-cert-v01@openssh.com',
            'ssh-ed25519',
            'sk-ssh-ed25519@openssh.com',
            'rsa-sha2-512',
            'ssh-ed25519-cert-v01@openssh.com',
            'rsa-sha2-256',
            'sk-ssh-ed25519-cert-v01@openssh.com',
            'rsa-sha2-256-cert-v01@openssh.com',
            'ssh-ed25519',  # Repeated on purpose.
        ]
        kex = self._get_builtin_ubuntu_24_04_kex(host_keys)
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ''


    def test_policy_evaluate_builtin_ubuntu_24_04_required_plus_optional_subset(self):
        '''A real Ubuntu 24.04 v2 server may present fewer required host keys plus any optional keys.'''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        host_keys = ['ssh-ed25519', 'sk-ssh-ed25519@openssh.com', 'rsa-sha2-256']
        kex = self._get_builtin_ubuntu_24_04_kex(host_keys)
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ''


    def test_policy_evaluate_builtin_ubuntu_24_04_optional_only_subset(self):
        '''Existing subset semantics are preserved: a server may support a subset (even none) of the required host keys.

        This locks in the current meaning of "subset" (fewer keys are allowed), which this fix must not change.
        '''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        host_keys = ['ssh-ed25519-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com']
        kex = self._get_builtin_ubuntu_24_04_kex(host_keys)
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ''


    def test_policy_evaluate_builtin_ubuntu_24_04_all_keys_exact_mode(self):
        '''In exact mode, all required host keys (plus optional ones) pass when the pruned list matches exactly.'''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        policy._allow_hostkey_subset_and_reordering = False
        policy_struct = BUILTIN_POLICIES[self.UBUNTU_24_04_V2_POLICY]
        host_keys = list(policy_struct['host_keys']) + list(policy_struct['optional_host_keys'])
        kex = self._get_builtin_ubuntu_24_04_kex(host_keys)
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is True
        assert len(errors) == 0
        assert error_str == ''


    def test_policy_evaluate_builtin_ubuntu_24_04_missing_required_exact_mode(self):
        '''In exact mode, a missing required host key still fails and the full actual list is reported.'''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        policy._allow_hostkey_subset_and_reordering = False
        policy_struct = BUILTIN_POLICIES[self.UBUNTU_24_04_V2_POLICY]
        host_keys = ['rsa-sha2-512', 'rsa-sha2-256', 'sk-ssh-ed25519@openssh.com', 'rsa-sha2-512-cert-v01@openssh.com']
        kex = self._get_builtin_ubuntu_24_04_kex(host_keys)
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is False
        assert len(errors) == 1
        assert 'Host keys did not match.' in error_str
        assert 'exact match' in error_str
        # The error payload must contain the complete actual list, not the pruned one.
        assert 'sk-ssh-ed25519@openssh.com' in error_str
        assert 'rsa-sha2-512-cert-v01@openssh.com' in error_str
        assert policy_struct['optional_host_keys'] is not None


    def test_policy_evaluate_builtin_ubuntu_24_04_unrelated_host_key_fails(self):
        '''In subset mode, a host key that is neither required nor optional is still rejected.'''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        policy_struct = BUILTIN_POLICIES[self.UBUNTU_24_04_V2_POLICY]
        host_keys = list(policy_struct['host_keys']) + ['ecdsa-sha2-nistp256'] + list(policy_struct['optional_host_keys'])
        kex = self._get_builtin_ubuntu_24_04_kex(host_keys)
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is False
        assert len(errors) == 1
        assert 'Host keys did not match.' in error_str
        # Optional keys are reported as a separate expected list, and the actual list is complete.
        assert 'Expected (optional):' in error_str
        assert 'ecdsa-sha2-nistp256' in error_str
        assert 'sk-ssh-ed25519@openssh.com' in error_str
        assert 'rsa-sha2-512-cert-v01@openssh.com' in error_str


    def test_policy_evaluate_no_optional_host_keys_extra_key_fails(self):
        '''A policy without optional host keys must keep rejecting an extra host key in subset mode.'''

        policy_data = '''name = "Test Policy"
version = 1
allow_algorithm_subset_and_reordering = true
compressions = comp_alg1, comp_alg2
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = self.Policy(policy_data=policy_data)
        ret, errors, error_str = policy.evaluate('SSH Server 1.0', self._get_kex())
        assert ret is False
        assert len(errors) == 1
        assert 'Host keys did not match.' in error_str
        assert 'key_alg2' in error_str


    def test_policy_evaluate_builtin_ubuntu_24_04_other_alg_categories_unchanged(self):
        '''Optional host keys do not weaken the kex, cipher, or MAC checks of the built-in Ubuntu 24.04 policy.'''

        policy = self.Policy.load_builtin_policy(self.UBUNTU_24_04_V2_POLICY)
        assert policy is not None
        policy_struct = BUILTIN_POLICIES[self.UBUNTU_24_04_V2_POLICY]
        host_keys = list(policy_struct['host_keys']) + list(policy_struct['optional_host_keys'])
        kex_algs = list(policy_struct['kex']) + ['diffie-hellman-group1-sha1']
        ciphers = list(policy_struct['ciphers']) + ['aes128-cbc']
        macs = list(policy_struct['macs']) + ['hmac-sha1']
        kex = self._get_builtin_ubuntu_24_04_kex(host_keys, kex_algs=kex_algs, ciphers=ciphers, macs=macs)
        ret, errors, error_str = policy.evaluate('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13', kex)
        assert ret is False
        assert len(errors) == 3
        assert 'Host keys did not match.' not in error_str
        assert 'Key exchanges did not match.' in error_str
        assert 'Ciphers did not match.' in error_str
        assert 'MACs did not match.' in error_str


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
