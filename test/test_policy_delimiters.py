"""Tests for policy values that contain the '=' delimiter inside quotes.

A policy line is ``key = value``.  For the ``name`` and ``banner`` fields the
value is a quoted string that may itself contain '=' characters (and escaped
quotes), so the key/value boundary is the first '=' only.
"""

import pytest

from ssh_audit.policy import Policy


POLICY_WITH_EQUALS = '''# Policy whose quoted values contain the '=' delimiter.
name = "Production = EU"
version = 1
banner = "SSH = \\"Prod\\" = ready"
compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1
macs = mac_alg1'''


class TestPolicyDelimiters:
    def test_quoted_name_and_banner_with_equals_are_accepted(self, tmp_path):
        '''Quoted name/banner values may contain '=' and escaped quotes.'''

        failed = False
        policy = None
        try:
            policy = Policy(policy_data=POLICY_WITH_EQUALS)
        except ValueError:
            failed = True

        assert not failed, "a quoted '=' in the name/banner fields was rejected"
        assert policy.get_name_and_version() == 'Production = EU (version 1)'
        assert 'Name: [Production = EU]' in str(policy)
        assert 'Banner: [SSH = "Prod" = ready]' in str(policy)

        # The same bytes must behave identically when read from a real file.
        policy_file = tmp_path / 'policy_with_equals.txt'
        policy_file.write_text(POLICY_WITH_EQUALS, encoding='utf-8')

        failed = False
        from_file = None
        try:
            from_file = Policy(policy_file=str(policy_file))
        except ValueError:
            failed = True

        assert not failed, "a quoted '=' was rejected when read from a policy file"
        assert from_file.get_name_and_version() == policy.get_name_and_version()
        assert 'Banner: [SSH = "Prod" = ready]' in str(from_file)

    def test_ordinary_values_are_unchanged(self):
        '''Values without '=' keep parsing exactly as before.'''

        policy_data = '''# This is a comment
name = "Test Policy"
version = 1

compressions = comp_alg1
host keys = key_alg1
key exchanges = kex_alg1, kex_alg2
ciphers = cipher_alg1, cipher_alg2, cipher_alg3
macs = mac_alg1, mac_alg2, mac_alg3'''

        policy = Policy(policy_data=policy_data)
        assert policy.get_name_and_version() == 'Test Policy (version 1)'
        assert 'Ciphers: cipher_alg1, cipher_alg2, cipher_alg3' in str(policy)
        assert 'Banner: {undefined}' in str(policy)

    def test_empty_quoted_banner_is_accepted(self):
        '''An empty quoted banner is still treated as an empty string.'''

        policy_data = '''name = "Empty Banner Policy"
version = 1
banner = ""'''

        policy = Policy(policy_data=policy_data)
        assert policy.get_name_and_version() == 'Empty Banner Policy (version 1)'
        assert 'Banner: []' in str(policy)

    def test_invalid_field_is_still_rejected(self):
        '''Unknown keys remain invalid regardless of the delimiter handling.'''

        policy_data = '''name = "Bad Field Policy"
version = 1
bogus = "value"'''

        with pytest.raises(ValueError, match='invalid field found in policy'):
            Policy(policy_data=policy_data)

    def test_missing_version_is_still_rejected(self):
        '''The version field is still mandatory.'''

        policy_data = '''name = "No Version Policy"
compressions = comp_alg1'''

        with pytest.raises(ValueError, match='does not have a version field'):
            Policy(policy_data=policy_data)

    def test_missing_delimiter_is_still_rejected(self):
        '''A line without any '=' is still a parse error.'''

        policy_data = '''name = "No Delimiter Policy"
version = 1
compressions'''

        with pytest.raises(ValueError, match='could not parse line'):
            Policy(policy_data=policy_data)

    def test_unquoted_value_is_still_rejected(self):
        '''The quoted-value requirement for name/banner is untouched.'''

        policy_data = '''name = "Unquoted Banner Policy"
version = 1
banner = SSH = old'''

        with pytest.raises(ValueError):
            Policy(policy_data=policy_data)
