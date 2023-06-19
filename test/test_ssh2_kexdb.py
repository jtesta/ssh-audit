import pytest

from ssh_audit.ssh2_kexdb import SSH2_KexDB


class Test_SSH2_KexDB:

    @pytest.fixture(autouse=True)
    def init(self):
        self.db = SSH2_KexDB.get_db()

    def test_ssh2_kexdb(self):
        '''Ensures that the SSH2_KexDB.ALGORITHMS dictionary is in the right format.'''

        db_keys = list(self.db.keys())
        db_keys.sort()

        # Ensure only these keys exist in the database.
        assert db_keys == ['enc', 'kex', 'key', 'mac']

        # For 'enc', 'kex', etc...
        for alg_type in self.db:

            # Iterate over algorithms within this type (i.e.: all 'enc' algorithms, all 'kex' algorithms, etc).
            for alg_name in self.db[alg_type]:

                # Get the list of failures, warnings, etc., for this algorithm.
                alg_data = self.db[alg_type][alg_name]

                # This list must be between 1 and 4 entries long.
                assert 1 <= len(alg_data) <= 4

                # The first entry denotes the versions when this algorithm was added to OpenSSH, Dropbear, and/or libssh, followed by when it was deprecated, and finally when it was removed.  Hence it must have between 0 and 3 entries.
                added_entry = alg_data[0]
                assert 0 <= len(added_entry) <= 3
