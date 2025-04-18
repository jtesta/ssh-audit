import pytest

from ssh_audit.ssh2_kexdb import SSH2_KexDB


class Test_SSH2_KexDB:

    @pytest.fixture(autouse=True)
    def init(self):
        self.db = SSH2_KexDB.get_db()
        self.pq_warning = SSH2_KexDB.WARN_NOT_PQ_SAFE

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


    def test_kex_pq_unsafe(self):
        '''Ensures that all key exchange algorithms are marked as post-quantum unsafe, unless they appear in a whitelist.'''

        # These algorithms include protections against quantum attacks.
        kex_pq_safe = [
            "ecdh-nistp256-kyber-512r3-sha256-d00@openquantumsafe.org",
            "ecdh-nistp384-kyber-768r3-sha384-d00@openquantumsafe.org",
            "ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org",
            "ext-info-c",
            "ext-info-s",
            "kex-strict-c-v00@openssh.com",
            "kex-strict-s-v00@openssh.com",
            "mlkem768x25519-sha256",
            "sntrup4591761x25519-sha512@tinyssh.org",
            "sntrup761x25519-sha512@openssh.com",
            "sntrup761x25519-sha512",
            "x25519-kyber-512r3-sha256-d00@amazon.com",
            "x25519-kyber512-sha512@aws.amazon.com",
            "mlkem768nistp256-sha256",  # PQ safe, but has a conventional back-door.
            "mlkem1024nistp384-sha384"  # PQ safe, but has a conventional back-door.
        ]

        failures = []
        for kex_name in self.db['kex']:

            # Skip key exchanges that are PQ safe.
            if kex_name in kex_pq_safe:
                continue

            # Ensure all other kex exchanges have the proper PQ unsafe flag set in their warnings list.
            alg_data = self.db['kex'][kex_name]
            if len(alg_data) < 3 or self.pq_warning not in alg_data[2]:
                failures.append(kex_name)

        assert failures == []
