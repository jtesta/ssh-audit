import pytest

from ssh_audit.ssh2_kexdb import SSH2_KexDB
from ssh_audit.dheat import DHEat


class TestDHEat:

    @pytest.fixture(autouse=True)
    def init(self):
        self.SSH2_KexDB = SSH2_KexDB
        self.DHEat = DHEat

    def test_kex_definition_completeness(self):
        alg_db = self.SSH2_KexDB.get_db()
        kex_db = alg_db['kex']

        # Get all Diffie-Hellman algorithms defined in our database.
        dh_algs = []
        for kex in kex_db:
            if kex.startswith('diffie-hellman-'):
                dh_algs.append(kex)

        # Ensure that each DH algorithm in our database is in either DHEat's alg_priority or gex_algs list.  Also ensure that all non-group exchange algorithms are accounted for in the alg_modulus_sizes dictionary.
        for dh_alg in dh_algs:
            assert (dh_alg in self.DHEat.alg_priority) or (dh_alg in self.DHEat.gex_algs)

            if dh_alg.find("group-exchange") == -1:
                assert dh_alg in self.DHEat.alg_modulus_sizes
