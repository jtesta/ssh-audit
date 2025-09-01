import pytest

from ssh_audit.hardening_guides import Hardening_Guides


class TestHardeningGuides:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.OutputBuffer = ssh_audit.OutputBuffer()


    def test_hardening_guides_consistency(self):
        '''Ensure that the HARDENING_GUIDES struct is consistent.'''

        # Required keys in each guide dict.
        required_guide_fields = ["server_guide", "version", "version_date", "change_log", "notes", "commands"]

        # Required keys in the commands dict.
        required_command_fields = ["heading", "comment", "command"]

        for name, guides in Hardening_Guides.HARDENING_GUIDES.items():

            # Ensure the key (guide name) is a string.
            assert type(name) is str

            # Ensure the value (guides) is a list.
            assert type(guides) is list

            for guide in guides:

                # Ensure each guide is a dict.
                assert type(guide) is dict

                # Ensure each required key is in this guide.
                for required_guide_field in required_guide_fields:
                    assert required_guide_field in guide

                # Check the guide values are the correct type.
                assert type(guide["server_guide"]) is bool
                assert type(guide["version"]) is int
                assert type(guide["version_date"]) is str
                assert type(guide["change_log"]) is str
                assert type(guide["notes"]) is str
                assert type(guide["commands"]) is list

                # The version must be creater than zero.
                assert guide["version"] > 0

                # Ensure the format is "YYYY-MM-DD".
                version_date = guide["version_date"]
                date_fields = version_date.split("-")
                assert len(date_fields) == 3

                # Check that the year is 4 digits and greater than 0.
                year = date_fields[0]
                assert len(year) == 4
                assert int(year) > 0

                # Check that the month is 2 digits and between 1 and 12.
                month = date_fields[1]
                assert len(month) == 2
                assert 1 <= int(month) <= 12

                # Check that the day is 2 digits and between 1 and 31.
                day = date_fields[2]
                assert len(day) == 2
                assert 1 <= int(day) <= 31

                # Check that the change log is filled in.
                assert len(guide["change_log"]) > 0

                commands = guide["commands"]
                for command in commands:

                    # Ensure each required key is in this command list.
                    for required_command_field in required_command_fields:
                        assert required_command_field in command

                    # Check that these fields are not empty.
                    assert len(command["heading"]) > 0
                    assert len(command["command"]) > 0
