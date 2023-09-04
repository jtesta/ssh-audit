# Contributing to ssh-audit

We are very much open to receiving patches from the community!  To encourage participation, passing CI tests, unit tests, etc., *is OPTIONAL*.  As long as the patch works properly, it can be merged.

However, if you can submit patches that pass all of our automated tests, then you'll lighten the load for the project maintainer (who already has enough to do!).  This document describes what tests are done and what documentation is maintained.

*Anything extra you can do is appreciated!*


## Tox Tests

[Tox](https://tox.wiki/) is used to automate testing.  Linting is done with [pylint](http://pylint.pycqa.org/en/latest/) & [flake8](https://flake8.pycqa.org/en/latest/), and static type-checking is done with [mypy](https://mypy.readthedocs.io/en/stable/).

For Ubuntu systems, install tox with `apt install tox`, then simply run `tox` in the top-level directory.  Look for any error messages in the (verbose) output.


## Docker Tests

Docker is used to run ssh-audit against various real SSH servers (OpenSSH, Dropbear, and TinySSH).  The output is then diff'ed against the expected result.  Any differences result in failure.

The docker tests are run with `./docker_test.sh`.


## Man Page

The `ssh-audit.1` man page documents the various features of ssh-audit.  If features are added, or significant behavior is modified, the man page needs to be updated.
