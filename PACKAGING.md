# Windows

An executable can only be made on a Windows host because the PyInstaller tool (https://www.pyinstaller.org/) does not support cross-compilation.

**NOTE**: PyInstaller v4.2 is known to generate executables with broken PE checksums.  As a result, this triggers several anti-virus programs, including Microsoft Defender.  This issue has been [fixed here](https://github.com/pyinstaller/pyinstaller/pull/5580), but as of this writing, it has not been shipped in a stable release.  One workaround is to use the PyInstaller master branch instead of the version on PyPI.

First, clone PyInstaller onto a Linux machine with MinGW tools installed (`apt install mingw-w64`).  In its `booloader` directory, compile with `python3 waf all`.  Copy the *entire* pyinstaller directory to a Windows machine.  From an elevated command prompt, install it with `python setup.py install`.  Check that it was successfully installed by running `pyinstaller`.  If so, follow the instructions below, but do not install pyinstaller using pip in step #2.

1.) Install Python v3.9.x from https://www.python.org/.  To make life easier, check the option to add Python to the PATH environment variable.

2.) Using pip, install pyinstaller and colorama:

```
    pip install pyinstaller colorama
```

3.) Install Cygwin (https://www.cygwin.com/).

4.) Create the executable with:

```
    $ ./build_windows_executable.sh
```


# PyPI

To create package and upload to test server:

```
    $ sudo apt install python3-virtualenv
    $ make -f Makefile.pypi
    $ make -f Makefile.pypi uploadtest
```

To download from test server and verify:

```
    $ virtualenv -p /usr/bin/python3 /tmp/pypi_test
    $ cd /tmp/pypi_test; source bin/activate
    $ pip3 install --index-url https://test.pypi.org/simple ssh-audit
```

To upload to production server (hint: use username '\_\_token\_\_' and API token):

```
    $ make -f Makefile.pypi uploadprod
```

To download from production server and verify:

```
    $ virtualenv -p /usr/bin/python3 /tmp/pypi_prod
    $ cd /tmp/pypi_prod; source bin/activate
    $ pip3 install ssh-audit
```

# Snap

To create the snap package, run a fully-updated Ubuntu Server 20.04 VM.

Install pre-requisites with:

```
    $ sudo apt install make snapcraft
    $ sudo snap install review-tools lxd
```

Initialize LXD (leave all options default):

```
    $ sudo lxd init
```

Bump the version number in snapcraft.yaml.  Then run:

```
    $ make -f Makefile.snap
```

Upload the snap with:

```
    $ snapcraft login
    $ snapcraft upload --release=stable ssh-audit_*.snap
```


# Docker

Build image with:

```
    $ make -f Makefile.docker
```

Then upload it to Dockerhub with:

```
    $ make -f Makefile.docker upload
```
