# Windows

An executable can only be made on a Windows host because the PyInstaller tool (https://www.pyinstaller.org/) does not support cross-compilation.

1.) Install Python v3.11.x from https://www.python.org/.  To make life easier, check the option to add Python to the PATH environment variable.

2.) Install Cygwin (https://www.cygwin.com/).

3.) Install/update package dependencies and create the executable with:

```
    $ ./build_windows_executable.sh
```


# PyPI

To create package and upload to test server:

```
    $ sudo apt install python3-virtualenv python3.8-venv
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

To create the snap package, run a fully-updated Ubuntu Server 22.04 VM.

Create the snap package with:
```
    $ ./build_snap.sh
```

Upload the snap with:

```
    $ snapcraft export-login ~/snap_creds.txt
    $ export SNAPCRAFT_STORE_CREDENTIALS=$(cat ~/snap_creds.txt)
    $ snapcraft upload --release=beta ssh-audit_*.snap
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
