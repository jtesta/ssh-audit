#!/usr/bin/env bash

#
#   The MIT License (MIT)
#
#   Copyright (C) 2021 Joe Testa (jtesta@positronsecurity.com)
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#   THE SOFTWARE.
#

################################################################################
# build_windows_executable.sh
#
# Builds a Windows executable using PyInstaller.
################################################################################


PLATFORM="$(uname -s)"

# This script is intended for use on Cygwin only.
case "$PLATFORM" in
    CYGWIN*) ;;
    *)
	echo "Platform not supported ($PLATFORM).  This must be run in Cygwin only."
	exit 1
	;;
esac

# Ensure that Python 3.x is installed.
if [[ "$(python -V)" != "Python 3."* ]]; then
    echo "Python v3.x not found.  Install the latest stable version from: https://www.python.org/"
    exit 1
fi

# Ensure that pyinstaller is installed.
command -v pyinstaller >/dev/null 2>&1 || { echo >&2 "pyinstaller not found.  Install with: 'pip install pyinstaller'"; exit 1; }

# Ensure that the colorama module is installed.
X=`pip show colorama` 2> /dev/null
if [[ $? != 0 ]]; then
    echo "Colorama module not found.  Install with: 'pip install colorama'"
    exit 1
fi

# Update the man page.
./update_windows_man_page.sh
if [[ $? != 0 ]]; then
    echo "Failed to run ./update_windows_man_page.sh"
    exit 1
fi

# Do all operations from this point from the main source directory.
pushd src/ssh_audit > /dev/null

# Delete the executable if it exists from a prior run.
if [[ -f dist/ssh-audit.exe ]]; then
    rm dist/ssh-audit.exe
fi

# Create a link from ssh_audit.py to ssh-audit.py.
if [[ ! -f ssh-audit.py ]]; then
    ln ssh_audit.py ssh-audit.py
fi

echo -e "\nRunning pyinstaller...\n"
pyinstaller -F --icon ../../windows_icon.ico ssh-audit.py

if [[ -f dist/ssh-audit.exe ]]; then
    echo -e "\nExecutable created in $(pwd)/dist/ssh-audit.exe\n"
fi

# Remove the link we created, above.
rm ssh-audit.py

popd > /dev/null
exit 0
