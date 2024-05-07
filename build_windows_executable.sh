#!/usr/bin/env bash

#
#   The MIT License (MIT)
#
#   Copyright (C) 2021-2024 Joe Testa (jtesta@positronsecurity.com)
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
case "${PLATFORM}" in
    CYGWIN*) ;;
    *)
    echo "Platform not supported (${PLATFORM}).  This must be run in Cygwin only."
    exit 1
    ;;
esac

# Ensure that Python 3.x is installed.
if [[ "$(python -V)" != "Python 3."* ]]; then
    echo "Python v3.x not found.  Install the latest stable version from: https://www.python.org/"
    exit 1
fi

# Install/update package dependencies.
echo "Installing/updating pyinstaller and colorama packages..."
pip install -U pyinstaller colorama
echo

# Prompt for the version to release.
echo -n "Enter the version to release, using format 'vX.X.X': "
read -r version

# Ensure that entered version fits required format.
if [[ ! $version =~ ^v[0-9]\.[0-9]\.[0-9]$ ]]; then
   echo "Error: version string does not match format vX.X.X!"
   exit 1
fi

# Verify that version is correct.
echo -n "Version will be set to '${version}'.  Is this correct? (y/n): "
read -r yn
echo

if [[ $yn != "y" ]]; then
   echo "Build cancelled."
   exit 1
fi

# Reset any local changes made to globals.py from a previous run.
git checkout src/ssh_audit/globals.py 2> /dev/null

# Update the man page.
./add_builtin_man_page.sh
retval=$?
if [[ ${retval} != 0 ]]; then
    echo "Failed to run ./update_windows_man_page.sh"
    exit 1
fi

# Do all operations from this point from the main source directory.
pushd src/ssh_audit || exit > /dev/null

# Delete the existing VERSION variable and add the value that the user entered, above.
sed -i '/^VERSION/d' globals.py
echo "VERSION = '$version'" >> globals.py

# Delete cached files if they exist from a prior run.
rm -rf dist/ build/ ssh-audit.spec

# Create a hard link from ssh_audit.py to ssh-audit.py.
if [[ ! -f ssh-audit.py ]]; then
    ln ssh_audit.py ssh-audit.py
fi

echo -e "\nRunning pyinstaller...\n"
pyinstaller -F --icon ../../windows_icon.ico ssh-audit.py

if [[ -f dist/ssh-audit.exe ]]; then
    echo -e "\nExecutable created in $(pwd)/dist/ssh-audit.exe\n"
else
    echo -e "\nFAILED to create $(pwd)/dist/ssh-audit.exe!\n"
    exit 1
fi

# Ensure that the version string doesn't have '-dev' in it.
dist/ssh-audit.exe | grep -E 'ssh-audit.exe v.+\-dev' > /dev/null
retval=$?
if [[ ${retval} == 0 ]]; then
    echo -e "\nError: executable's version number includes '-dev'."
    exit 1
fi

# Remove the cache files created during the build process, along with the link we created, above.
rm -rf build/ ssh-audit.spec ssh-audit.py

# Reset the changes we made to globals.py.
git checkout globals.py 2> /dev/null

popd || exit > /dev/null
exit 0
