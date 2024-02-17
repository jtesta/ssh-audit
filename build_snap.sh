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
# build_snap.sh
#
# Builds a Snap package.
################################################################################


# Pre-requisites
sudo apt install -y make
sudo snap install snapcraft --classic
sudo snap install review-tools lxd

# Initialize LXD.
sudo lxd init --auto

# Reset the filesystem from any previous runs.
rm -rf parts/ prime/ snap/ stage/ build/ dist/ src/*.egg-info/ ssh-audit*.snap
git checkout snapcraft.yaml 2> /dev/null
git checkout src/ssh_audit/globals.py 2> /dev/null

# Add the built-in manual page.
./add_builtin_man_page.sh

# Get the version from the globals.py file.
version=$(grep VERSION src/ssh_audit/globals.py | awk 'BEGIN {FS="="} ; {print $2}' | tr -d '[:space:]')

# Strip the quotes around the version (along with the initial 'v' character) and append "-1" to make the default Snap version (i.e.: 'v2.5.0' => '2.5.0-1')
default_snap_version="${version:2:-1}-1"
echo -e -n "\nEnter Snap package version [default: ${default_snap_version}]: "
read -r snap_version

# If no version was specified, use the default version.
if [[ $snap_version == '' ]]; then
    snap_version=$default_snap_version
    echo -e "Using default snap version: ${snap_version}\n"
fi

# Ensure that the snap version fits the format of X.X.X-X.
if [[ ! $snap_version =~ ^[0-9]\.[0-9]\.[0-9]\-[0-9]$ ]]; then
   echo "Error: version string does not match format X.X.X-X!"
   exit 1
fi

# Append the version field to the end of the file.  Not pretty, but it works.
echo -e "\nversion: '${snap_version}'" >> snapcraft.yaml

# Set the SNAP_PACKAGE variable to True so that file permission errors give more user-friendly 
sed -i 's/SNAP_PACKAGE = False/SNAP_PACKAGE = True/' src/ssh_audit/globals.py

snapcraft --use-lxd && echo -e "\nDone.\n"
