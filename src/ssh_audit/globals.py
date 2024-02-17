"""
   The MIT License (MIT)

   Copyright (C) 2017-2023 Joe Testa (jtesta@positronsecurity.com)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
# The version to display.
VERSION = 'v3.2.0-dev'

# SSH software to impersonate
SSH_HEADER = 'SSH-{0}-OpenSSH_8.2'

# The URL to the Github issues tracker.
GITHUB_ISSUES_URL = 'https://github.com/jtesta/ssh-audit/issues'

# The man page.  Only filled in on Docker, PyPI, Snap, and Windows builds.
BUILTIN_MAN_PAGE = ''

# True when installed from a Snap package, otherwise False.
SNAP_PACKAGE = False

# Error message when installed as a Snap package and a file access fails.
SNAP_PERMISSIONS_ERROR = 'Error while accessing file.  It appears that ssh-audit was installed as a Snap package.  In that case, there are two options:  1.) only try to read & write files in the $HOME/snap/ssh-audit/common/ directory, or 2.) grant permissions to read & write files in $HOME using the following command: "sudo snap connect ssh-audit:home :home"'
