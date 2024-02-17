#!/usr/bin/env bash

#
#   The MIT License (MIT)
#
#   Copyright (C) 2021-2024 Joe Testa (jtesta@positronsecurity.com)
#   Copyright (C) 2021 Adam Russell (<adam[at]thecliguy[dot]co[dot]uk>)
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
# add_builtin_man_page.sh
#
# PURPOSE
#   Since some platforms lack a manual reader it's necessary to provide an
#   alternative means of reading the man page.
#
#   This script should be run as part of the ssh-audit packaging process for
#   Docker, PyPI, Snap, and Windows. It populates the 'BUILTIN_MAN_PAGE'
#   variable in 'globals.py' with the contents of the man page. Users can then
#   see the man page with "ssh-audit [--manual|-m]".
#
#   Linux or Cygwin is required to run this script.
#
# USAGE
#   add_builtin_man_page.sh [-m <path-to-man-page>] [-g <path-to-globals.py>]
#
################################################################################

usage() {
    echo >&2 "Usage: $0 [-m <path-to-man-page>] [-g <path-to-globals.py>] [-h]"
    echo >&2 "  -m    Specify an alternate man page path (default: ./ssh-audit.1)"
    echo >&2 "  -g    Specify an alternate globals.py path (default: ./src/ssh_audit/globals.py)"
    echo >&2 "  -h    This help message"
}

PLATFORM="$(uname -s)"

# This script is intended for use on Linux and Cygwin only.
case "${PLATFORM}" in
  Linux | CYGWIN*) ;;
  *)
    echo "Platform not supported: ${PLATFORM}"
    exit 1
    ;;
esac

MAN_PAGE=./ssh-audit.1
GLOBALS_PY=./src/ssh_audit/globals.py

while getopts "m: g: h" OPTION; do
    case "${OPTION}" in
        m)
            MAN_PAGE="${OPTARG}"
            ;;
        g)
            GLOBALS_PY="${OPTARG}"
            ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo >&2 "Invalid parameter(s) provided"
            usage
            exit 1
            ;;
    esac
done

# Check that the specified files exist.
[[ -f "$MAN_PAGE" ]] || { echo >&2 "man page file not found: $MAN_PAGE"; exit 1; }
[[ -f "${GLOBALS_PY}" ]] || { echo >&2 "globals.py file not found: ${GLOBALS_PY}"; exit 1; }

# Check that the 'ul' (do underlining) binary exists.
if [[ "${PLATFORM}" == "Linux" ]]; then
    command -v ul >/dev/null 2>&1 || { echo >&2 "ul not found."; exit 1; }
fi

# Check that the 'sed' (stream editor) binary exists.
command -v sed >/dev/null 2>&1 || { echo >&2 "sed not found."; exit 1; }

# Reset the globals.py file, in case it was modified from a prior run.
git checkout "${GLOBALS_PY}" > /dev/null 2>&1

# Remove the Windows man page placeholder from 'globals.py'.
sed -i '/^BUILTIN_MAN_PAGE/d' "${GLOBALS_PY}"

echo "Processing man page at ${MAN_PAGE} and placing output into ${GLOBALS_PY}..."

# Append the man page content to 'globals.py'.
#   * man outputs a backspace-overwrite sequence rather than an ANSI escape
#     sequence.
#   * 'MAN_KEEP_FORMATTING' preserves the backspace-overwrite sequence when
#     redirected to a file or a pipe.
#   * sed converts unicode hyphens into an ASCI equivalent.
#   * The 'ul' command converts the backspace-overwrite sequence to an ANSI
#     escape sequence. Not required under Cygwin because man outputs ANSI escape
#     codes automatically.

echo BUILTIN_MAN_PAGE = '"""' >> "${GLOBALS_PY}"

if [[ "${PLATFORM}" == CYGWIN* ]]; then
    MANWIDTH=80 MAN_KEEP_FORMATTING=1 man "${MAN_PAGE}" | sed $'s/\u2010/-/g' >> "${GLOBALS_PY}"
else
    MANWIDTH=80 MAN_KEEP_FORMATTING=1 man "${MAN_PAGE}" | ul | sed $'s/\u2010/-/g' >> "${GLOBALS_PY}"
fi

echo '"""' >> "${GLOBALS_PY}"

echo "Done."
exit 0
