#!/bin/bash

################################################################################
# update_windows_man_page
#
# PURPOSE
#   Since Windows lacks a manual reader it's necessary to provide an alternative
#   means of reading the man page. 
#
#   This script should be run as part of the ssh-audit packaging process for 
#   Windows. It populates the 'WINDOWS_MAN_PAGE' variable in 'globals.py' with 
#   the contents of the man page. Windows users can then print the content of 
#   'WINDOWS_MAN_PAGE' by invoking ssh-audit with the manual parameters 
#   (--manual / -m).
#
# USAGE
#   update_windows_man_page.sh -m <path-to-man-page> -g <path-to-globals.py>
#
################################################################################

while getopts "m: g:" OPTION
do
    case "$OPTION" in
        m)
            MAN_PAGE="$OPTARG"
            ;;
        g)
            GLOBALS_PY="$OPTARG"
            ;;
        *)
            echo >&2 "Invalid parameter(s) provided"
            exit 1
            ;;
    esac
done

if [[ -z "$MAN_PAGE" || -z "$GLOBALS_PY" ]]; then
    echo >&2 "Missing parameter(s)."
    exit 1
fi

# Check that the specified files exist.
[ -f "$MAN_PAGE" ] || { echo >&2 "man page file not found: $MAN_PAGE"; exit 1; }
[ -f "$GLOBALS_PY" ] || { echo >&2 "globals.py file not found: $GLOBALS_PY"; exit 1; }

# Check that the 'ul' (do underlining) binary exists.
command -v ul >/dev/null 2>&1 || { echo >&2 "ul not found."; exit 1; }

# Remove the Windows man page placeholder from 'globals.py'.
sed -i '/^WINDOWS_MAN_PAGE/d' "$GLOBALS_PY"

# Append the man page content to 'globals.py'.
#   * man outputs a backspace-overwrite sequence rather than an ANSI escape 
#     sequence.
#   * 'MAN_KEEP_FORMATTING' preserves the backspace-overwrite sequence when 
#     redirected to a file or a pipe.
#   * The 'ul' command converts the backspace-overwrite sequence to an ANSI escape 
#     sequence.
echo WINDOWS_MAN_PAGE = '"""' >> "$GLOBALS_PY"
MANWIDTH=80 MAN_KEEP_FORMATTING=1 man "$MAN_PAGE" | ul >> "$GLOBALS_PY"
echo '"""' >> "$GLOBALS_PY"