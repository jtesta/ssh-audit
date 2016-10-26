#!/bin/sh
_cdir=$(cd -- "$(dirname "$0")" && pwd)
type prospector > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "err: prospector (Python Static Analysis) not found."
	exit 1
fi
if [ X"$1" == X"" ]; then
	_file="${_cdir}/../ssh-audit.py"
else
	_file="$1"
fi
prospector -E --profile-path "${_cdir}" -P prospector "${_file}"
