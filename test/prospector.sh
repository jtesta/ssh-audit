#!/bin/sh
_cdir=$(cd -- "$(dirname "$0")" && pwd)
type prospector > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "err: prospector (Python Static Analysis) not found."
	exit 1
fi
prospector --profile-path "${_cdir}" -P prospector "${_cdir}/../ssh-audit.py"
