#!/bin/sh
_cdir=$(cd -- "$(dirname "$0")" && pwd)
type mypy > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "err: mypy (Optional Static Typing for Python) not found."
	exit 1
fi
_htmldir="${_cdir}/../html/mypy-py2"
mkdir -p "${_htmldir}"
mypy --python-version 2.7 --config-file "${_cdir}/mypy.ini" --html-report "${_htmldir}" "${_cdir}/../ssh-audit.py"
