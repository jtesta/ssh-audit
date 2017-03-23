#!/bin/sh
_cdir=$(cd -- "$(dirname "$0")" && pwd)
type mypy > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "err: mypy (Optional Static Typing for Python) not found."
	exit 1
fi
_htmldir="${_cdir}/../html/mypy-py3"
mkdir -p "${_htmldir}"
env MYPYPATH="${_cdir}/stubs/" mypy \
--python-version 3.5 \
--show-error-context \
--config-file "${_cdir}/mypy.ini" \
--html-report "${_htmldir}" "${_cdir}/../ssh-audit.py"
