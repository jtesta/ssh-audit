#!/bin/sh
_cdir=$(cd -- "$(dirname "$0")" && pwd)
type py.test > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "err: py.test (Python testing framework) not found."
	exit 1
fi
cd -- "${_cdir}/.."
mkdir -p html
py.test -v --cov-report=html:html/coverage --cov=ssh-audit test
