#!/bin/sh

CI_VERBOSE=1

ci_err() { [ $1 -ne 0 ] && echo "err: $2" >&2 && exit 1; }
ci_is_osx() { [ X"$(uname -s)" == X"Darwin" ]; }

ci_get_py_ver() {
	local _v
	case "$1" in
		py26) _v=2.6.9 ;;
		py27) _v=2.7.13 ;;
		py33) _v=3.3.6 ;;
		py34) _v=3.4.6 ;;
		py35) _v=3.5.3 ;;
		py36) _v=3.6.1 ;;
		py37) _v=3.7-dev ;;
		pypy) ci_is_osx && _v=pypy2-5.7.0 || _v=pypy-portable-5.7.0 ;;
		pypy3) ci_is_osx && _v=pypy3.3-5.5-alpha || _v=pypy3-portable-5.7.0 ;;
		*) [ -z "$1" ] && _v=$(python -V 2>&1 | cut -d ' ' -f 2) || _v="$1" ;;
	esac
	echo "${_v}"
}

ci_get_py_env() {
	if [ -z "$1" ]; then
		set -- "$(python -V 2>&1)"
	fi
	case "$1" in
		pypy|pypy2|pypy-*|pypy2-*) echo "pypy" ;;
		pypy3|pypy3*) echo "pypy3" ;;
		*)
			local _v=$(echo "$1" | head -1 | sed -e 's/[^0-9]//g' | cut -c1-2;)
			echo "$1" | tail -1 | grep -qi pypy
			if [ $? -eq 0 ]; then
				case "${_ver}" in
					2*) echo "pypy" ;;
					*) echo "pypy3" ;;
				esac
			else
				echo "py${_v}"
			fi
	esac
}

ci_pyenv_setup() {
	rm -rf ~/.pyenv
	git clone --depth 1 https://github.com/yyuu/pyenv.git ~/.pyenv
	PYENV_ROOT=$HOME/.pyenv
	PATH="$HOME/.pyenv/bin:$PATH"
	eval "$(pyenv init -)"
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] $(pyenv -v)"
}

ci_pyenv_install() {
	CI_PYENV_CACHE=~/.pyenv.cache
	type pyenv > /dev/null 2>&1
	ci_err $? "pyenv not found"
	local _py_ver=$(ci_get_py_ver "$1")
	local _py_env=$(ci_get_py_env "${_py_ver}")
	local _nocache
	case "${_py_env}" in
		py37) _nocache=1 ;;
	esac
	[ -z "${PYENV_ROOT}" ] && PYENV_ROOT="$HOME/.pyenv"
	local _py_ver_dir="${PYENV_ROOT}/versions/${_py_ver}"
	local _py_ver_cached_dir="${CI_PYENV_CACHE}/${_py_ver}"
	if [ -z "${_nocache}" ]; then
		if [ ! -d "${_py_ver_dir}" ]; then
			if [ -d "${_py_ver_cached_dir}" ]; then
				[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] using cached pyenv ${_py_ver}"
				ln -s "${_py_ver_cached_dir}" "${_py_ver_dir}"
			fi
		fi
	fi
	if [ ! -d "${_py_ver_dir}" ]; then
		[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] pyenv install ${_py_ver}"
		pyenv install -s "${_py_ver}"
		ci_err $? "pyenv failed to install ${_py_ver}"
		if [ -z "${_nocache}" ]; then
			[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] pyenv cache ${_py_ver}"
			rm -rf -- "${_py_ver_cached_dir}"
			mkdir -p -- "${CI_PYENV_CACHE}"
			mv "${_py_ver_dir}" "${_py_ver_cached_dir}"
			ln -s "${_py_ver_cached_dir}" "${_py_ver_dir}"
		fi
	fi
	pyenv rehash
}

ci_pyenv_use() {
	type pyenv > /dev/null 2>&1
	ci_err $? "pyenv not found"
	local _py_ver=$(ci_get_py_ver "$1")
	pyenv shell "${_py_ver}"
	ci_err $? "pyenv could not use ${_py_ver}"
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] using python: $(python -V 2>&1)"
}

ci_pip_setup() {
	local _py_ver=$(ci_get_py_ver "$1")
	local _py_env=$(ci_get_py_env "${_py_ver}")
	PIPOPT=$(python -c 'import sys; print("" if hasattr(sys, "real_prefix") else "--user")')
	if [ -z "${_py_env##py2*}" ]; then
		curl -O https://bootstrap.pypa.io/get-pip.py
		python get-pip.py ${PIPOPT}
		ci_err $? "failed to install pip"
	fi
	if [ X"${_py_env}" == X"py26" ]; then
	  python -c 'import pip; pip.main();' install ${PIPOPT} -U pip virtualenv
	else
	  python -m pip install ${PIPOPT} -U pip virtualenv
	fi
}

ci_venv_setup() {
	local _py_ver=$(ci_get_py_ver "$1")
	local _py_env=$(ci_get_py_env "${_py_ver}")
	local VENV_DIR=~/.venv/${_py_ver}
	mkdir -p -- ~/.venv
	rm -rf -- "${VENV_DIR}"
	if [ X"${_py_env}" == X"py26" ]; then
	  python -c 'import virtualenv; virtualenv.main();' "${VENV_DIR}"
	else
	  python -m virtualenv "${VENV_DIR}"
	fi
}

ci_venv_use() {
	local _py_ver=$(ci_get_py_ver "$1")
	local _py_env=$(ci_get_py_env "${_py_ver}")
	local VENV_DIR=~/.venv/${_py_ver}
	. "${VENV_DIR}/bin/activate"
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] using python: $(python -V 2>&1)"
}

ci_run_wrapped() {
	local _versions=$(echo "${PY_VER}" | sed -e 's/,/ /g')
	[ -z "${_versions}" ] && eval "$1"
	for _i in ${_versions}; do
		local _v=$(echo "$_i" | cut -d '/' -f 1)
		local _o=$(echo "$_i" | cut -d '/' -sf 2)
		[ -z "${_o}" ] && _o="${PY_ORIGIN}"
		eval "$1" "${_v}" "${_o}"
	done
}

ci_step_before_install_wrapped() {
	local _py_ver="$1"
	local _py_ori="$2"
	case "${_py_ori}" in
		pyenv)
			if [ "${CI_PYENV_SETUP}" -eq 0 ]; then
				ci_pyenv_setup
				CI_PYENV_SETUP=1
			fi
			ci_pyenv_install "${_py_ver}"
			ci_pyenv_use "${_py_ver}"
			;;
	esac
	ci_pip_setup "${_py_ver}"
	ci_venv_setup "${_py_ver}"
}

ci_step_before_install() {
	if ci_is_osx; then
		[ ${CI_VERBOSE} -gt 0 ] && sw_vers
		brew update || brew update
		brew install autoconf pkg-config openssl readline xz
		brew upgrade autoconf pkg-config openssl readline xz
		PY_ORIGIN=pyenv
	fi
	CI_PYENV_SETUP=0
	ci_run_wrapped "ci_step_before_install_wrapped"
	if [ "${CI_PYENV_SETUP}" -eq 1 ]; then
		pyenv shell --unset
		[ ${CI_VERBOSE} -gt 0 ] && pyenv versions
	fi
}

ci_step_install_wrapped() {
	local _py_ver="$1"
	ci_venv_use "${_py_ver}"
	pip install -U tox coveralls codecov
}

ci_step_script_wrapped() {
	local _py_ver="$1"
	local _py_ori="$2"
	local _py_env=$(ci_get_py_env "${_py_ver}")
	ci_venv_use "${_py_ver}"
	if [ -z "${_py_env##*py3*}" ]; then
		if [ -z "${_py_env##*pypy3*}" ]; then
			# NOTE: workaround for travis environment
			_pydir=$(dirname $(which python))
			ln -s -- "${_pydir}/python" "${_pydir}/pypy3"
			# NOTE: do not lint, as it hangs when flake8 is run
			# NOTE: do not type, as it can't install dependencies
			TOXENV=${_py_env}-test
		else
			TOXENV=${_py_env}-test,${_py_env}-type,${_py_env}-lint
		fi
	else
		# NOTE: do not type, as it isn't supported on py2x
		TOXENV=${_py_env}-test,${_py_env}-lint
	fi
	tox -e $TOXENV,cov
}

ci_step_success_wrapped() {
	local _py_ver="$1"
	local _py_ori="$2"
	ci_venv_use "${_py_ver}"
	coveralls
	codecov
}

ci_step_failure() { 
	cat .tox/log/*
	cat .tox/*/log/*
}

ci_step_install() { ci_run_wrapped "ci_step_install_wrapped"; }
ci_step_script() { ci_run_wrapped "ci_step_script_wrapped"; }
ci_step_success() { ci_run_wrapped "ci_step_success_wrapped"; }
