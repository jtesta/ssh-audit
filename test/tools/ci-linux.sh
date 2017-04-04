#!/bin/sh

CI_VERBOSE=1

ci_err_msg() { echo "[ci] error: $1" >&2; }
ci_err() { [ $1 -ne 0 ] && ci_err_msg "$2" && exit 1; }
ci_is_osx() { [ X"$(uname -s)" == X"Darwin" ]; }

ci_get_pypy_ver() {
	local _v="$1"
	[ -z "$_v" ] && _v=$(python -V 2>&1)
	case "$_v" in
		pypy-*|pypy2-*|pypy3-*|pypy3.*) echo "$_v"; return 0 ;;
		pypy|pypy2|pypy3) echo "$_v-unknown"; return 0 ;;
	esac
	echo "$_v" | tail -1 | grep -qi pypy
	if [ $? -eq 0 ]; then
		local _py_ver=$(echo "$_v" | head -1 | cut -d ' ' -sf 2)
		local _pypy_ver=$(echo "$_v" | tail -1 | cut -d ' ' -sf 2)
		[ -z "${_py_ver} " ] && _py_ver=2
		[ -z "${_pypy_ver}" ] && _pypy_ver="unknown"
		case "${_py_ver}" in
			2*) echo "pypy-${_pypy_ver}" ;;
			3.3*) echo "pypy3.3-${_pypy_ver}" ;;
			3.5*) echo "pypy3.5-${_pypy_ver}" ;;
			*) echo "pypy3-${_pypy_ver}" ;;
		esac
		return 0
	else
		return 1
	fi
}

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
		*)
			[ -z "$1" ] && set -- "$(python -V 2>&1)"
			_v=$(ci_get_pypy_ver "$1")
			[ -z "$_v" ] && _v=$(echo "$_v" | head -1 | cut -d ' ' -sf 2)
			;;
	esac
	echo "${_v}"
	return 0
}

ci_get_py_env() {
	[ -z "$1" ] && set -- "$(python -V 2>&1)"
	case "$(ci_get_pypy_ver "$1")" in
		pypy|pypy2|pypy-*|pypy2-*) echo "pypy" ;;
		pypy3|pypy3*) echo "pypy3" ;;
		*)
			local _v=$(echo "$1" | head -1 | sed -e 's/[^0-9]//g' | cut -c1-2)
			echo "py${_v}"
	esac
	return 0
}

ci_pyenv_setup() {
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] install pyenv"
	rm -rf ~/.pyenv
	git clone --depth 1 https://github.com/yyuu/pyenv.git ~/.pyenv
	PYENV_ROOT=$HOME/.pyenv
	PATH="$HOME/.pyenv/bin:$PATH"
	eval "$(pyenv init -)"
	ci_err $? "failed to init pyenv"
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] pyenv init: $(pyenv -v 2>&1)"
	return 0
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
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] pyenv install: ${_py_env}/${_py_ver}"
	[ -z "${PYENV_ROOT}" ] && PYENV_ROOT="$HOME/.pyenv"
	local _py_ver_dir="${PYENV_ROOT}/versions/${_py_ver}"
	local _py_ver_cached_dir="${CI_PYENV_CACHE}/${_py_ver}"
	if [ -z "${_nocache}" ]; then
		if [ ! -d "${_py_ver_dir}" ]; then
			if [ -d "${_py_ver_cached_dir}" ]; then
				[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] pyenv reuse ${_py_ver}"
				ln -s "${_py_ver_cached_dir}" "${_py_ver_dir}"
			fi
		fi
	fi
	if [ ! -d "${_py_ver_dir}" ]; then
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
	return 0
}

ci_pyenv_use() {
	type pyenv > /dev/null 2>&1
	ci_err $? "pyenv not found"
	local _py_ver=$(ci_get_py_ver "$1")
	pyenv shell "${_py_ver}"
	ci_err $? "pyenv could not use ${_py_ver}"
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] pyenv using python: $(python -V 2>&1)"
	return 0
}

ci_pip_setup() {
	local _py_ver=$(ci_get_py_ver "$1")
	local _py_env=$(ci_get_py_env "${_py_ver}")
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] install pip/venv for ${_py_env}/${_py_ver}"
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
	ci_err $? "failed to upgrade pip/venv" || return 0
}

ci_venv_setup() {
	local _py_ver=$(ci_get_py_ver "$1")
	local _py_env=$(ci_get_py_env "${_py_ver}")
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] create venv for ${_py_env}/${_py_ver}"
	local VENV_DIR=~/.venv/${_py_ver}
	mkdir -p -- ~/.venv
	rm -rf -- "${VENV_DIR}"
	if [ X"${_py_env}" == X"py26" ]; then
	  python -c 'import virtualenv; virtualenv.main();' "${VENV_DIR}"
	else
	  python -m virtualenv "${VENV_DIR}"
	fi
	ci_err $? "failed to create venv" || return 0
}

ci_venv_use() {
	local _py_ver=$(ci_get_py_ver "$1")
	local _py_env=$(ci_get_py_env "${_py_ver}")
	local VENV_DIR=~/.venv/${_py_ver}
	. "${VENV_DIR}/bin/activate"
	ci_err $? "could not actiavte virtualenv"
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] venv using python: $(python -V 2>&1)"
	return 0
}

ci_get_filedir() {
	local _sdir=$(cd -- "$(dirname "$0")" && pwd)
	local _pdir=$(pwd)
	if [ -z "${_pdir##${_sdir}*}" ]; then
		_sdir="${_pdir}"
	fi
	local _first=1
	while [ X"${_sdir}" != X"/" ]; do
		if [ ${_first} -eq 1 ]; then
			_first=0
			local _f=$(find "${_sdir}" -name "$1" | head -1)
			if [ -n "${_f}" ]; then
				echo $(dirname -- "${_f}")
				return 0
			fi
		else
			_f=$(find "${_sdir}" -mindepth 1 -maxdepth 1 -name "$1" | head -1)
		fi
		[ -n "${_f}" ] && echo "${_sdir}" && return 0
		_sdir=$(cd -- "${_sdir}/.." && pwd)
	done
	return 1
}

ci_sq_ensure_java() {
	type java >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		ci_err_msg "java not found"
		return 1
	fi
	local _java_ver=$(java -version 2>&1 | head -1 | sed -e 's/[^0-9\._]//g')
	if [ -z "${_java_ver##1.8*}" ]; then
		return 0
	fi
	ci_err_msg "unsupported java version: ${_java_ver}"
	return 1
}

ci_sq_ensure_scanner() {
	local _cli_version="3.0.0.702"
	local _cli_basedir="$HOME/.bin"
	local _cli_postfix=""
	case "$(uname -s)" in
		Linux)
			[ X"$(uname -m)" = X"x86_64" ] && _cli_postfix="-linux"
			[ X"$(uname -m)" = X"amd64" ] && _cli_postfix="-linux"
			;;
		Darwin) _cli_postfix="-macosx" ;;
	esac
	if [ X"${_cli_postfix}" = X"" ]; then
		ci_sq_ensure_java || return 1
	fi
	if [ X"${SONAR_SCANNER_PATH}" != X"" ]; then
		if [ -e "${SONAR_SCANNER_PATH}" ]; then
			return 0
		fi
	fi
	local _cli_fname="sonar-scanner-cli-${_cli_version}${_cli_postfix}"
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] ensure scanner ${_cli_fname}"
	local _cli_dname="sonar-scanner-${_cli_version}${_cli_postfix}"
	local _cli_archive="${_cli_basedir}/${_cli_fname}.zip"
	local _cli_dir="${_cli_basedir}/${_cli_dname}"
	local _cli_url="https://sonarsource.bintray.com/Distribution/sonar-scanner-cli/${_cli_fname}.zip"
	if [ ! -e "${_cli_archive}" ]; then
		mkdir -p -- "${_cli_basedir}" > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			ci_err_msg "could not create ${_cli_basedir}"
			return 1
		fi
		[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] downloading ${_cli_fname}"
		curl -kL -o "${_cli_archive}" "${_cli_url}"
		[ $? -ne 0 ] && ci_err_msg "download failed" && return 1
		[ ! -e "${_cli_archive}" ] && ci_err_msg "download verify" && return 1
	fi
	if [ ! -d "${_cli_dir}" ]; then
		[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] extracting ${_cli_fname}"
		unzip -od "${_cli_basedir}" "${_cli_archive}"
		[ $? -ne 0 ] && ci_err_msg "extract failed" && return 1
		[ ! -d "${_cli_dir}" ] && ci_err_msg "extract verify" && return 1
	fi
	if [ ! -e "${_cli_dir}/bin/sonar-scanner" ]; then
		ci_err_msg "sonar-scanner binary not found."
		return 1
	fi
	SONAR_SCANNER_PATH="${_cli_dir}/bin/sonar-scanner"
	return 0
}

ci_sq_run() {
	if [ X"${SONAR_SCANNER_PATH}" = X"" ]; then
		ci_err_msg "environment variable SONAR_SCANNER_PATH not set"
		return 1
	fi
	if [ X"${SONAR_HOST_URL}" = X"" ]; then
		ci_err_msg "environment variable SONAR_HOST_URL not set"
		return 1
	fi
	if [ X"${SONAR_AUTH_TOKEN}" = X"" ]; then
		ci_err_msg "environment variable SONAR_AUTH_TOKEN not set"
		return 1
	fi
	local _pdir=$(ci_get_filedir "ssh-audit.py")
	if [ -z "${_pdir}" ]; then
		ci_err_msg "failed to find project directory"
		return 1
	fi
	local _odir=$(pwd)
	cd -- "${_pdir}"
	local _branch=$(git name-rev --name-only HEAD | cut -d '~' -f 1)
	case "${_branch}" in
		master) ;;
		develop) ;;
		*) ci_err_msg "unknown branch: ${_branch}"; return 1 ;;
	esac
	local _junit=$(cd -- "${_pdir}" && ls -1 reports/junit.*.xml | sort -r | head -1)
	if [ X"${_junit}" = X"" ]; then
		ci_err_msg "no junit.xml found"
		return 1
	fi
	local _project_ver=$(grep VERSION ssh-audit.py | head -1 | cut -d "'" -f 2)
	if [ -z "${_project_ver}" ]; then
		ci_err_msg "failed to get project version"
		return 1
	fi
	if [ -z "${_project_ver##*dev}" ]; then
		local _git_rc=$(git rev-list --count `git rev-parse HEAD`)
		_project_ver="${_project_ver}.${_git_rc}"
	fi
	[ ${CI_VERBOSE} -gt 0 ] && echo "[ci] run sonar-scanner for ${_project_ver}"
	"${SONAR_SCANNER_PATH}" -X \
		-Dsonar.projectKey=arthepsy-github:ssh-audit \
		-Dsonar.sources=ssh-audit.py \
		-Dsonar.tests=test \
		-Dsonar.test.inclusions=test/*.py \
		-Dsonar.host.url="${SONAR_HOST_URL}" \
		-Dsonar.projectName=ssh-audit \
		-Dsonar.projectVersion="${_project_ver}" \
		-Dsonar.branch="${_branch}" \
		-Dsonar.python.coverage.overallReportPath=reports/coverage.xml \
		-Dsonar.python.xunit.reportPath="${_junit}" \
		-Dsonar.organization=arthepsy-github \
		-Dsonar.login="${SONAR_AUTH_TOKEN}"
	cd -- "${_odir}"
	return 0
}

ci_run_wrapped() {
	local _versions=$(echo "${PY_VER}" | sed -e 's/,/ /g')
	[ -z "${_versions}" ] && eval "$1"
	for _i in ${_versions}; do
		local _v=$(echo "$_i" | cut -d '/' -f 1)
		local _o=$(echo "$_i" | cut -d '/' -sf 2)
		[ -z "${_o}" ] && _o="${PY_ORIGIN}"
		eval "$1" "${_v}" "${_o}" || return 1
	done
	return 0
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
			ci_pyenv_install "${_py_ver}" || return 1
			ci_pyenv_use "${_py_ver}" || return 1
			;;
	esac
	ci_pip_setup "${_py_ver}" || return 1
	ci_venv_setup "${_py_ver}" || return 1
	return 0
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
	ci_run_wrapped "ci_step_before_install_wrapped" || return 1
	if [ "${CI_PYENV_SETUP}" -eq 1 ]; then
		pyenv shell --unset
		[ ${CI_VERBOSE} -gt 0 ] && pyenv versions
	fi
	return 0
}

ci_step_install_wrapped() {
	local _py_ver="$1"
	ci_venv_use "${_py_ver}"
	pip install -U tox coveralls codecov
	ci_err $? "failed to install dependencies" || return 0
}

ci_step_script_wrapped() {
	local _py_ver="$1"
	local _py_ori="$2"
	local _py_env=$(ci_get_py_env "${_py_ver}")
	ci_venv_use "${_py_ver}" || return 1
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
	ci_err $? "tox failed" || return 0
}

ci_step_success_wrapped() {
	local _py_ver="$1"
	local _py_ori="$2"
	if [ X"${SQ}" = X"1" ]; then
		ci_sq_ensure_scanner && ci_sq_run
	fi
	ci_venv_use "${_py_ver}" || return 1
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
