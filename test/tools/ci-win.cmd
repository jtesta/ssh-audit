@ECHO OFF

IF "%PYTHON%" == "" (
	ECHO PYTHON environment variable not set
	EXIT 1
)
SET PATH=%PYTHON%;%PYTHON%\\Scripts;%PATH%"
FOR /F %%i IN ('python -c "import platform; print(platform.python_version());"') DO (
	SET PYTHON_VERSION=%%i
)
SET PYTHON_VERSION_MAJOR=%PYTHON_VERSION:~0,1%
IF "%PYTHON_VERSION:~3,1%" == "." (
	SET PYTHON_VERSION_MINOR=%PYTHON_VERSION:~2,1%
) ELSE (
	SET PYTHON_VERSION_MINOR=%PYTHON_VERSION:~2,2%
)
FOR /F %%i IN ('python -c "import struct; print(struct.calcsize(\"P\")*8)"') DO (
	SET PYTHON_ARCH=%%i
)
CALL :devenv

IF /I "%1"=="" (
	SET target=test
) ELSE (
	SET target=%1
)

echo [CI] TARGET=%target%
GOTO %target%

:devenv
SET WIN_SDK_ROOT=C:\Program Files\Microsoft SDKs\Windows
SET VS2015_ROOT=C:\Program Files (x86)\Microsoft Visual Studio 14.0
IF %PYTHON_VERSION_MAJOR% == 2 (
	SET WINDOWS_SDK_VERSION="v7.0"
) ELSE IF %PYTHON_VERSION_MAJOR% == 3 (
	IF %PYTHON_VERSION_MAJOR% LEQ 4 (
		SET WINDOWS_SDK_VERSION="v7.1"
	) ELSE (
		SET WINDOWS_SDK_VERSION="2015"
	)
) ELSE (
	ECHO Unsupported Python version: "%PYTHON_VERSION%"
	EXIT 1
)
SETLOCAL ENABLEDELAYEDEXPANSION
IF %PYTHON_ARCH% == 32 (SET PYTHON_ARCHX=x86) ELSE (SET PYTHON_ARCHX=x64)
IF %WINDOWS_SDK_VERSION% == "2015" (
	"%VS2015_ROOT%\VC\vcvarsall.bat" %PYTHON_ARCHX%
) ELSE (
	SET DISTUTILS_USE_SDK=1
	SET MSSdk=1
	"%WIN_SDK_ROOT%\%WINDOWS_SDK_VERSION%\Setup\WindowsSdkVer.exe" -q -version:%WINDOWS_SDK_VERSION%
	"%WIN_SDK_ROOT%\%WINDOWS_SDK_VERSION%\Bin\SetEnv.cmd" /%PYTHON_ARCHX% /release
)
GOTO :eof

:install
pip install --user --upgrade pip virtualenv
SET VENV_DIR=.venv\%PYTHON_VERSION%
rmdir /s /q %VENV_DIR% > nul 2>nul
mkdir .venv > nul 2>nul
IF "%PYTHON_VERSION_MAJOR%%PYTHON_VERSION_MINOR%" == "26" (
	python -c "import virtualenv; virtualenv.main();" %VENV_DIR%
) ELSE (
	python -m virtualenv %VENV_DIR%
)
CALL %VENV_DIR%\Scripts\activate
python -V
pip install tox
deactivate
GOTO :eof

:install_deps
SET LXML_FILE=
SET LXML_URL=
IF %PYTHON_VERSION_MAJOR% == 3 (
	IF %PYTHON_VERSION_MINOR% == 3 (
		IF %PYTHON_ARCH% == 32 (
			SET LXML_FILE=lxml-3.7.3.win32-py3.3.exe
			SET LXML_URL=https://pypi.python.org/packages/66/fd/b82a54e7a15e91184efeef4b659379d0581a73cf78239d70feb0f0877841/lxml-3.7.3.win32-py3.3.exe
		) ELSE (
			SET LXML_FILE=lxml-3.7.3.win-amd64-py3.3.exe
			SET LXML_URL=https://pypi.python.org/packages/dc/bc/4742b84793fa1fd991b5d2c6f2e5d32695659d6cfedf5c66aef9274a8723/lxml-3.7.3.win-amd64-py3.3.exe
		)
	) ELSE IF %PYTHON_VERSION_MINOR% == 4 (
		IF %PYTHON_ARCH% == 32 (
			SET LXML_FILE=lxml-3.7.3.win32-py3.4.exe
			SET LXML_URL=https://pypi.python.org/packages/88/33/265459d68d465ddc707621e6471989f5c2cb0d43f230f516800ffd629af7/lxml-3.7.3.win32-py3.4.exe
		) ELSE (
			SET LXML_FILE=lxml-3.7.3.win-amd64-py3.4.exe
			SET LXML_URL=https://pypi.python.org/packages/2d/65/e47db7f36a69a1b59b4f661e42d699d6c43e663b8fd91035e6f7681d017e/lxml-3.7.3.win-amd64-py3.4.exe
		)
	)
)
IF NOT "%LXML_FILE%" == "" (
	CALL :download %LXML_URL% .downloads\%LXML_FILE%
	easy_install --user .downloads\%LXML_FILE%
)
GOTO :eof

:test
	SET VENV_DIR=.venv\%PYTHON_VERSION%
	CALL %VENV_DIR%\Scripts\activate
	IF "%TOXENV%" == "" (
		SET TOXENV=py%PYTHON_VERSION_MAJOR%%PYTHON_VERSION_MINOR%
	)
	IF "%PYTHON_VERSION_MAJOR%%PYTHON_VERSION_MINOR%" == "26" (
		SET TOX=python -c "from tox import cmdline; cmdline()"
	) ELSE (
		SET TOX=python -m tox
	)
	IF %PYTHON_VERSION_MAJOR% == 3 (
		IF %PYTHON_VERSION_MINOR% LEQ 4 (
			:: Python 3.3 and 3.4 does not support typed-ast (mypy dependency)
			%TOX% --sitepackages -e %TOXENV%-test,%TOXENV%-lint,cov || EXIT 1
		) ELSE (
			%TOX% --sitepackages -e %TOXENV%-test,%TOXENV%-type,%TOXENV%-lint,cov || EXIT 1
		)
	) ELSE (
		%TOX% --sitepackages -e %TOXENV%-test,%TOXENV%-lint,cov || EXIT 1
	)
GOTO :eof

:download
IF NOT EXIST %2 (
	IF NOT EXIST .downloads\ mkdir .downloads
	powershell -command "(new-object net.webclient).DownloadFile('%1', '%2')" || EXIT 1

)
GOTO :eof
