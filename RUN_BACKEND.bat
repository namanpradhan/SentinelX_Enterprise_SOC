@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "ROOT=%~dp0"
set "PY=%ROOT%venv\Scripts\python.exe"
set "SENTINELX_DEMO_MODE=0"
set "DISABLE_SQLALCHEMY_CEXT_RUNTIME=1"
if not exist "%PY%" py -3 -m venv "%ROOT%venv"
call "%ROOT%venv\Scripts\activate.bat"
"%PY%" -m pip install -r "%ROOT%backend\requirements.txt" || exit /b 1
"%PY%" -c "import os; os.environ['DISABLE_SQLALCHEMY_CEXT_RUNTIME']='1'; import sqlalchemy; from sqlalchemy.util import _has_cy; assert not _has_cy.HAS_CYEXTENSION; print('SQLAlchemy', sqlalchemy.__version__, 'OK')" || exit /b 1
cd /d "%ROOT%backend"
"%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
