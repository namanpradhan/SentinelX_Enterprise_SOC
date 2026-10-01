@echo off
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
  echo Create the environment first with START_SENTINELX.bat
  pause
  exit /b 1
)
call "venv\Scripts\activate.bat"
set "SENTINELX_BASE=http://127.0.0.1:8000"
set "DISABLE_SQLALCHEMY_CEXT_RUNTIME=1"
echo Checking SQLAlchemy compatibility...
python -c "import os; os.environ['DISABLE_SQLALCHEMY_CEXT_RUNTIME']='1'; import sqlalchemy; from sqlalchemy.util import _has_cy; print(sqlalchemy.__version__, 'C extensions enabled:', _has_cy.HAS_CYEXTENSION); assert not _has_cy.HAS_CYEXTENSION" || goto :fail
echo Running API smoke test...
python tests\smoke_test.py || goto :fail
echo Running full acceptance contract test...
python tests\full_acceptance.py || goto :fail
where node >nul 2>&1
if errorlevel 1 goto :skip_node_check
echo Validating frontend JavaScript...
node --check frontend\app.js || goto :fail
:skip_node_check
echo.
echo SENTINELX v4.2.13 VALIDATION PASS
pause
exit /b 0
:fail
echo.
echo SENTINELX VALIDATION FAILED. Review the error above.
pause
exit /b 1
