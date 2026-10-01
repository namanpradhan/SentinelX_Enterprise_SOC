$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot '.')).Path
$Backend = Join-Path $Root 'backend'
$Venv = Join-Path $Root 'venv'
$Py = Join-Path $Venv 'Scripts\python.exe'
$Port = 8000
$Url = "http://127.0.0.1:$Port/"

function Write-Stage($n,$msg){ Write-Host "[$n/5] $msg" -ForegroundColor Cyan }
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SENTINELX ENTERPRISE SOC v4.2.13" -ForegroundColor White
Write-Host "  One-click Windows launcher • FastAPI + SQLite" -ForegroundColor White
Write-Host "  DETECT > ANALYZE > RESPOND > PROTECT" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

try {
  if(-not (Test-Path $Py)){
    Write-Stage 1 "Creating Python virtual environment..."
    & py -3 -m venv $Venv
  } else { Write-Stage 1 "Python environment: READY" }
  if(-not (Test-Path $Py)){ throw "Python virtual environment could not be created." }

  Write-Stage 2 "Installing SentinelX dependencies..."
  & $Py -m pip install -r (Join-Path $Backend 'requirements.txt')

  Write-Stage 3 "Checking SQLAlchemy Windows compatibility..."
  $env:DISABLE_SQLALCHEMY_CEXT_RUNTIME = '1'
  $check = & $Py -c "import os; os.environ['DISABLE_SQLALCHEMY_CEXT']='1'; import sqlalchemy; from sqlalchemy.util import _has_cy; print(sqlalchemy.__version__, bool(_has_cy.HAS_CYEXTENSION))" 2>&1
  if($LASTEXITCODE -ne 0 -or ($check -match 'True')){
    Write-Host "Native SQLAlchemy extension unavailable to this Windows policy; installing pure-Python build..." -ForegroundColor Yellow
    & $Py -m pip uninstall -y SQLAlchemy
    & $Py -m pip install --no-binary SQLAlchemy "SQLAlchemy==2.0.54"
    $check = & $Py -c "import os; os.environ['DISABLE_SQLALCHEMY_CEXT']='1'; import sqlalchemy; from sqlalchemy.util import _has_cy; print(sqlalchemy.__version__, bool(_has_cy.HAS_CYEXTENSION))" 2>&1
  }
  if($LASTEXITCODE -ne 0 -or ($check -match 'True')){ throw "SQLAlchemy could not be prepared for this Windows security policy.`n$check" }
  Write-Host "SQLAlchemy compatibility: OK" -ForegroundColor Green

  if(-not (Test-Path (Join-Path $Backend 'app\main.py'))){ throw "Backend entrypoint not found." }
  Write-Stage 4 "Starting SentinelX API + web application..."
  $env:SENTINELX_DEMO_MODE='0'
  $env:DISABLE_SQLALCHEMY_CEXT_RUNTIME='1'
  $logDir = Join-Path $Root 'logs'; New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $stdout = Join-Path $logDir 'sentinelx-api.out.log'; $stderr = Join-Path $logDir 'sentinelx-api.err.log'
  $proc = Start-Process -FilePath $Py -WorkingDirectory $Backend -ArgumentList @('-m','uvicorn','app.main:app','--host','127.0.0.1','--port',"$Port") -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden

  $healthy = $false
  for($i=0;$i -lt 60;$i++){
    Start-Sleep -Seconds 1
    try{
      $r = Invoke-WebRequest -UseBasicParsing "$Url`health" -TimeoutSec 2
      if($r.StatusCode -eq 200){ $healthy=$true; break }
    } catch {}
    if($proc.HasExited){ break }
  }
  if(-not $healthy){
    $err = if(Test-Path $stderr){ Get-Content $stderr -Tail 25 -Raw } else { '' }
    throw "SentinelX API did not become healthy.`n$err"
  }

  Write-Stage 5 "Opening SentinelX..."
  Start-Process $Url
  Write-Host ""
  Write-Host "SentinelX is running: $Url" -ForegroundColor Green
  Write-Host "API docs: $Url`docs" -ForegroundColor DarkCyan
  Write-Host "Logs: $logDir" -ForegroundColor DarkGray
  Write-Host "Close this window to leave SentinelX running in the background." -ForegroundColor DarkGray
  Read-Host "Press ENTER to stop SentinelX"
  if(-not $proc.HasExited){ Stop-Process -Id $proc.Id -Force }
} catch {
  Write-Host ""; Write-Host "SentinelX startup failed:" -ForegroundColor Red; Write-Host $_.Exception.Message -ForegroundColor Red
  Write-Host ""; Read-Host "Press ENTER to close"
  exit 1
}
