"""SentinelX Windows telemetry starter agent.

Collects selected Windows Security / PowerShell / process telemetry and posts
normalized events to SentinelX. Authorized deployment only.

Environment:
  SENTINELX_API=http://127.0.0.1:8000
  SENTINELX_AGENT_KEY=<same key configured on the SentinelX server>
  SENTINELX_AGENT_INTERVAL=15
"""
from __future__ import annotations
import json, os, subprocess, time
from datetime import datetime, timezone
import requests

API=os.getenv('SENTINELX_API','http://127.0.0.1:8000').rstrip('/')
KEY=os.getenv('SENTINELX_AGENT_KEY','')
INTERVAL=max(5,int(os.getenv('SENTINELX_AGENT_INTERVAL','15')))


def ps(script:str) -> str:
    p=subprocess.run(['powershell','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-Command',script],capture_output=True,text=True,timeout=12)
    return p.stdout.strip()


def hostname():
    return os.getenv('COMPUTERNAME') or ps('$env:COMPUTERNAME') or 'WINDOWS-ENDPOINT'


def ipv4():
    out=ps("Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'} | Select-Object -ExpandProperty IPAddress | ConvertTo-Json -Compress")
    try:
        x=json.loads(out); x=x if isinstance(x,list) else [x]; return x[0] if x else None
    except Exception:return None


def emit(event_type,message,severity='low',username=None):
    payload={'platform':'windows','source':'SentinelX Windows Agent','hostname':hostname(),'device_name':hostname(),'ip_address':ipv4(),'event_type':event_type,'severity':severity,'username':username,'message':message,'agent_version':'SX-Agent 4.2.8'}
    headers={'Content-Type':'application/json'}
    if KEY:headers['X-Agent-Key']=KEY
    r=requests.post(API+'/collectors/ingest',json=payload,headers=headers,timeout=10)
    r.raise_for_status()
    return r.json()


def collect_security_events():
    script=r'''$ids=4625,4104,4688; Get-WinEvent -FilterHashtable @{LogName='Security';Id=$ids;StartTime=(Get-Date).AddSeconds(-20)} -ErrorAction SilentlyContinue | Select-Object -First 25 Id,ProviderName,Message,TimeCreated | ConvertTo-Json -Compress'''
    out=ps(script)
    try: data=json.loads(out); return data if isinstance(data,list) else ([data] if data else [])
    except Exception:return []


def collect_processes():
    script="Get-Process | Select-Object -First 80 ProcessName,Id,Path | ConvertTo-Json -Compress"
    out=ps(script)
    try:return json.loads(out)
    except Exception:return []


def run_once():
    current_user=os.getenv('USERNAME')
    for ev in collect_security_events():
        eid=str(ev.get('Id'))
        if eid=='4625': et,severity='failed_login','medium'
        elif eid=='4104': et,severity='powershell_execution','high'
        elif eid=='4688': et,severity='process_creation','low'
        else: et,severity='windows_event','low'
        msg=(ev.get('Message') or '')[:1800]
        try: emit(et,msg,severity,current_user)
        except Exception as exc: print('telemetry error:',type(exc).__name__,exc)
    # A lightweight posture heartbeat is deliberately separate from process content.
    proc_count=len(collect_processes())
    try: emit('device_posture',f'Windows endpoint heartbeat; visible process sample size={proc_count}', 'low', current_user)
    except Exception as exc: print('heartbeat error:',type(exc).__name__,exc)


def main():
    print(f'SentinelX Windows Agent 4.2.8 → {API} interval={INTERVAL}s')
    if not KEY: print('WARNING: SENTINELX_AGENT_KEY is not configured; the server must be configured to accept bearer authentication instead.')
    while True:
        try: run_once()
        except Exception as exc: print('agent cycle error:',type(exc).__name__,exc)
        time.sleep(INTERVAL)

if __name__=='__main__': main()
