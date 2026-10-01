from fastapi import APIRouter, Depends
from app.services.auth import get_current_user
from app.services.idsips import status as ids_status, recent_alerts
from pathlib import Path
import json, os, shutil, subprocess

router=APIRouter(prefix='/integrations',tags=['Security Integrations'])
CATALOG_PATH=Path(__file__).resolve().parents[3] / 'data' / 'metasploit' / 'catalog.json'

def _catalog():
    try: return json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
    except Exception: return []

def _msf_status():
    exe=shutil.which('msfconsole'); version=None
    if exe:
        try:
            p=subprocess.run([exe,'-q','-x','version;exit'],capture_output=True,text=True,timeout=20)
            version=(p.stdout or p.stderr).strip()[-800:]
        except Exception: pass
    return {'installed':bool(exe),'path':exe,'version':version,'execution_policy':'disabled-from-ui','catalog_size':len(_catalog()),'note':'Exploit execution and payload delivery are intentionally disabled in the SentinelX UI. Use the catalog for authorized defensive validation and lab planning.'}

@router.get('/idsips/status')
def ids_status_api(user=Depends(get_current_user)): return ids_status()

@router.get('/idsips/alerts')
def ids_alerts(limit:int=100,user=Depends(get_current_user)): return recent_alerts(max(1,min(limit,500)))

@router.get('/metasploit/status')
def metasploit_status(user=Depends(get_current_user)): return _msf_status()

@router.get('/metasploit/search')
def metasploit_search(q:str='',kind:str='',limit:int=100,user=Depends(get_current_user)):
    rows=_catalog(); q=q.lower().strip()
    if q: rows=[x for x in rows if q in json.dumps(x).lower()]
    if kind: rows=[x for x in rows if x.get('type')==kind]
    return rows[:max(1,min(limit,200))]

@router.get('/overview')
def integrations_overview(user=Depends(get_current_user)):
    return {'ids_ips':ids_status(),'metasploit':_msf_status()}
