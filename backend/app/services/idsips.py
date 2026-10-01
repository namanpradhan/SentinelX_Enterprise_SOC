from __future__ import annotations
import json, os, shutil, subprocess
from pathlib import Path
from datetime import datetime


def _which(name): return shutil.which(name)


def _version(exe, args):
    if not exe: return None
    try:
        p=subprocess.run([exe,*args],capture_output=True,text=True,timeout=8)
        text=(p.stdout or p.stderr).strip().splitlines()
        return text[0][:240] if text else None
    except Exception: return None


def status():
    suri=_which('suricata'); snort=_which('snort') or _which('snort3'); msf=_which('msfconsole')
    return {
        'suricata': {'installed':bool(suri),'path':suri,'version':_version(suri,['--build-info']) if suri else None,'eve_log':os.getenv('SENTINELX_SURICATA_EVE_LOG','')},
        'snort': {'installed':bool(snort),'path':snort,'version':_version(snort,['-V']) if snort else None,'alert_log':os.getenv('SENTINELX_SNORT_ALERT_LOG','')},
        'note':'SentinelX integrates with locally installed sensors; third-party binaries and commercial/community rule feeds are not bundled.'
    }


def _tail_json(path: str, limit=200):
    p=Path(path)
    if not p.exists(): return []
    rows=[]
    try:
        with p.open('rb') as fh:
            fh.seek(0,2); size=fh.tell(); fh.seek(max(0,size-500000))
            raw=fh.read().decode('utf-8','replace')
        for line in raw.splitlines()[-limit*4:]:
            try: rows.append(json.loads(line))
            except Exception: continue
    except Exception: return []
    return rows[-limit:]


def recent_alerts(limit=100):
    rows=[]
    for sensor,path in [('suricata',os.getenv('SENTINELX_SURICATA_EVE_LOG','')),('snort',os.getenv('SENTINELX_SNORT_ALERT_LOG',''))]:
        if not path: continue
        for x in _tail_json(path,limit):
            alert=x.get('alert') or {}
            if sensor=='suricata' and x.get('event_type')!='alert': continue
            rows.append({'sensor':sensor,'timestamp':x.get('timestamp') or x.get('time') or datetime.utcnow().isoformat(),'signature':alert.get('signature') or x.get('msg') or x.get('rule') or 'IDS alert','severity':alert.get('severity') or x.get('priority') or 'medium','src_ip':x.get('src_ip') or x.get('src_addr'),'src_port':x.get('src_port'),'dest_ip':x.get('dest_ip') or x.get('dst_addr'),'dest_port':x.get('dest_port') or x.get('dst_port'),'raw':x})
    return rows[-limit:]
