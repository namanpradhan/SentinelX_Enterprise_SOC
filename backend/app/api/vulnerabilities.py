from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.vulnerability import VulnerabilityFinding
from app.models.device import Device
from app.services.auth import get_current_user, require_roles, audit
from app.services.vulnerability import scan, persist_results, tool_status, DEFAULT_PORTS

router=APIRouter(prefix='/vulnerabilities',tags=['Vulnerability Management'])

class ScanRequest(BaseModel):
    deep: bool = False
    confirm_authorized: bool = False
    ports: list[int] | None = None

@router.get('/status')
def status(user=Depends(get_current_user)):
    return {'scanner':'Nmap','status':tool_status(),'default_ports':DEFAULT_PORTS}

@router.get('/findings')
def findings(status:str='',severity:str='',search:str='',limit:int=500,db:Session=Depends(get_db),user=Depends(get_current_user)):
    q=db.query(VulnerabilityFinding)
    if status:q=q.filter(VulnerabilityFinding.status==status)
    if severity:q=q.filter(VulnerabilityFinding.severity==severity)
    if search:
        like=f'%{search}%'; q=q.filter((VulnerabilityFinding.title.ilike(like))|(VulnerabilityFinding.ip_address.ilike(like))|(VulnerabilityFinding.cve.ilike(like))|(VulnerabilityFinding.service.ilike(like))|(VulnerabilityFinding.product.ilike(like)))
    rows=q.order_by(VulnerabilityFinding.risk_score.desc(),VulnerabilityFinding.last_seen.desc()).limit(max(1,min(limit,1000))).all()
    return [dict(id=f.id,device_id=f.device_id,ip_address=f.ip_address,port=f.port,protocol=f.protocol,service=f.service,product=f.product,version=f.version,cpe=f.cpe,cve=f.cve,cwe=f.cwe,severity=f.severity,risk_score=f.risk_score,cvss=f.cvss,title=f.title,evidence=f.evidence,remediation=f.remediation,scanner=f.scanner,status=f.status,discovered_at=f.discovered_at.isoformat(),last_seen=f.last_seen.isoformat()) for f in rows]

@router.get('/summary')
def summary(db:Session=Depends(get_db),user=Depends(get_current_user)):
    rows=db.query(VulnerabilityFinding).filter(VulnerabilityFinding.status=='open').all()
    return {'open':len(rows),'critical':sum(1 for x in rows if x.severity=='critical'),'high':sum(1 for x in rows if x.severity=='high'),'medium':sum(1 for x in rows if x.severity=='medium'),'low':sum(1 for x in rows if x.severity=='low'),'risk_sum':sum(x.risk_score for x in rows)}

@router.post('/scan/device/{device_id}')
def scan_device(device_id:int,payload:ScanRequest=ScanRequest(),db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    device=db.query(Device).filter(Device.id==device_id).first()
    if not device or not device.ip_address: raise HTTPException(404,'Device has no IPv4 address to assess')
    try:
        result=scan(device.ip_address,ports=payload.ports,deep=payload.deep,device_id=device.id,confirm_authorized=payload.confirm_authorized)
        result['device_id']=device.id
        saved=persist_results(db,result)
    except PermissionError as e: raise HTTPException(400,str(e))
    except (ValueError,RuntimeError) as e: raise HTTPException(400,str(e))
    audit(db,user,'vulnerability.scan','success',f'device:{device.id}',details=f"target={device.ip_address};deep={payload.deep};findings={len(saved)}")
    return {'status':'completed','device':{'id':device.id,'name':device.name,'ip_address':device.ip_address},'scan':{'scanner':result['scanner'],'nmap':result['nmap'],'ports':result['ports'],'services':result['services'],'deep_vulnerability_scripts':result['deep_vulnerability_scripts']},'findings':[_finding(f) for f in saved]}

@router.post('/scan/target')
def scan_target(payload:dict,db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    ip=str(payload.get('ip_address','')).strip(); deep=bool(payload.get('deep',False)); confirm=bool(payload.get('confirm_authorized',False))
    try: result=scan(ip,ports=payload.get('ports'),deep=deep,device_id=None,confirm_authorized=confirm)
    except PermissionError as e: raise HTTPException(400,str(e))
    except (ValueError,RuntimeError) as e: raise HTTPException(400,str(e))
    saved=persist_results(db,result)
    audit(db,user,'vulnerability.scan_target','success',f'ip:{ip}',details=f'deep={deep};findings={len(saved)}')
    return {'status':'completed','scan':{'scanner':result['scanner'],'nmap':result['nmap'],'ports':result['ports'],'services':result['services'],'deep_vulnerability_scripts':result['deep_vulnerability_scripts']},'findings':[_finding(f) for f in saved]}

@router.patch('/{finding_id}/status')
def update_status(finding_id:int,status:str,db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    if status not in {'open','accepted','resolved'}: raise HTTPException(400,'Invalid finding status')
    f=db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id==finding_id).first()
    if not f: raise HTTPException(404,'Vulnerability finding not found')
    f.status=status; db.commit(); db.refresh(f); audit(db,user,'vulnerability.status','success',f'finding:{f.id}',details=status); return _finding(f)

def _finding(f):
    return {'id':f.id,'device_id':f.device_id,'ip_address':f.ip_address,'port':f.port,'protocol':f.protocol,'service':f.service,'product':f.product,'version':f.version,'cpe':f.cpe,'cve':f.cve,'cwe':f.cwe,'severity':f.severity,'risk_score':f.risk_score,'cvss':f.cvss,'title':f.title,'evidence':f.evidence,'remediation':f.remediation,'scanner':f.scanner,'status':f.status,'discovered_at':f.discovered_at.isoformat(),'last_seen':f.last_seen.isoformat()}
