
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.device import Device
from app.models.vulnerability import VulnerabilityFinding
from app.services.auth import get_current_user, require_roles, audit
router=APIRouter(prefix='/devices',tags=['Devices'])
class DeviceCreate(BaseModel):
    name:str=Field(min_length=1,max_length=255); hostname:str|None=None; ip_address:str|None=None; device_type:str='endpoint'; platform:str='Unknown'; os_version:str|None=None; status:str='online'; risk_score:int=0; agent_version:str|None=None; source:str='manual'; location:str|None=None; tags:str|None=None
@router.get('/')
def get_devices(search:str='',platform:str='',status:str='',device_type:str='',source:str='',limit:int=500,db:Session=Depends(get_db),user=Depends(get_current_user)):
    q=db.query(Device)
    if search:
        like=f'%{search}%'; q=q.filter((Device.name.ilike(like))|(Device.hostname.ilike(like))|(Device.ip_address.ilike(like))|(Device.platform.ilike(like))|(Device.tags.ilike(like)))
    if platform:q=q.filter(Device.platform==platform)
    if status:q=q.filter(Device.status==status)
    if device_type:q=q.filter(Device.device_type==device_type)
    if source:q=q.filter(Device.source==source)
    rows=q.order_by(Device.last_seen.desc()).limit(max(1,min(limit,1000))).all()
    return [device_dict(d, db) for d in rows]
@router.get('/{device_id}')
def get_device(device_id:int,db:Session=Depends(get_db),user=Depends(get_current_user)):
    d=db.query(Device).filter(Device.id==device_id).first()
    if not d: raise HTTPException(404,'Device not found')
    return device_dict(d, db)
@router.post('/')
def create_device(payload:DeviceCreate,db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    if payload.status not in {'online','offline','degraded','unknown'}: raise HTTPException(400,'Invalid device status')
    d=Device(**payload.model_dump(),last_seen=datetime.utcnow()); db.add(d); db.commit(); db.refresh(d); return device_dict(d, db)
@router.patch('/{device_id}/status')
def update_device_status(device_id:int,status:str,db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    if status not in {'online','offline','degraded','unknown'}: raise HTTPException(400,'Invalid device status')
    d=db.query(Device).filter(Device.id==device_id).first()
    if not d: raise HTTPException(404,'Device not found')
    old=d.status; d.status=status; d.last_seen=datetime.utcnow(); db.commit(); db.refresh(d); audit(db,user,'device.status','success',f'device:{d.id}',details=f'{old}->{status}'); return device_dict(d, db)
def device_dict(d, db=None):
    vuln_count = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.ip_address==d.ip_address, VulnerabilityFinding.status=="open").count() if db and d.ip_address else 0
    return {'id':d.id,'name':d.name,'hostname':d.hostname,'ip_address':d.ip_address,'device_type':d.device_type,'platform':d.platform,'os_version':d.os_version,'status':d.status,'risk_score':d.risk_score,'agent_version':d.agent_version,'source':d.source,'location':d.location,'tags':d.tags,'open_vulnerabilities':vuln_count,'last_seen':d.last_seen.isoformat() if d.last_seen else None}
