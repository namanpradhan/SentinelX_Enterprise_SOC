
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.incident import Incident
from app.services.auth import get_current_user, require_roles, audit
router=APIRouter(prefix='/incidents',tags=['Incidents'])

def incident_dict(i): return {'id':i.id,'created_at':i.created_at.isoformat() if i.created_at else None,'updated_at':i.updated_at.isoformat() if i.updated_at else None,'title':i.title,'severity':i.severity,'risk_score':i.risk_score,'status':i.status,'hostname':i.hostname,'username':i.username,'summary':i.summary}
@router.get('/')
def get_incidents(search:str='',severity:str='',status:str='',limit:int=200,db:Session=Depends(get_db),user=Depends(get_current_user)):
    q=db.query(Incident)
    if search:
        like=f'%{search}%'; q=q.filter((Incident.title.ilike(like))|(Incident.summary.ilike(like))|(Incident.hostname.ilike(like))|(Incident.username.ilike(like)))
    if severity:q=q.filter(Incident.severity==severity)
    if status:q=q.filter(Incident.status==status)
    return [incident_dict(i) for i in q.order_by(Incident.updated_at.desc()).limit(max(1,min(limit,500))).all()]
@router.patch('/{incident_id}/status')
def update_incident_status(incident_id:int,status:str,db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    if status not in {'open','investigating','resolved'}: raise HTTPException(400,'Invalid status')
    i=db.query(Incident).filter(Incident.id==incident_id).first()
    if not i: raise HTTPException(404,'Incident not found')
    old=i.status; i.status=status; db.commit(); db.refresh(i); audit(db,user,'incident.status','success',f'incident:{i.id}',details=f'{old}->{status}'); return incident_dict(i)
