
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.event import SecurityEvent
from app.services.telemetry import ingest_event
from app.schemas.event import SecurityEventCreate
from app.services.auth import get_current_user, require_roles
router=APIRouter(prefix='/events',tags=['Security Events'])
@router.post('/')
def create_event(event:SecurityEventCreate,db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    payload=event.model_dump(); e,a,i,d=ingest_event(db,payload)
    return {'status':'success','event_id':e.id,'detection':d,'alert':alert_dict(a) if a else None,'incident':incident_dict(i) if i else None}
@router.get('/')
def get_events(search:str='',severity:str='',source:str='',event_type:str='',limit:int=500,db:Session=Depends(get_db),user=Depends(get_current_user)):
    q=db.query(SecurityEvent)
    if search:
        like=f'%{search}%'; q=q.filter((SecurityEvent.source.ilike(like))|(SecurityEvent.event_type.ilike(like))|(SecurityEvent.hostname.ilike(like))|(SecurityEvent.username.ilike(like))|(SecurityEvent.message.ilike(like)))
    if severity:q=q.filter(SecurityEvent.severity==severity)
    if source:q=q.filter(SecurityEvent.source==source)
    if event_type:q=q.filter(SecurityEvent.event_type==event_type)
    return [event_dict(e) for e in q.order_by(SecurityEvent.timestamp.desc()).limit(max(1,min(limit,1000))).all()]
def event_dict(e): return {'id':e.id,'timestamp':e.timestamp.isoformat() if e.timestamp else None,'source':e.source,'event_type':e.event_type,'severity':e.severity,'hostname':e.hostname,'username':e.username,'message':e.message}
def alert_dict(a): return {'id':a.id,'event_id':a.event_id,'created_at':a.created_at.isoformat() if a.created_at else None,'rule':a.rule,'severity':a.severity,'risk_score':a.risk_score,'status':a.status,'description':a.description,'mitre_technique':a.mitre_technique}
def incident_dict(i): return {'id':i.id,'created_at':i.created_at.isoformat() if i.created_at else None,'updated_at':i.updated_at.isoformat() if i.updated_at else None,'title':i.title,'severity':i.severity,'risk_score':i.risk_score,'status':i.status,'hostname':i.hostname,'username':i.username,'summary':i.summary}
