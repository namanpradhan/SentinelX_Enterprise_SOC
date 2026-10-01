
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.services.auth import get_current_user, require_roles, audit
router=APIRouter(prefix='/alerts',tags=['Alerts'])

def row(a): return {'id':a.id,'event_id':a.event_id,'created_at':a.created_at.isoformat() if a.created_at else None,'rule':a.rule,'severity':a.severity,'risk_score':a.risk_score,'status':a.status,'description':a.description,'mitre_technique':a.mitre_technique}

@router.get('/')
def get_alerts(search:str='',severity:str='',status:str='',mitre:str='',source:str='',min_risk:int=0,limit:int=500,db:Session=Depends(get_db),user=Depends(get_current_user)):
    q=db.query(Alert).join(SecurityEvent,Alert.event_id==SecurityEvent.id)
    if search:
        like=f'%{search}%'; q=q.filter((Alert.rule.ilike(like))|(Alert.description.ilike(like))|(SecurityEvent.hostname.ilike(like))|(SecurityEvent.username.ilike(like))|(SecurityEvent.message.ilike(like)))
    if severity:q=q.filter(Alert.severity==severity)
    if status:q=q.filter(Alert.status==status)
    if mitre:q=q.filter(Alert.mitre_technique==mitre)
    if source:q=q.filter(SecurityEvent.source==source)
    if min_risk:q=q.filter(Alert.risk_score>=min_risk)
    return [row(a) for a in q.order_by(Alert.created_at.desc()).limit(max(1,min(limit,1000))).all()]

@router.patch('/{alert_id}/status')
def update_alert_status(alert_id:int,status:str,db:Session=Depends(get_db),user=Depends(require_roles('admin','employee'))):
    if status not in {'open','acknowledged','closed'}: raise HTTPException(400,'Invalid status')
    a=db.query(Alert).filter(Alert.id==alert_id).first()
    if not a: raise HTTPException(404,'Alert not found')
    old=a.status; a.status=status; db.commit(); db.refresh(a); audit(db,user,'alert.status','success',f'alert:{a.id}',details=f'{old}->{status}'); return {'status':'success','alert_id':a.id,'new_status':a.status}
