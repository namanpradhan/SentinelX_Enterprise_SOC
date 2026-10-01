
from datetime import datetime, timedelta
from collections import Counter
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.device import Device
from app.services.auth import get_current_user
router=APIRouter(prefix='/dashboard',tags=['Dashboard'])
@router.get('/stats')
def stats(db:Session=Depends(get_db),user=Depends(get_current_user)):
    return {'events':db.query(SecurityEvent).count(),'alerts':db.query(Alert).count(),'open_alerts':db.query(Alert).filter(Alert.status=='open').count(),'incidents':db.query(Incident).count(),'open_incidents':db.query(Incident).filter(Incident.status!='resolved').count(),'high_alerts':db.query(Alert).filter(Alert.severity.in_(['high','critical'])).count(),'devices':db.query(Device).count(),'online_devices':db.query(Device).filter(Device.status=='online').count()}
@router.get('/trends')
def trends(hours:int=24,db:Session=Depends(get_db),user=Depends(get_current_user)):
    hours=max(1,min(hours,168)); now=datetime.utcnow().replace(minute=0,second=0,microsecond=0); events=db.query(SecurityEvent).filter(SecurityEvent.timestamp>=now-timedelta(hours=hours-1)).all(); alerts=db.query(Alert).filter(Alert.created_at>=now-timedelta(hours=hours-1)).all()
    out=[]
    for i in range(hours):
        bucket=now-timedelta(hours=hours-1-i)
        end=bucket+timedelta(hours=1)
        ev=sum(1 for x in events if x.timestamp and bucket<=x.timestamp<end)
        al=sum(1 for x in alerts if x.created_at and bucket<=x.created_at<end)
        out.append({'label':bucket.strftime('%H:%M'),'events':ev,'alerts':al})
    return out
@router.get('/severity')
def severity(db:Session=Depends(get_db),user=Depends(get_current_user)):
    c=Counter(x.severity for x in db.query(Alert).all()); return [{'severity':k,'count':c.get(k,0)} for k in ['critical','high','medium','low']]
@router.get('/rules-top')
def rules_top(db:Session=Depends(get_db),user=Depends(get_current_user)):
    c=Counter(x.rule for x in db.query(Alert).all()); return [{'rule':k,'count':v} for k,v in c.most_common(12)]
