from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.models.device import Device
from app.services.auth import get_current_user

router=APIRouter(prefix="/assets", tags=["Asset Intelligence"])

@router.get("/summary")
def asset_summary(db: Session=Depends(get_db), user=Depends(get_current_user)):
    total=db.query(Device).count(); online=db.query(Device).filter(Device.status=="online").count()
    degraded=db.query(Device).filter(Device.status=="degraded").count(); offline=db.query(Device).filter(Device.status=="offline").count()
    rows=db.query(Device.platform, func.count(Device.id)).group_by(Device.platform).all()
    return {"total":total,"online":online,"degraded":degraded,"offline":offline,"platforms":[{"platform":p,"count":c} for p,c in rows]}

@router.get("/risk")
def asset_risk(db: Session=Depends(get_db), user=Depends(get_current_user)):
    devices=db.query(Device).order_by(Device.risk_score.desc(), Device.last_seen.desc()).limit(100).all()
    return [{"id":d.id,"name":d.name,"hostname":d.hostname,"platform":d.platform,"risk_score":d.risk_score,"status":d.status} for d in devices]
