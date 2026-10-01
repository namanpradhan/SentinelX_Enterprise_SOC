from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.services.auth import get_current_user, require_permission
from app.services.ai import models as ai_models, generate

router = APIRouter(prefix='/ai', tags=['AI Analyst'])

class InvestigateRequest(BaseModel):
    model: str | None = None

@router.get('/status')
def status(user=Depends(get_current_user)):
    return ai_models()

@router.get('/models')
def models(user=Depends(get_current_user)):
    return ai_models()

@router.post('/investigate/{alert_id}')
def investigate_alert(alert_id:int, payload:InvestigateRequest | None=None, db:Session=Depends(get_db), user=Depends(require_permission('ai.investigate'))):
    alert=db.query(Alert).filter(Alert.id==alert_id).first()
    if not alert: raise HTTPException(404,'Alert not found')
    event=db.query(SecurityEvent).filter(SecurityEvent.id==alert.event_id).first()
    prompt=f'''You are the SentinelX Security Operations investigation assistant.\nYou are an analyst aid, not an autonomous decision maker. Do not claim certainty that is not supported by the evidence.\nReturn these sections: Summary, Evidence, Likely Tactics/Techniques, Investigation Steps, Containment Considerations, Confidence & Gaps.\n\nAlert: {alert.rule}\nSeverity: {alert.severity}\nRisk: {alert.risk_score}/100\nMITRE: {alert.mitre_technique or 'unmapped'}\nDescription: {alert.description}\nEvent source: {event.source if event else 'unknown'}\nEvent type: {event.event_type if event else 'unknown'}\nHost: {event.hostname if event else 'unknown'}\nUser: {event.username if event else 'unknown'}\nMessage: {event.message if event else 'unknown'}'''
    try:
        result=generate(prompt,(payload.model if payload else None))
        if not result.get('analysis'): raise RuntimeError('AI provider returned an empty response')
        return {'status':'success','provider':result['provider'],'model':result['model'],'analysis':result['analysis'],'note':'Analyst assistance only; validate conclusions against telemetry and deterministic detections.'}
    except Exception as exc:
        return {'status':'fallback','provider':'SentinelX Deterministic Analyst','model':None,'analysis':(
            f'Alert {alert.id} matched {alert.rule} at risk {alert.risk_score}/100.\n\n'
            f'Evidence: {event.message if event else "No linked event was available."}\n\n'
            f'Investigation steps: validate the initiating identity, source host/IP, parent process or request context, related events and network destinations.\n\n'
            f'Containment considerations: follow the incident runbook and isolate only after corroborating the activity.\n\n'
            f'MITRE mapping: {alert.mitre_technique or "Not mapped"}.\n\n'
            f'Provider note: local model service unavailable ({type(exc).__name__}).'
        ),'note':'The deterministic fallback is intentionally used when a local model is unavailable.'}
