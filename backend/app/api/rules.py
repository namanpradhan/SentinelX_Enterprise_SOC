
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from app.core.database import get_db
from app.rules.detection import detect_event, RULES, ensure_rule_states
from app.models.rule_state import RuleState
from app.services.auth import get_current_user, require_roles, audit

router=APIRouter(prefix='/rules',tags=['Detection Rules'])

@router.get('/')
def rules(search:str='',severity:str='',category:str='',enabled:str='',sort:str='risk',direction:str='desc',db:Session=Depends(get_db),user=Depends(get_current_user)):
    ensure_rule_states(db)
    states={x.rule_id:x.enabled for x in db.query(RuleState).all()}
    rows=[{'id':r.id,'event_type':','.join(r.event_types),'category':r.category,'tactic':r.tactic,'severity':r.severity,'risk':r.risk,'mitre':r.mitre,'description':r.description,'recommendation':r.recommendation,'enabled':states.get(r.id,True)} for r in RULES]
    if search: rows=[x for x in rows if search.lower() in (x['id']+' '+x['event_type']+' '+x['description']+' '+x['mitre']+' '+x['category']).lower()]
    if severity: rows=[x for x in rows if x['severity']==severity]
    if category: rows=[x for x in rows if x['category']==category]
    if enabled in {'true','false'}: rows=[x for x in rows if x['enabled']==(enabled=='true')]
    reverse=direction!='asc'; rows.sort(key=lambda x:x.get(sort) or '', reverse=reverse)
    return rows

@router.post('/{rule_id}/toggle')
def toggle_rule(rule_id:str, db:Session=Depends(get_db), user=Depends(require_roles('admin'))):
    ensure_rule_states(db); row=db.query(RuleState).filter(RuleState.rule_id==rule_id).first()
    if not row: raise HTTPException(404,'Rule not found')
    row.enabled=not row.enabled; row.updated_at=datetime.utcnow(); db.commit(); audit(db,user,'rule.toggle','success',f'rule:{rule_id}',details=f'enabled={row.enabled}'); return {'rule_id':rule_id,'enabled':row.enabled}

@router.post('/test')
def test_rule(event_type:str,message:str, db:Session=Depends(get_db), user=Depends(get_current_user)): return detect_event(event_type,message,db)
