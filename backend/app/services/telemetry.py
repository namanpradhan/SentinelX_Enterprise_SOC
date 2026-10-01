from datetime import datetime
from app.models.event import SecurityEvent
from app.models.alert import Alert
from app.services.correlation import correlate_alert
from app.rules.detection import detect_event
SUPPORTED_PLATFORMS={"windows":"Windows","windows_server":"Windows Server","macos":"macOS","linux":"Linux","android":"Android","ios":"iOS","network":"Network","firewall":"Firewall","router":"Router","switch":"Switch","tv":"Smart TV","iot":"IoT","cloud":"Cloud","server":"Server"}

def normalize_event(payload):
    platform=str(payload.get('platform') or 'unknown').lower().replace(' ','_')
    sev=str(payload.get('severity') or 'low').lower()
    if sev not in {'critical','high','medium','low','info'}: sev='low'
    return {'source':str(payload.get('source') or SUPPORTED_PLATFORMS.get(platform,'Universal Collector'))[:100],
            'event_type':str(payload.get('event_type') or payload.get('type') or 'generic_event')[:100],
            'severity':sev,'hostname':payload.get('hostname') or payload.get('device_name') or payload.get('asset'),
            'username':payload.get('username') or payload.get('user'),
            'message':str(payload.get('message') or payload.get('description') or 'Universal telemetry event')[:2000]}

def ingest_event(db,payload):
    e=normalize_event(payload); detection=detect_event(e['event_type'],e['message'],db)
    if detection['detected']: e['severity']=detection['severity']
    event=SecurityEvent(**e); db.add(event); db.commit(); db.refresh(event)
    alert=None; incident=None
    if detection['detected']:
        alert=Alert(event_id=event.id,rule=detection['rule'],severity=detection['severity'],risk_score=detection['risk_score'],status='open',description=detection['description'],mitre_technique=detection['mitre_technique'])
        db.add(alert); db.commit(); db.refresh(alert); incident=correlate_alert(db,alert,event.hostname,event.username)
    return event,alert,incident,detection
