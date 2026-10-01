import os, requests

BASE=os.getenv("SENTINELX_BASE","http://127.0.0.1:8000")
s=requests.Session()

def ok(method,path,**kwargs):
    r=s.request(method,BASE+path,timeout=25,**kwargs)
    assert r.status_code < 400, f"{method} {path}: {r.status_code} {r.text[:500]}"
    return r

assert ok("GET","/health").json()["version"] == "4.2.13"
for username,password,role in [("admin","Admin@12345","admin"),("employee","Employee@12345","employee"),("user","User@12345","user")]:
    ss=requests.Session(); lr=ss.post(BASE+"/auth/login",json={"username":username,"password":password},timeout=10); assert lr.ok
    token=lr.json()["access_token"]; ss.headers["Authorization"]="Bearer "+token
    assert ss.get(BASE+"/auth/me",timeout=10).json()["user"]["role"] == role
    assert ss.get(BASE+"/auth/session",timeout=10).ok
    if role != "admin":
        assert ss.get(BASE+"/auth/users",timeout=10).status_code == 403
    ss.post(BASE+"/auth/logout",timeout=10)
login=ok("POST","/auth/login",json={"username":"admin","password":"Admin@12345"}).json(); s.headers["Authorization"]="Bearer "+login["access_token"]
paths=["/auth/me","/auth/session","/soc/overview","/soc/activity?limit=20","/alerts/?limit=50","/incidents/?limit=50","/events/?limit=50","/devices/?limit=100","/network/local","/network/live","/dashboard/trends?hours=24","/dashboard/severity","/dashboard/rules-top","/rules/?limit=500","/vulnerabilities/status","/vulnerabilities/summary","/vulnerabilities/findings?limit=100","/integrations/overview","/integrations/idsips/status","/integrations/idsips/alerts?limit=50","/integrations/metasploit/status","/integrations/metasploit/search?limit=50","/ai/status","/system/status"]
for path in paths: ok("GET",path)
assert len(ok("GET","/rules/?limit=500").json()) >= 140
assert ok("POST","/rules/test?event_type=powershell_execution&message=powershell%20-enc%20AAAA").json()["detected"]
assert s.get(BASE+"/actions/simulate",timeout=10).status_code == 404
assert ok("POST","/auth/logout").json()["status"] == "logged_out"
print("FINAL CLEAN FULL ACCEPTANCE PASS")
