import os, requests

BASE = os.getenv("SENTINELX_BASE", "http://127.0.0.1:8000")
s = requests.Session()

def ok(method, path, **kwargs):
    r = s.request(method, BASE + path, timeout=20, **kwargs)
    assert r.status_code < 400, f"{method} {path}: {r.status_code} {r.text[:500]}"
    return r

h = ok("GET", "/health").json(); assert h["version"] == "4.2.13"
login = ok("POST", "/auth/login", json={"username":"admin","password":"Admin@12345"}).json()
s.headers["Authorization"] = "Bearer " + login["access_token"]
for path in ["/auth/me","/auth/session","/soc/overview","/soc/activity?limit=10","/alerts/?limit=10","/incidents/?limit=10","/events/?limit=10","/devices/?limit=10","/rules/?limit=500","/network/local","/network/live","/dashboard/trends?hours=6","/dashboard/severity","/dashboard/rules-top","/system/status","/vulnerabilities/status","/vulnerabilities/summary","/vulnerabilities/findings?limit=10","/integrations/idsips/status","/integrations/idsips/alerts?limit=10","/integrations/metasploit/status","/integrations/metasploit/search?limit=10","/ai/status"]:
    ok("GET", path)
assert len(ok("GET", "/rules/?limit=500").json()) >= 140
assert ok("POST", "/rules/test?event_type=powershell_execution&message=powershell%20-enc%20AAAA").json()["detected"]
assert ok("GET", "/devices/?limit=10").json() == []
assert ok("GET", "/events/?limit=10").json() == []
assert ok("GET", "/alerts/?limit=10").json() == []
assert ok("GET", "/incidents/?limit=10").json() == []
assert s.get(BASE+"/actions/simulate", timeout=10).status_code == 404
ok("POST", "/auth/logout")
print("FINAL CLEAN SMOKE PASS")
