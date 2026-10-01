from playwright.sync_api import sync_playwright

URL='http://127.0.0.1:8000/'

with sync_playwright() as p:
    browser=p.chromium.launch(headless=True, executable_path='/usr/bin/chromium', args=['--no-sandbox'])
    page=browser.new_page(viewport={'width':1440,'height':1000})
    errors=[]
    page.on('console', lambda msg: errors.append('console:'+msg.text) if msg.type=='error' else None)
    page.on('pageerror', lambda exc: errors.append('pageerror:'+str(exc)))
    page.goto(URL, wait_until='networkidle')
    assert page.locator('#loginForm').is_visible()
    assert 'SentinelX API online' in page.locator('#loginBackendState').inner_text()
    page.fill('#loginUser','admin')
    page.fill('#loginPass','Admin@12345')
    page.click('#loginForm button[type="submit"]')
    page.wait_for_timeout(1200)
    assert page.locator('#app').is_visible(), page.locator('#loginError').inner_text()
    # every workspace
    names=['Command Center','Device Fleet','Network Discovery','Threat Queue','Incident Response','Event Stream','ATT&CK Coverage','Detection Rules','AI Analyst','Identity & Access','Reports & Export','Security Center']
    nav=page.locator('.nav-item')
    for i,name in enumerate(names):
        page.get_by_role('button', name=name, exact=True).click()
        page.wait_for_timeout(150)
        assert page.locator('#viewTitle').inner_text()==name
        assert page.locator('#view').inner_text().strip()
    # filters on alerts
    page.get_by_role('button', name='Threat Queue', exact=True).click()
    page.select_option('#severityFilter','critical')
    assert page.locator('#filterCount').inner_text().startswith('Showing')
    page.click('#clearFilters')
    # network page controls
    page.get_by_role('button', name='Network Discovery', exact=True).click()
    assert page.locator('#discoverBtn').is_visible()
    # rules tester
    page.get_by_role('button', name='Detection Rules', exact=True).click()
    page.fill('#ruleTestType','powershell_execution')
    page.fill('#ruleTestMessage','powershell -enc AAAA')
    page.click('#ruleTestBtn')
    page.wait_for_timeout(500)
    assert 'detected' in page.locator('#ruleTestOut').inner_text()
    # IAM security controls
    page.get_by_role('button', name='Identity & Access', exact=True).click()
    assert page.locator('#changePasswordBtn').is_visible()
    assert page.locator('#sessionTimer').inner_text() != '—'
    # reports exports
    page.get_by_role('button', name='Reports & Export', exact=True).click()
    assert page.locator('[data-export="alerts"]').is_visible()
    # security center
    page.get_by_role('button', name='Security Center', exact=True).click()
    assert 'SECURITY CONTROLS' in page.locator('#view').inner_text()
    # logout and login screen
    page.click('#logoutBtn')
    page.wait_for_timeout(200)
    assert page.locator('#loginScreen').is_visible()
    browser.close()
    if errors:
        raise AssertionError('\n'.join(errors))
print('BROWSER SMOKE PASS')
