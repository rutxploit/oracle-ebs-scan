#!/bin/bash
# Oracle EBS + OAM Quick Scanner
# Usage: ./quickscan.sh <host> [port]
TARGET="${1:?Usage: $0 <host> [port]}"
PORT="${2:-443}"
BASE="https://$TARGET:$PORT"
T=5  # timeout per request

R='\033[91m'; Y='\033[93m'; G='\033[92m'
B='\033[94m'; W='\033[1m'; C='\033[96m'; RS='\033[0m'

hit()  { echo -e "${R}[★ $1]${RS} $2  (${3}b)"; }
redir(){ echo -e "${Y}[→ $1]${RS} $2  → ${3}"; }
nok()  { echo -e "${B}[  $1]${RS} $2  (${3}b)"; }

probe() {
    local path="$1" method="${2:-GET}" data="$3" hdrs="$4"
    local args=(-sk -o /tmp/_sc.tmp -w "%{http_code} %{size_download}" -m $T -X "$method")
    [ -n "$data" ] && args+=(-d "$data" -H "Content-Type: application/x-www-form-urlencoded")
    [ -n "$hdrs" ] && args+=(-H "$hdrs")
    args+=(-H "User-Agent: Mozilla/5.0")
    read -r code size <<< $(curl "${args[@]}" "$BASE$path" 2>/dev/null)
    body=$(cat /tmp/_sc.tmp 2>/dev/null)
    loc=$(curl -sk -o /dev/null -w "%{redirect_url}" -m $T -H "User-Agent: Mozilla/5.0" "$BASE$path" 2>/dev/null)
    case "$code" in
        200) hit  "$code" "$path" "$size" ;;
        301|302|303) redir "$code" "$path" "$loc" ;;
        400|401|403|500|503) nok "$code" "$path" "$size" ;;
    esac
}

echo -e "\n${W}╔══════════════════════════════════════════╗
║  Oracle EBS/OAM Scanner                 ║
║  Target: $TARGET:$PORT
╚══════════════════════════════════════════╝${RS}"

# ── PORT SCAN ──────────────────────────────────────────────────
echo -e "\n${W}── OPEN PORTS ─────────────────────────────────────${RS}"
for p in 80 443 7001 7002 7201 7202 14100 14101 5575 8080 8443; do
    if timeout 2 bash -c "echo >/dev/tcp/$TARGET/$p" 2>/dev/null; then
        echo -e "  ${G}OPEN${RS}  $p"
    fi
done

# ── EBS PATHS ──────────────────────────────────────────────────
echo -e "\n${W}── ORACLE EBS PATHS ───────────────────────────────${RS}"
for p in \
    "/OA_HTML/AppsLocalLogin.jsp" \
    "/OA_HTML/AppsLogin" \
    "/OA_HTML/BneUploaderService" \
    "/OA_HTML/JavaScriptServlet" \
    "/OA_HTML/OAErrorPage.jsp" \
    "/OA_HTML/OA.jsp?OAFunc=AMS_ADMIN" \
    "/OA_HTML/ieshostedsurvey.jsp" \
    "/OA_HTML/ibytransmit" \
    "/OA_HTML/configurator/UiServlet" \
    "/OA_CGI/FNDWRR.exe" \
    "/OA_CGI/FNDWRR.exe?temp_id=1" \
    "/OA_HTML/configurator%2fUiServlet" \
    "/OA_HTML/help%2f..%2fieshostedsurvey.jsp"; do
    probe "$p"
done

# ── OAM PATHS ──────────────────────────────────────────────────
echo -e "\n${W}── OAM PATHS ──────────────────────────────────────${RS}"
for p in \
    "/accessgate/ssologin" \
    "/oamconsole" \
    "/oamconsole/faces/sign-in" \
    "/console" \
    "/console/login/LoginForm.jsp" \
    "/em" \
    "/iam/admin" \
    "/iam/admin/config/discovery" \
    "/oam/admin/api/v1/config/discovery" \
    "/oam/server/info" \
    "/oam/server/obrareq.cgi" \
    "/ms_oauth/oauth2/endpoints/oauthservice/discovery" \
    "/.well-known/openid-configuration" \
    "/identity/faces/signin" \
    "/oam/version.txt"; do
    probe "$p"
done

# ── CVE-2021-35587 ─────────────────────────────────────────────
echo -e "\n${W}── CVE-2021-35587 OAM Pre-Auth RCE (CVSS 9.8) ────${RS}"
code=$(curl -sk -o /tmp/_35587.tmp -w "%{http_code}" -m $T \
    -H "User-Agent: Mozilla/5.0" \
    "$BASE/iam/admin/config/discovery" 2>/dev/null)
body=$(cat /tmp/_35587.tmp)
echo -e "  GET /iam/admin/config/discovery → HTTP $code"
if [ "$code" = "200" ]; then
    echo -e "  ${R}[★ ACCESSIBLE — sending XML deser probe]${RS}"
    code2=$(curl -sk -o /tmp/_35587b.tmp -w "%{http_code}" -m $T \
        -X POST -H "Content-Type: application/xml" \
        -d '<?xml version="1.0"?><OAMConfig><OAMComponent name="probe"/></OAMConfig>' \
        "$BASE/iam/admin/config/discovery" 2>/dev/null)
    echo -e "  POST probe → HTTP $code2  body: $(head -c 150 /tmp/_35587b.tmp)"
    [ "$code2" = "500" ] && echo -e "\n  ${R}[★★ HTTP 500 — LIKELY VULNERABLE TO CVE-2021-35587 RCE]${RS}\n"
fi

# ── CSRF LEAK ──────────────────────────────────────────────────
echo -e "\n${W}── JavaScriptServlet CSRF Leak ────────────────────${RS}"
tok=$(curl -sk -m $T -X POST \
    -H "FETCH-CSRF-TOKEN: 1" -H "CSRF-XHR: YES" \
    -H "User-Agent: Mozilla/5.0" \
    "$BASE/OA_HTML/JavaScriptServlet" 2>/dev/null | grep -oP 'csrftkn:[A-Z0-9\-]+')
[ -n "$tok" ] && echo -e "  ${R}[★ LEAKED]: $tok${RS}" || echo -e "  ${G}Not leaking${RS}"

# ── CRED IN REDIRECT ───────────────────────────────────────────
echo -e "\n${W}── Credential in HTTP Redirect ────────────────────${RS}"
loc=$(curl -sk -o /dev/null -w "%{redirect_url}" -m $T \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "usernameField=testuser&passwordField=VISIBLE123" \
    "$BASE/OA_HTML/AppsLogin" 2>/dev/null)
if echo "$loc" | grep -q "VISIBLE123"; then
    echo -e "  ${R}[★ PASSWORD IN REDIRECT]: $loc${RS}"
else
    echo -e "  ${G}Not exposed${RS}  loc=$loc"
fi

# ── DEFAULT CREDS ──────────────────────────────────────────────
echo -e "\n${W}── Default Credentials (WebLogic/OAM) ────────────${RS}"
for cred in "weblogic:weblogic1" "weblogic:Welcome1" "oamadmin:oamadmin" "admin:admin"; do
    user="${cred%%:*}"; pass="${cred##*:}"
    code=$(curl -sk -o /dev/null -w "%{http_code}" -m $T \
        -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        -d "j_username=$user&j_password=$pass&j_character_encoding=UTF-8" \
        "$BASE/console/j_security_check" 2>/dev/null)
    loc=$(curl -sk -o /dev/null -w "%{redirect_url}" -m $T \
        -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        -d "j_username=$user&j_password=$pass&j_character_encoding=UTF-8" \
        "$BASE/console/j_security_check" 2>/dev/null)
    if [ "$code" = "302" ] && ! echo "$loc" | grep -qi "error\|login\|fail"; then
        echo -e "  ${R}[★ VALID]: $user:$pass → $loc${RS}"
    else
        echo -e "  ${B}$user:$pass → HTTP $code${RS}"
    fi
    sleep 0.2
done

echo -e "\n${W}══════════════════════════════════════════${RS}"
echo -e "${W}  Done — $(date)${RS}"
echo -e "${W}══════════════════════════════════════════${RS}\n"
