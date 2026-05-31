# PII Disclosure Checking Skill — Claude Linux Edition

## SKILL IDENTITY
**Name:** pii-disclosure-checker  
**Version:** 2.0 — Linux Native  
**Scope:** Passive PII exposure discovery — no fuzzing, no exploitation, no breach/leaked DB queries (handled separately by automated tooling)  
**Authorization Required:** Written CISO permission for every target domain before execution

---

## WHEN TO ACTIVATE THIS SKILL

Activate when the user says any of:
- "check [domain] for PII leaks"
- "PII scan [domain]"
- "find exposed PII on [domain]"
- "audit [domain] for data exposure"
- "run PII disclosure check on [domain]"
- "pii-check [domain]"

On activation, extract `{DOMAIN}` from the request and begin Phase 0 immediately.

---

## EXECUTION RULES FOR CLAUDE LINUX

1. **Use `bash_tool` for every command** — never just describe what to run, actually run it
2. **Install missing tools inline** using `pip install --break-system-packages` or `apt-get install -y`
3. **Save all findings to `/home/claude/pii_scan_{DOMAIN}/`** — create this directory first
4. **Write a JSON findings ledger** at `/home/claude/pii_scan_{DOMAIN}/findings.json` — append each finding as discovered
5. **Rate limit all outbound requests** — add `sleep 1` between API calls, `sleep 2` between tool phases
6. **Never print raw PII to terminal** — mask everything beyond first 4 chars (e.g., `john****@company.com`)
7. **Check HTTP status codes** — log non-200 responses but do not retry more than once
8. **Always produce the final report** in `/home/claude/pii_scan_{DOMAIN}/REPORT.md` at the end

---

## PHASE 0: ENVIRONMENT SETUP

Run this block first, every time:

```bash
# Create working directory
DOMAIN="{DOMAIN}"
COMPANY=$(echo $DOMAIN | cut -d'.' -f1)
WORKDIR="/home/claude/pii_scan_${DOMAIN}"
mkdir -p "$WORKDIR"/{subdomains,endpoints,content,headers,cloud,archive,code,api,reports}
cd "$WORKDIR"

# Install required tools
pip install requests dnspython --break-system-packages -q 2>/dev/null
apt-get install -y curl jq whois dnsutils nmap 2>/dev/null | tail -3

# Initialize findings ledger
echo '{"domain":"'$DOMAIN'","scan_started":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","findings":[]}' > findings.json

echo "[+] Environment ready — scanning $DOMAIN"
echo "[+] Working directory: $WORKDIR"
```

---

## PHASE 1: SUBDOMAIN & ASSET ENUMERATION

**Goal:** Build a complete map of the attack surface before looking for PII.

### 1.1 — Certificate Transparency (crt.sh)

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 1.1 — CT log mining via crt.sh"

# Fetch CT records
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
  -H "Accept: application/json" \
  --max-time 30 \
  | jq -r '.[].name_value' 2>/dev/null \
  | tr ',' '\n' \
  | sed 's/\*\.//g' \
  | sort -u \
  | grep -v "^$" \
  > "$WORKDIR/subdomains/crtsh.txt"

COUNT=$(wc -l < "$WORKDIR/subdomains/crtsh.txt")
echo "[+] crt.sh found $COUNT unique subdomains/names"
cat "$WORKDIR/subdomains/crtsh.txt"
```

### 1.2 — CertSpotter API

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 1.2 — CertSpotter CT enumeration"

curl -s "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" \
  --max-time 30 \
  | jq -r '.[].dns_names[]' 2>/dev/null \
  | sort -u \
  | grep -v '\*' \
  > "$WORKDIR/subdomains/certspotter.txt"

echo "[+] CertSpotter: $(wc -l < $WORKDIR/subdomains/certspotter.txt) names"
sleep 1
```

### 1.3 — Passive DNS via HackerTarget

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 1.3 — Passive DNS via HackerTarget"

curl -s "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" \
  --max-time 30 \
  | cut -d',' -f1 \
  | sort -u \
  > "$WORKDIR/subdomains/hackertarget.txt"

echo "[+] HackerTarget: $(wc -l < $WORKDIR/subdomains/hackertarget.txt) hosts"
sleep 1
```

### 1.4 — DNS TXT/MX/SPF Record Analysis

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 1.4 — DNS record analysis (TXT, MX, SPF, DMARC)"

{
  echo "=== MX Records ==="
  dig +short MX $DOMAIN
  echo ""
  echo "=== TXT Records (may reveal internal services) ==="
  dig +short TXT $DOMAIN
  echo ""
  echo "=== SPF (reveals mail infra) ==="
  dig +short TXT $DOMAIN | grep -i spf
  echo ""
  echo "=== DMARC ==="
  dig +short TXT _dmarc.$DOMAIN
  echo ""
  echo "=== DKIM common selectors ==="
  for sel in default google selector1 selector2 mail dkim k1; do
    result=$(dig +short TXT ${sel}._domainkey.$DOMAIN 2>/dev/null)
    [ -n "$result" ] && echo "DKIM selector '$sel': $result"
  done
} | tee "$WORKDIR/subdomains/dns_records.txt"

echo ""
echo "[+] DNS records saved — check for internal service names in SPF/TXT"
sleep 1
```

### 1.5 — Subdomain Consolidation & PII-Risk Triage

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 1.5 — Consolidating subdomains and triaging PII risk"

# Merge all sources
cat "$WORKDIR"/subdomains/{crtsh,certspotter,hackertarget}.txt 2>/dev/null \
  | sort -u \
  | grep -E "^[a-zA-Z0-9._-]+\.${DOMAIN//./\\.}$" \
  > "$WORKDIR/subdomains/all_subdomains.txt"

TOTAL=$(wc -l < "$WORKDIR/subdomains/all_subdomains.txt")
echo "[+] Total unique subdomains: $TOTAL"

# Flag high-PII-risk subdomains
echo ""
echo "[!] HIGH PII RISK SUBDOMAINS:"
grep -iE "(hr|payroll|people|recruit|crm|staff|employee|user|customer|account|report|export|analytics|bi\.|data\.|legacy|old\.|admin|portal|internal|intranet|api\.|staging|dev\.|uat\.|test\.)" \
  "$WORKDIR/subdomains/all_subdomains.txt" \
  | tee "$WORKDIR/subdomains/high_risk_subdomains.txt"

echo ""
echo "[+] High-risk subdomains saved to high_risk_subdomains.txt"
```

---

## PHASE 2: HTTP SURFACE SCANNING

**Goal:** For each discovered subdomain, inspect headers, response bodies, and known sensitive paths for PII leakage.

### 2.1 — HTTP Header Analysis (All Subdomains)

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 2.1 — HTTP header inspection"

python3 << 'PYEOF'
import subprocess, json, os, time

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"

subs_file = f"{workdir}/subdomains/all_subdomains.txt"
if not os.path.exists(subs_file):
    print("[!] No subdomains file found, using root domain only")
    targets = [domain]
else:
    with open(subs_file) as f:
        targets = [l.strip() for l in f if l.strip()][:50]  # cap at 50 for speed

SECURITY_HEADERS = [
    'strict-transport-security', 'content-security-policy',
    'x-content-type-options', 'x-frame-options',
    'referrer-policy', 'permissions-policy'
]

results = []
for target in targets:
    for scheme in ['https', 'http']:
        url = f"{scheme}://{target}"
        try:
            r = subprocess.run(
                ['curl', '-sI', '--max-time', '8', '--location', '--max-redirs', '3', url],
                capture_output=True, text=True, timeout=12
            )
            if r.returncode == 0 and r.stdout:
                headers = {}
                status = None
                for line in r.stdout.splitlines():
                    if line.startswith('HTTP/'):
                        status = line.split(' ')[1] if len(line.split(' ')) > 1 else None
                    elif ':' in line:
                        k, v = line.split(':', 1)
                        headers[k.lower().strip()] = v.strip()

                missing_sec = [h for h in SECURITY_HEADERS if h not in headers]
                tech_leak = {k: headers[k] for k in ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'] if k in headers}
                cookie_issues = []
                if 'set-cookie' in headers:
                    cv = headers['set-cookie'].lower()
                    if 'secure' not in cv: cookie_issues.append('missing Secure flag')
                    if 'httponly' not in cv: cookie_issues.append('missing HttpOnly flag')
                    if 'samesite' not in cv: cookie_issues.append('missing SameSite flag')

                entry = {'url': url, 'status': status, 'tech_leak': tech_leak,
                         'missing_security_headers': missing_sec, 'cookie_issues': cookie_issues}
                results.append(entry)

                if tech_leak:
                    print(f"[TECH LEAK] {url} — {tech_leak}")
                if cookie_issues:
                    print(f"[COOKIE]    {url} — {', '.join(cookie_issues)}")
                break
        except Exception:
            pass
    time.sleep(0.3)

with open(f"{workdir}/headers/header_analysis.json", 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n[+] Header analysis complete — {len(results)} hosts scanned")
PYEOF
```

### 2.2 — Sensitive Path Probing (Passive — No Fuzzing)

Only probe well-known, documented paths. Not brute-force.

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 2.2 — Probing known sensitive paths for PII exposure"

python3 << 'PYEOF'
import subprocess, json, os, time, re

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"

# Known PII-sensitive paths — documented, not brute-forced
SENSITIVE_PATHS = [
    '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
    '/.well-known/security.txt', '/.well-known/openid-configuration',
    '/api-docs', '/swagger.json', '/swagger-ui.html', '/swagger-ui/',
    '/openapi.json', '/openapi.yaml', '/api/swagger.json',
    '/v1/swagger.json', '/v2/api-docs', '/v3/api-docs',
    '/graphql', '/graphiql', '/__graphql', '/playground',
    '/.env', '/.env.backup', '/.env.example',
    '/config.json', '/config.yaml', '/settings.json',
    '/phpinfo.php', '/info.php', '/server-status', '/server-info',
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/mappings',
    '/actuator/beans', '/actuator/configprops', '/actuator/info',
    '/health', '/healthz', '/metrics', '/status',
    '/api/v1/users', '/api/v2/users', '/api/users',
    '/api/v1/customers', '/api/v1/employees', '/api/v1/accounts',
    '/admin', '/admin/', '/admin/users', '/dashboard',
    '/wp-json/wp/v2/users',  # WordPress user enum
    '/xmlrpc.php',
    '/debug', '/debug/vars', '/debug/pprof',
    '/_cat/indices', '/_cluster/health',  # Elasticsearch
    '/api/v1/namespaces',  # Kubernetes
    '/console', '/h2-console',  # Database consoles
]

subs_file = f"{workdir}/subdomains/high_risk_subdomains.txt"
targets = [domain]
if os.path.exists(subs_file):
    with open(subs_file) as f:
        targets += [l.strip() for l in f if l.strip()][:20]

findings = []
pii_patterns = {
    'email':       re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'phone':       re.compile(r'\+?[\d\s\-().]{9,18}\d'),
    'jwt':         re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
    'aws_key':     re.compile(r'AKIA[0-9A-Z]{16}'),
    'private_key': re.compile(r'-----BEGIN.{0,20}PRIVATE KEY-----'),
    'api_key':     re.compile(r'(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}'),
    'ssn':         re.compile(r'\b\d{3}[-\s]\d{2}[-\s]\d{4}\b'),
    'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
}

for target in targets:
    for path in SENSITIVE_PATHS:
        url = f"https://{target}{path}"
        try:
            r = subprocess.run(
                ['curl', '-s', '--max-time', '8', '-o', '/tmp/pii_probe_body',
                 '-w', '%{http_code}|%{content_type}', '--location', '--max-redirs', '2', url],
                capture_output=True, text=True, timeout=12
            )
            if r.returncode == 0:
                parts = r.stdout.strip().split('|')
                status = parts[0] if parts else '0'
                ctype = parts[1] if len(parts) > 1 else ''

                if status in ['200', '206']:
                    try:
                        with open('/tmp/pii_probe_body', 'r', errors='ignore') as bf:
                            body = bf.read(50000)  # cap at 50KB
                    except: body = ''

                    pii_hits = {}
                    for ptype, pat in pii_patterns.items():
                        matches = pat.findall(body)
                        if matches:
                            pii_hits[ptype] = len(set(matches))

                    severity = 'INFO'
                    if any(k in pii_hits for k in ['private_key', 'aws_key', 'credit_card', 'ssn']):
                        severity = 'CRITICAL'
                    elif any(k in pii_hits for k in ['jwt', 'api_key', 'email']):
                        severity = 'HIGH'
                    elif pii_hits:
                        severity = 'MEDIUM'
                    elif path in ['/.env', '/config.json', '/actuator/env', '/actuator/configprops']:
                        severity = 'HIGH'
                    elif path in ['/api-docs', '/swagger.json', '/graphql']:
                        severity = 'MEDIUM'

                    if status == '200':
                        finding = {
                            'url': url, 'path': path, 'status': status,
                            'content_type': ctype, 'pii_hits': pii_hits, 'severity': severity,
                            'body_size': len(body)
                        }
                        findings.append(finding)

                        if severity in ['CRITICAL', 'HIGH']:
                            print(f"[{severity}] {url} — PII: {pii_hits if pii_hits else 'sensitive path exposed'}")
                        elif severity == 'MEDIUM':
                            print(f"[MEDIUM] {url} — {ctype}")

        except Exception as e:
            pass
        time.sleep(0.2)

with open(f"{workdir}/endpoints/sensitive_paths.json", 'w') as f:
    json.dump(findings, f, indent=2)

exposed = [f for f in findings if f['severity'] in ['CRITICAL', 'HIGH', 'MEDIUM']]
print(f"\n[+] Path probe complete — {len(findings)} paths responded 200, {len(exposed)} flagged")
PYEOF
```

### 2.3 — robots.txt & Sitemap Deep Parse

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 2.3 — Deep parse robots.txt and sitemap for hidden routes"

python3 << 'PYEOF'
import subprocess, re, os, urllib.parse

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"

def fetch(url):
    r = subprocess.run(['curl', '-s', '--max-time', '10', url], capture_output=True, text=True, timeout=15)
    return r.stdout if r.returncode == 0 else ''

# robots.txt
robots = fetch(f"https://{domain}/robots.txt")
if robots and 'Disallow' in robots:
    print(f"\n[robots.txt] {domain}:")
    risky = []
    for line in robots.splitlines():
        if line.startswith('Disallow:') or line.startswith('Allow:'):
            path = line.split(':', 1)[1].strip()
            print(f"  {line}")
            if re.search(r'(admin|user|customer|employee|export|report|download|api|data|backup|private|internal|crm|hr)', path, re.I):
                risky.append(path)
    if risky:
        print(f"\n[!] HIGH-INTEREST paths in robots.txt: {risky}")
    with open(f"{workdir}/endpoints/robots_txt.txt", 'w') as f:
        f.write(robots)

# Sitemap — look for data export / report / user management URLs
sitemap = fetch(f"https://{domain}/sitemap.xml")
if '<url>' in sitemap or '<loc>' in sitemap:
    urls = re.findall(r'<loc>(.*?)</loc>', sitemap)
    risky_urls = [u for u in urls if re.search(r'(export|report|download|user|customer|employee|data)', u, re.I)]
    if risky_urls:
        print(f"\n[!] RISKY sitemap URLs ({len(risky_urls)} found):")
        for u in risky_urls[:20]:
            print(f"  {u}")
    with open(f"{workdir}/endpoints/sitemap_urls.txt", 'w') as f:
        f.write('\n'.join(urls))
    print(f"\n[+] Sitemap: {len(urls)} total URLs, {len(risky_urls)} flagged")
PYEOF
```

---

## PHASE 3: API SURFACE DEEP ANALYSIS

**Goal:** Find unauthenticated API endpoints that return or accept PII.

### 3.1 — OpenAPI / Swagger Spec Harvesting & PII Mapping

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 3.1 — API spec harvesting and PII endpoint mapping"

python3 << 'PYEOF'
import subprocess, json, re, os

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"

SPEC_PATHS = [
    '/swagger.json', '/swagger-ui/swagger.json', '/api/swagger.json',
    '/v1/swagger.json', '/v2/api-docs', '/v3/api-docs', '/api-docs',
    '/openapi.json', '/openapi.yaml', '/api/openapi.json',
    '/api/v1/swagger.json', '/api/v2/swagger.json',
    '/docs/swagger.json', '/internal/swagger.json',
]

subs_file = f"{workdir}/subdomains/all_subdomains.txt"
targets = [domain]
if os.path.exists(subs_file):
    with open(subs_file) as f:
        api_subs = [l.strip() for l in f if re.search(r'^(api|gateway|gw|service|backend|internal)', l.strip())]
        targets += api_subs[:15]

PII_FIELDS = {'email', 'phone', 'mobile', 'address', 'ssn', 'dob', 'birthdate',
              'birth_date', 'passport', 'national_id', 'nic', 'name', 'first_name',
              'last_name', 'full_name', 'gender', 'salary', 'income', 'credit_card',
              'card_number', 'cvv', 'account_number', 'ip_address', 'location',
              'latitude', 'longitude', 'medical', 'health', 'diagnosis', 'password'}

all_pii_endpoints = []

for target in targets:
    for path in SPEC_PATHS:
        url = f"https://{target}{path}"
        r = subprocess.run(['curl', '-s', '--max-time', '10', url], capture_output=True, text=True, timeout=15)
        if r.returncode != 0 or not r.stdout.strip(): continue

        try:
            spec = json.loads(r.stdout)
        except:
            if 'swagger' not in r.stdout.lower() and 'openapi' not in r.stdout.lower():
                continue
            spec = {}

        print(f"\n[API SPEC FOUND] {url}")
        paths = spec.get('paths', {})
        for ep_path, methods in paths.items():
            for method, details in methods.items():
                if not isinstance(details, dict): continue
                # Check for PII in parameters, requestBody, responses
                spec_text = json.dumps(details).lower()
                found_pii = [f for f in PII_FIELDS if f in spec_text]
                requires_auth = bool(details.get('security') or details.get('parameters', [{}])[0].get('in') == 'header')
                if found_pii:
                    entry = {
                        'spec_url': url, 'endpoint': ep_path, 'method': method.upper(),
                        'pii_fields': found_pii, 'authenticated': requires_auth,
                        'severity': 'CRITICAL' if not requires_auth else 'HIGH'
                    }
                    all_pii_endpoints.append(entry)
                    auth_str = "NO AUTH" if not requires_auth else "authenticated"
                    print(f"  [{entry['severity']}] {method.upper()} {ep_path} — PII: {found_pii} ({auth_str})")

with open(f"{workdir}/api/pii_endpoints.json", 'w') as f:
    json.dump(all_pii_endpoints, f, indent=2)

print(f"\n[+] API scan complete — {len(all_pii_endpoints)} PII-exposing endpoints found")
PYEOF
```

### 3.2 — GraphQL Introspection Check

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 3.2 — GraphQL introspection exposure check"

python3 << 'PYEOF'
import subprocess, json, re, os

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"

GQL_PATHS = ['/graphql', '/graphiql', '/__graphql', '/api/graphql',
             '/v1/graphql', '/playground', '/gql', '/query']

INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name } } } }"}'

PII_TYPE_KEYWORDS = {'user', 'customer', 'employee', 'person', 'profile', 'account',
                     'contact', 'address', 'payment', 'order', 'medical', 'health'}

subs_file = f"{workdir}/subdomains/all_subdomains.txt"
targets = [domain]
if os.path.exists(subs_file):
    with open(subs_file) as f:
        targets += [l.strip() for l in f if l.strip()][:10]

for target in targets:
    for path in GQL_PATHS:
        url = f"https://{target}{path}"
        r = subprocess.run([
            'curl', '-s', '--max-time', '10',
            '-X', 'POST', '-H', 'Content-Type: application/json',
            '-d', INTROSPECTION_QUERY, url
        ], capture_output=True, text=True, timeout=15)

        if r.returncode == 0 and '__schema' in r.stdout:
            print(f"\n[CRITICAL] GraphQL introspection ENABLED: {url}")
            try:
                data = json.loads(r.stdout)
                types = data.get('data', {}).get('__schema', {}).get('types', [])
                pii_types = [t for t in types if any(k in t.get('name','').lower() for k in PII_TYPE_KEYWORDS)]
                if pii_types:
                    print(f"  [!] PII-likely types exposed: {[t['name'] for t in pii_types]}")
                    for t in pii_types[:5]:
                        fields = [f['name'] for f in (t.get('fields') or [])]
                        if fields:
                            print(f"    {t['name']}: {fields}")
            except: pass

            with open(f"{workdir}/api/graphql_introspection_{target.replace('.','_')}.json", 'w') as f:
                f.write(r.stdout[:100000])

print("\n[+] GraphQL introspection check complete")
PYEOF
```

### 3.3 — Wayback Machine API Endpoint Mining

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 3.3 — Wayback CDX mining for historical API and data endpoints"

python3 << 'PYEOF'
import subprocess, json, re, os

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"

# Query CDX API for all 200-status URLs
cdx_url = (
    f"http://web.archive.org/cdx/search/cdx"
    f"?url={domain}/*&output=json&fl=original,statuscode,timestamp"
    f"&filter=statuscode:200&collapse=urlkey&matchType=domain&limit=2000"
)

print(f"[*] Querying Wayback CDX API...")
r = subprocess.run(['curl', '-s', '--max-time', '30', cdx_url], capture_output=True, text=True, timeout=35)

if r.returncode != 0 or not r.stdout.strip():
    print("[!] CDX API unavailable or no results")
else:
    try:
        records = json.loads(r.stdout)
        urls = [rec[0] for rec in records[1:] if rec]  # skip header

        # Filter for high-interest patterns
        PII_URL_PATTERNS = re.compile(
            r'(\.(csv|xls|xlsx|json|xml|sql|log|bak|backup|dump|tar|gz|zip|env)'
             r'|/api/|/export|/download|/report|/users|/customers|/employees'
             r'|/admin|/dashboard|/data|/backup|/debug|/config|/credentials'
             r'|actuator|swagger|graphql|openapi)',
            re.IGNORECASE
        )

        flagged = [u for u in urls if PII_URL_PATTERNS.search(u)]

        with open(f"{workdir}/archive/all_wayback_urls.txt", 'w') as f:
            f.write('\n'.join(urls))
        with open(f"{workdir}/archive/flagged_wayback_urls.txt", 'w') as f:
            f.write('\n'.join(flagged))

        print(f"[+] CDX results: {len(urls)} total URLs, {len(flagged)} flagged")
        print("\n[!] FLAGGED HISTORICAL URLS (sample):")
        for u in flagged[:30]:
            print(f"  {u}")

        # Check if flagged historical endpoints still live
        print("\n[*] Probing top flagged historical endpoints for liveness...")
        live_count = 0
        for url in flagged[:20]:
            r2 = subprocess.run(
                ['curl', '-sI', '--max-time', '6', '-o', '/dev/null', '-w', '%{http_code}', url],
                capture_output=True, text=True, timeout=10
            )
            if r2.stdout.strip() == '200':
                print(f"  [LIVE 200] {url}")
                live_count += 1

        print(f"\n[+] {live_count} historical flagged endpoints still live")

    except json.JSONDecodeError:
        print("[!] CDX response was not valid JSON")

PYEOF

sleep 2
```

---

## PHASE 4: CLOUD STORAGE EXPOSURE

**Goal:** Discover publicly accessible cloud buckets belonging to the company.

### 4.1 — S3 / GCS / Azure Bucket Enumeration

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 4.1 — Cloud storage bucket exposure check"

python3 << 'PYEOF'
import subprocess, json, os, re

domain = os.environ.get('DOMAIN', '')
company = domain.split('.')[0]
workdir = f"/home/claude/pii_scan_{domain}"

# Generate bucket name variants
variants = []
for base in [company, domain.replace('.', '-'), domain.replace('.', '')]:
    variants += [
        base, f"{base}-backup", f"{base}-backups", f"{base}-data",
        f"{base}-exports", f"{base}-export", f"{base}-prod",
        f"{base}-production", f"{base}-dev", f"{base}-development",
        f"{base}-staging", f"{base}-uat", f"{base}-logs",
        f"{base}-assets", f"{base}-static", f"{base}-media",
        f"{base}-uploads", f"{base}-files", f"{base}-reports",
        f"{base}-hr", f"{base}-finance", f"{base}-analytics",
        f"{base}-crm", f"{base}-database", f"{base}-dump",
        f"backup-{base}", f"data-{base}", f"files-{base}",
    ]

variants = list(dict.fromkeys(variants))  # dedupe preserving order
print(f"[*] Testing {len(variants)} bucket name variants")

open_buckets = []

for bucket in variants:
    # S3
    s3_url = f"https://{bucket}.s3.amazonaws.com"
    r = subprocess.run(
        ['curl', '-sI', '--max-time', '6', '-w', '\n%{http_code}', s3_url],
        capture_output=True, text=True, timeout=10
    )
    lines = r.stdout.strip().splitlines()
    status = lines[-1] if lines else '0'
    if status == '200':
        # Try to list contents
        r2 = subprocess.run(['curl', '-s', '--max-time', '8', s3_url], capture_output=True, text=True, timeout=12)
        print(f"[OPEN S3] {s3_url}")
        # Check for PII file types in listing
        if any(ext in r2.stdout for ext in ['.csv', '.xls', '.json', '.sql', '.log', '.bak']):
            print(f"  [!!!] DATA FILES LISTED IN BUCKET")
        open_buckets.append({'url': s3_url, 'type': 's3', 'listing': 'yes' if '<Key>' in r2.stdout else 'no'})
    elif status == '403':
        # Bucket exists but access denied — note it
        pass  # not a vulnerability, skip

    # GCS
    gcs_url = f"https://storage.googleapis.com/{bucket}"
    r = subprocess.run(
        ['curl', '-sI', '--max-time', '6', '-w', '\n%{http_code}', gcs_url],
        capture_output=True, text=True, timeout=10
    )
    lines = r.stdout.strip().splitlines()
    status = lines[-1] if lines else '0'
    if status == '200':
        print(f"[OPEN GCS] {gcs_url}")
        open_buckets.append({'url': gcs_url, 'type': 'gcs'})

    # Azure Blob
    azure_url = f"https://{bucket}.blob.core.windows.net/{bucket}"
    r = subprocess.run(
        ['curl', '-sI', '--max-time', '6', '-w', '\n%{http_code}', azure_url],
        capture_output=True, text=True, timeout=10
    )
    lines = r.stdout.strip().splitlines()
    status = lines[-1] if lines else '0'
    if status in ['200', '206']:
        print(f"[OPEN AZURE] {azure_url}")
        open_buckets.append({'url': azure_url, 'type': 'azure'})

with open(f"{workdir}/cloud/open_buckets.json", 'w') as f:
    json.dump(open_buckets, f, indent=2)

print(f"\n[+] Bucket scan complete — {len(open_buckets)} open buckets found")
if open_buckets:
    print("[!!!] OPEN BUCKETS FOUND — CRITICAL FINDING — ESCALATE IMMEDIATELY")
PYEOF

sleep 1
```

### 4.2 — GrayhatWarfare Bucket Search (Web)

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 4.2 — GrayhatWarfare public bucket index search"

COMPANY=$(echo $DOMAIN | cut -d'.' -f1)

# GrayhatWarfare has a search API — query for company name
curl -s "https://buckets.grayhatwarfare.com/api/v2/buckets?keywords=${COMPANY}&limit=20&start=0" \
  -H "Accept: application/json" \
  --max-time 15 \
  | jq -r '.buckets[]? | "\(.provider) | \(.bucket) | files: \(.files)"' 2>/dev/null \
  | tee "$WORKDIR/cloud/grayhatwarfare_results.txt"

echo ""
echo "[+] GrayhatWarfare search complete"
sleep 1
```

### 4.3 — Firebase / Firestore Exposure

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 4.3 — Firebase database exposure check"

COMPANY=$(echo $DOMAIN | cut -d'.' -f1)

python3 << 'PYEOF'
import subprocess, json, os

domain = os.environ.get('DOMAIN', '')
company = domain.split('.')[0]
workdir = f"/home/claude/pii_scan_{domain}"

firebase_variants = [
    company, f"{company}-default-rtdb", f"{company}-prod",
    f"{company}-app", f"{company}-api", f"{company}-backend",
    f"{company}-dev", f"{company}-staging",
]

open_firebase = []
for db in firebase_variants:
    url = f"https://{db}-default-rtdb.firebaseio.com/.json?shallow=true"
    r = subprocess.run(
        ['curl', '-s', '--max-time', '8', '-w', '\n%{http_code}', url],
        capture_output=True, text=True, timeout=12
    )
    lines = r.stdout.strip().splitlines()
    status = lines[-1] if lines else '0'
    body = '\n'.join(lines[:-1])

    if status == '200' and body not in ['null', '{}', '']:
        print(f"[CRITICAL] Open Firebase DB: {url}")
        print(f"  Keys: {body[:200]}")
        open_firebase.append({'url': url, 'preview': body[:200]})
    elif status == '200':
        pass  # empty db, not a finding

with open(f"{workdir}/cloud/firebase_exposure.json", 'w') as f:
    json.dump(open_firebase, f, indent=2)

print(f"[+] Firebase check complete — {len(open_firebase)} open instances found")
PYEOF
```

---

## PHASE 5: CODE REPOSITORY SCANNING

**Goal:** Find PII and credentials leaked in public code repositories.

### 5.1 — GitHub Public Repository Scan

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 5.1 — GitHub public repository scan"

# Note: For best results export GITHUB_TOKEN before running
# export GITHUB_TOKEN="ghp_yourtoken"

python3 << 'PYEOF'
import subprocess, json, os, re, urllib.parse, time

domain = os.environ.get('DOMAIN', '')
company = domain.split('.')[0]
workdir = f"/home/claude/pii_scan_{domain}"
token = os.environ.get('GITHUB_TOKEN', '')

headers = ['-H', 'Accept: application/vnd.github.v3+json']
if token:
    headers += ['-H', f'Authorization: token {token}']
else:
    print("[!] No GITHUB_TOKEN set — rate limits apply (10 req/min unauthenticated)")

SEARCH_QUERIES = [
    f'"{domain}" password',
    f'"{domain}" secret',
    f'"{domain}" api_key OR apikey',
    f'"{domain}" email OR phone',
    f'"{domain}" filename:.env',
    f'"{company}" db_password OR database_url',
    f'"{company}" BEGIN RSA PRIVATE KEY',
    f'"{company}" access_token OR auth_token',
    f'"{company}" AWS_SECRET OR AWS_ACCESS',
    f'"{domain}" filename:config.json',
    f'"{domain}" filename:credentials',
    f'"{domain}" filename:*.sql',
]

all_code_findings = []
for query in SEARCH_QUERIES:
    encoded = urllib.parse.quote(query)
    url = f"https://api.github.com/search/code?q={encoded}&per_page=10"
    r = subprocess.run(
        ['curl', '-s', '--max-time', '15', url] + headers,
        capture_output=True, text=True, timeout=20
    )
    if r.returncode != 0: continue
    try:
        data = json.loads(r.stdout)
        items = data.get('items', [])
        if items:
            print(f"\n[GH LEAK] Query: {query} — {len(items)} results")
            for item in items[:5]:
                print(f"  {item.get('html_url', '')}")
                print(f"    Repo: {item.get('repository', {}).get('full_name', '')} | File: {item.get('name', '')}")
                all_code_findings.append({
                    'query': query,
                    'url': item.get('html_url'),
                    'repo': item.get('repository', {}).get('full_name'),
                    'file': item.get('name'),
                    'severity': 'CRITICAL' if any(k in query for k in ['password','secret','PRIVATE KEY','AWS_SECRET','api_key']) else 'HIGH'
                })
    except: pass
    time.sleep(6 if not token else 2)  # respect rate limits

with open(f"{workdir}/code/github_findings.json", 'w') as f:
    json.dump(all_code_findings, f, indent=2)

print(f"\n[+] GitHub scan complete — {len(all_code_findings)} code findings")
PYEOF

sleep 2
```

### 5.2 — GitLab Public Repo Search

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 5.2 — GitLab public repository search"

COMPANY=$(echo $DOMAIN | cut -d'.' -f1)

python3 << 'PYEOF'
import subprocess, json, os, urllib.parse, time

domain = os.environ.get('DOMAIN', '')
company = domain.split('.')[0]
workdir = f"/home/claude/pii_scan_{domain}"

queries = [f'"{domain}"', f'"{domain}" password', f'"{domain}" secret', f'"{company}" api_key']

for q in queries:
    encoded = urllib.parse.quote(q)
    url = f"https://gitlab.com/api/v4/search?scope=blobs&search={encoded}&per_page=5"
    r = subprocess.run(['curl', '-s', '--max-time', '15', url], capture_output=True, text=True, timeout=20)
    if r.returncode == 0:
        try:
            items = json.loads(r.stdout)
            if items and isinstance(items, list):
                print(f"[GL] Query '{q}' — {len(items)} results")
                for item in items[:3]:
                    print(f"  {item.get('path', '')} in {item.get('project_id', '')}")
        except: pass
    time.sleep(2)

print("\n[+] GitLab scan complete")
PYEOF
```

---

## PHASE 6: EMAIL & IDENTITY OSINT

**Goal:** Map publicly exposed company email addresses and identity data.

### 6.1 — Hunter.io Email Harvesting

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 6.1 — Hunter.io email OSINT"
# Note: Set HUNTER_API_KEY env var for best results
# export HUNTER_API_KEY="your_key"

python3 << 'PYEOF'
import subprocess, json, os, re

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"
api_key = os.environ.get('HUNTER_API_KEY', '')

if api_key:
    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}&limit=100"
    r = subprocess.run(['curl', '-s', '--max-time', '15', url], capture_output=True, text=True, timeout=20)
    try:
        data = json.loads(r.stdout)
        emails = data.get('data', {}).get('emails', [])
        pattern = data.get('data', {}).get('pattern', 'unknown')
        print(f"[+] Hunter.io: {len(emails)} emails found")
        print(f"[+] Email pattern: {pattern}")
        for e in emails[:10]:
            masked = e['value'][:4] + '****@' + e['value'].split('@')[1]
            print(f"  {masked} — {e.get('type','')} — confidence: {e.get('confidence','')}%")
        with open(f"{workdir}/endpoints/hunter_emails.json", 'w') as f:
            json.dump({'count': len(emails), 'pattern': pattern, 'sample': emails[:5]}, f, indent=2)
    except: print("[!] Hunter.io parse error")
else:
    # Fallback: scrape public Hunter.io page
    r = subprocess.run(
        ['curl', '-s', '--max-time', '15', f'https://hunter.io/domain-search/{domain}',
         '-H', 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'],
        capture_output=True, text=True, timeout=20
    )
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain), r.stdout)
    unique = list(set(emails))
    print(f"[+] Hunter.io (web): {len(unique)} emails found in page source")
    for e in unique[:10]:
        print(f"  {e[:4]}****@{e.split('@')[1]}")

print("\n[+] Email harvesting complete")
PYEOF

sleep 1
```

### 6.2 — LinkedIn OSINT via Google Dork

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 6.2 — LinkedIn OSINT dork generation"

COMPANY=$(echo $DOMAIN | cut -d'.' -f1)

echo ""
echo "=== MANUAL LINKEDIN DORKS (run in browser) ==="
echo "These dorks should be run in Google to enumerate employee PII exposure:"
echo ""
echo "1. Employee enumeration:"
echo "   site:linkedin.com/in \"${COMPANY}\" \"email\" OR \"phone\""
echo ""
echo "2. Employee + role mapping:"
echo "   site:linkedin.com \"${COMPANY}\" (CTO OR CFO OR CISO OR \"Head of\" OR VP OR Director)"
echo ""
echo "3. Former employees with sensitive info:"
echo "   site:linkedin.com \"former\" \"${COMPANY}\" (engineer OR developer OR DBA OR sysadmin)"
echo ""
echo "4. Exposed contact info in bios:"
echo "   site:linkedin.com \"${DOMAIN}\" (gmail.com OR yahoo.com OR phone)"
echo ""
echo "=== END OF DORK LIST ===" | tee "$WORKDIR/endpoints/linkedin_dorks.txt"
```

---

## PHASE 7: CONTENT DOWNLOAD & PII VERIFICATION

**Goal:** For every flagged URL, download content and run deep PII pattern matching.

### 7.1 — PII Scanner Engine

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 7.1 — Deep PII pattern verification on all flagged content"

python3 << 'PYEOF'
import re, json, os, subprocess, hashlib
from pathlib import Path

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"

PII_PATTERNS = {
    'email':            (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), 'HIGH'),
    'phone_intl':       (re.compile(r'\+(?:[0-9] ?){8,14}[0-9]'), 'HIGH'),
    'phone_us':         (re.compile(r'\b(\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b'), 'HIGH'),
    'ssn':              (re.compile(r'\b\d{3}[-\s]\d{2}[-\s]\d{4}\b'), 'CRITICAL'),
    'credit_card_visa': (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'), 'CRITICAL'),
    'credit_card_mc':   (re.compile(r'\b5[1-5][0-9]{14}\b'), 'CRITICAL'),
    'credit_card_amex': (re.compile(r'\b3[47][0-9]{13}\b'), 'CRITICAL'),
    'iban':             (re.compile(r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]{0,16})\b'), 'CRITICAL'),
    'passport':         (re.compile(r'\b[A-Z]{1,2}[0-9]{6,9}\b'), 'HIGH'),
    'dob':              (re.compile(r'\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])[\/\-](19|20)\d{2}\b'), 'HIGH'),
    'ip_address':       (re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'), 'LOW'),
    'jwt_token':        (re.compile(r'eyJ[a-zA-Z0-9_-]{2,}\.eyJ[a-zA-Z0-9_-]{2,}\.[a-zA-Z0-9_-]{2,}'), 'CRITICAL'),
    'aws_access_key':   (re.compile(r'AKIA[0-9A-Z]{16}'), 'CRITICAL'),
    'aws_secret_key':   (re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']?[A-Za-z0-9/+=]{40}'), 'CRITICAL'),
    'private_key':      (re.compile(r'-----BEGIN.{0,30}PRIVATE KEY-----'), 'CRITICAL'),
    'api_key':          (re.compile(r'(?i)(api[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}'), 'CRITICAL'),
    'google_api_key':   (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 'CRITICAL'),
    'stripe_key':       (re.compile(r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}'), 'CRITICAL'),
    'nic_lk':           (re.compile(r'\b\d{9}[VvXx]\b|\b\d{12}\b'), 'CRITICAL'),  # Sri Lanka NIC
    'password_hash':    (re.compile(r'\$(?:2[aby]|1|5|6)\$[./A-Za-z0-9]+'), 'CRITICAL'),
    'db_conn_string':   (re.compile(r'(?i)(mysql|postgresql|mongodb|redis|mssql):\/\/[^:\s]+:[^@\s]+@'), 'CRITICAL'),
}

def mask_pii(value, ptype):
    s = str(value)
    if len(s) <= 8: return '****'
    return s[:4] + ('*' * (len(s) - 8)) + s[-4:]

def scan_text(text, source_url=''):
    findings = {}
    for ptype, (pattern, severity) in PII_PATTERNS.items():
        matches = list(set(pattern.findall(text)))
        if matches:
            findings[ptype] = {
                'count': len(matches),
                'severity': severity,
                'sample': mask_pii(matches[0], ptype),
                'source': source_url
            }
    return findings

# Collect all flagged URLs from previous phases
all_flagged_urls = []

flagged_file = f"{workdir}/archive/flagged_wayback_urls.txt"
if os.path.exists(flagged_file):
    with open(flagged_file) as f:
        all_flagged_urls += [l.strip() for l in f if l.strip()][:30]

sens_file = f"{workdir}/endpoints/sensitive_paths.json"
if os.path.exists(sens_file):
    with open(sens_file) as f:
        items = json.load(f)
        all_flagged_urls += [i['url'] for i in items if i.get('status') == '200']

all_flagged_urls = list(set(all_flagged_urls))[:50]
print(f"[*] Deep scanning {len(all_flagged_urls)} flagged URLs for PII")

deep_findings = []
for url in all_flagged_urls:
    r = subprocess.run(
        ['curl', '-s', '--max-time', '10', url],
        capture_output=True, text=True, timeout=15
    )
    if r.returncode == 0 and r.stdout:
        results = scan_text(r.stdout, url)
        if results:
            deep_findings.append({'url': url, 'pii': results})
            print(f"\n[PII FOUND] {url}")
            for ptype, info in results.items():
                print(f"  [{info['severity']}] {ptype}: {info['count']} instances — sample: {info['sample']}")

with open(f"{workdir}/content/deep_pii_scan.json", 'w') as f:
    json.dump(deep_findings, f, indent=2)

print(f"\n[+] Deep PII scan complete — {len(deep_findings)} URLs contain PII")
PYEOF
```

---

## PHASE 8: FINAL REPORT GENERATION

Run this last. Consolidates all findings into a CISO-ready report.

```bash
DOMAIN="{DOMAIN}"
WORKDIR="/home/claude/pii_scan_${DOMAIN}"

echo "[*] Phase 8 — Generating final report"

python3 << 'PYEOF'
import json, os
from datetime import datetime, timezone

domain = os.environ.get('DOMAIN', '')
workdir = f"/home/claude/pii_scan_{domain}"
now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

# Load all findings from previous phases
def load_json(path, default=[]):
    try:
        with open(path) as f: return json.load(f)
    except: return default

subdomains     = open(f"{workdir}/subdomains/all_subdomains.txt").read().splitlines() if os.path.exists(f"{workdir}/subdomains/all_subdomains.txt") else []
high_risk_subs = open(f"{workdir}/subdomains/high_risk_subdomains.txt").read().splitlines() if os.path.exists(f"{workdir}/subdomains/high_risk_subdomains.txt") else []
sensitive_paths = load_json(f"{workdir}/endpoints/sensitive_paths.json")
api_endpoints   = load_json(f"{workdir}/api/pii_endpoints.json")
github_findings = load_json(f"{workdir}/code/github_findings.json")
open_buckets    = load_json(f"{workdir}/cloud/open_buckets.json")
deep_pii        = load_json(f"{workdir}/content/deep_pii_scan.json")
wayback_flagged = open(f"{workdir}/archive/flagged_wayback_urls.txt").read().splitlines() if os.path.exists(f"{workdir}/archive/flagged_wayback_urls.txt") else []

# Severity counts
all_findings = []
all_findings += [{'src': 'Cloud Storage', 'sev': 'CRITICAL', 'desc': f"Open bucket: {b['url']}"} for b in open_buckets]
all_findings += [{'src': 'Deep PII Scan', 'sev': max((v['severity'] for v in f['pii'].values()), key=lambda s: ['LOW','MEDIUM','HIGH','CRITICAL'].index(s)), 'desc': f"PII in {f['url']}: {list(f['pii'].keys())}"} for f in deep_pii]
all_findings += [{'src': 'API Surface', 'sev': e['severity'], 'desc': f"{e['method']} {e['endpoint']} exposes {e['pii_fields']}"} for e in api_endpoints]
all_findings += [{'src': 'GitHub', 'sev': f['severity'], 'desc': f"Credential/PII leak in {f.get('repo','unknown')}: {f.get('file','')}"} for f in github_findings]
all_findings += [{'src': 'Sensitive Paths', 'sev': p['severity'], 'desc': f"{p['url']} returned 200 — {p.get('pii_hits','')}"} for p in sensitive_paths if p.get('severity') in ['CRITICAL','HIGH','MEDIUM']]

critical = [f for f in all_findings if f['sev'] == 'CRITICAL']
high     = [f for f in all_findings if f['sev'] == 'HIGH']
medium   = [f for f in all_findings if f['sev'] == 'MEDIUM']
low      = [f for f in all_findings if f['sev'] == 'LOW']

risk_score = min(100, len(critical)*25 + len(high)*10 + len(medium)*3 + len(low)*1)

report = f"""# PII Disclosure Assessment Report
**Target Domain:** {domain}  
**Scan Date:** {now}  
**Classification:** CONFIDENTIAL — CISO EYES ONLY  
**Authorization:** Written CISO permission on file  

---

## Executive Summary

Passive PII disclosure assessment of `{domain}` completed across {len(subdomains)} discovered subdomains.
The scan identified **{len(all_findings)} exposure points** with an aggregate risk score of **{risk_score}/100**.

| Severity | Count |
|---|---|
| 🔴 CRITICAL | {len(critical)} |
| 🟠 HIGH | {len(high)} |
| 🟡 MEDIUM | {len(medium)} |
| 🟢 LOW | {len(low)} |

{"⚠️  **GDPR Art. 33 assessment required** — critical findings may trigger 72-hour notification obligation." if critical else ""}

---

## Attack Surface Summary

- **Total subdomains discovered:** {len(subdomains)}
- **High PII-risk subdomains:** {len(high_risk_subs)}
- **Sensitive paths returning HTTP 200:** {len([p for p in sensitive_paths if p.get('status')=='200'])}
- **PII-exposing API endpoints:** {len(api_endpoints)}
- **Open cloud storage buckets:** {len(open_buckets)}
- **GitHub code findings:** {len(github_findings)}
- **Wayback flagged historical URLs:** {len(wayback_flagged)}
- **URLs confirmed containing PII:** {len(deep_pii)}

---

## Critical Findings

"""

for i, f in enumerate(critical, 1):
    report += f"### CRIT-{i:03d} [{f['src']}]\n**{f['desc']}**\n\n"

report += """---

## High Severity Findings

"""
for i, f in enumerate(high, 1):
    report += f"### HIGH-{i:03d} [{f['src']}]\n{f['desc']}\n\n"

if medium:
    report += "---\n\n## Medium Severity Findings\n\n"
    for i, f in enumerate(medium, 1):
        report += f"- **MED-{i:03d}** [{f['src']}]: {f['desc']}\n"

report += f"""
---

## Remediation Roadmap

### Immediate (0–24h) — Critical
"""
if open_buckets:
    report += "- [ ] Set all open cloud buckets to private, enable Block Public Access\n"
if any('GitHub' == f['src'] for f in critical):
    report += "- [ ] Revoke all exposed credentials found in GitHub immediately\n"
if any('Deep PII' == f['src'] for f in critical):
    report += "- [ ] Disable/restrict endpoints confirmed returning PII without authentication\n"
report += "- [ ] Notify DPO — assess GDPR Art. 33 breach notification obligation\n"

report += """
### Short-term (24–72h) — High
- [ ] Review and restrict all unauthenticated API endpoints returning user data
- [ ] Disable GraphQL introspection on all production instances
- [ ] Implement API authentication on all exposed Swagger/OpenAPI docs
- [ ] Rotate any credentials found in git history (even if private repos)

### Medium-term (1–2 weeks)
- [ ] Implement CSP, HSTS, and security headers across all subdomains
- [ ] Archive or decommission high-risk legacy/staging subdomains
- [ ] Audit S3/GCS/Azure bucket ACLs across all accounts
- [ ] Review robots.txt — remove references to sensitive admin paths

### Long-term (30 days)
- [ ] Implement DLP scanning on all data export/download endpoints
- [ ] Set up automated CT log monitoring for new subdomain detection
- [ ] Establish regular passive PII scan schedule (monthly)
- [ ] Request removal from Hunter.io and other email harvesting services

---

## Regulatory Impact Assessment

| Regulation | Relevance | Triggered By |
|---|---|---|
| GDPR Art. 5 | Data minimization violation | Bulk PII in unauthenticated endpoints |
| GDPR Art. 25 | Privacy by design failure | Open API docs, missing auth |
| GDPR Art. 32 | Inadequate technical measures | Open buckets, missing headers |
| GDPR Art. 33 | Breach notification (72h) | If personal data confirmed accessed |
| PCI-DSS Req. 3 | Cardholder data protection | Any credit card data found |
| PCI-DSS Req. 6 | Secure systems | Exposed config/env files |

---

## Evidence Files

All raw evidence is stored at: `{workdir}/`

| Directory | Contents |
|---|---|
| `subdomains/` | CT log results, DNS records, high-risk subdomain list |
| `endpoints/` | Sensitive path probe results, robots.txt, sitemap URLs |
| `api/` | OpenAPI/Swagger findings, GraphQL introspection results |
| `cloud/` | Open bucket list, Firebase exposure, GrayhatWarfare results |
| `archive/` | Wayback CDX results, flagged historical URLs |
| `code/` | GitHub and GitLab code findings |
| `content/` | Deep PII scan results on flagged URLs |
| `headers/` | HTTP header analysis for all subdomains |

---

*Generated by PII Disclosure Checker Skill v2.0 — Claude Linux Edition*  
*Authorized passive assessment only — no fuzzing, no exploitation, no credential testing*
"""

report_path = f"{workdir}/REPORT.md"
with open(report_path, 'w') as f:
    f.write(report)

print(report)
print(f"\n[+] Full report saved to: {report_path}")
print(f"[+] Risk Score: {risk_score}/100")
print(f"[+] Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)} | Low: {len(low)}")
PYEOF
```

---

## QUICK START — FULL SCAN ONE-LINER

To run all phases sequentially on a domain:

```bash
export DOMAIN="company.com"
export GITHUB_TOKEN="ghp_yourtoken"        # optional but recommended
export HUNTER_API_KEY="your_hunter_key"    # optional
# Then run each phase block in order: Phase 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8
```

---

## API KEYS REFERENCE

| Service | Env Var | Free Tier | Purpose |
|---|---|---|---|
| GitHub | `GITHUB_TOKEN` | Yes | Higher rate limits on code search |
| Hunter.io | `HUNTER_API_KEY` | 25 req/month | Email harvesting |
| Shodan | `SHODAN_API_KEY` | $1 one-time | Infrastructure discovery |
| VirusTotal | `VT_API_KEY` | Yes | Passive DNS, subdomain enum |

---

## SCOPE BOUNDARIES

**This skill performs ONLY:**
- Passive HTTP requests to discovered endpoints (no auth attempts)
- Public CT log and DNS queries
- Publicly available API queries (GitHub search, Hunter.io, etc.)
- Cloud storage HEAD requests to check public accessibility
- Regex pattern matching on publicly accessible response bodies
- No brute forcing, fuzzing, credential testing, or exploitation

**Breach / leaked database lookups are excluded** — handled by separate automated tooling per CISO directive.

---

*Authorized use only. Written CISO permission required for every target domain.*
