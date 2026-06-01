# PII Disclosure Checker

> Authorized passive reconnaissance skill for detecting exposed Personally Identifiable Information across public-facing company assets. Built for Claude Linux (computer use) environments.

---

## Table of Contents

1. [Overview](#overview)
2. [Legal & Authorization Requirements](#legal--authorization-requirements)
3. [Security Standards Compliance](#security-standards-compliance)
4. [Architecture](#architecture)
5. [Prerequisites](#prerequisites)
6. [Installation](#installation)
7. [Configuration](#configuration)
8. [Usage](#usage)
9. [Scan Phases](#scan-phases)
10. [PII Detection Patterns](#pii-detection-patterns)
11. [Output & Reporting](#output--reporting)
12. [Severity Classification](#severity-classification)
13. [Regulatory Impact Matrix](#regulatory-impact-matrix)
14. [Remediation SLAs](#remediation-slas)
15. [Scope Boundaries](#scope-boundaries)
16. [Contributing](#contributing)
17. [License](#license)

---

## Overview

The **PII Disclosure Checker** is a structured, passive security assessment skill designed to detect unintentional exposure of personally identifiable information across a company's public digital surface. It operates exclusively within authorized boundaries, using no fuzzing, brute-forcing, credential testing, or active exploitation techniques.

The skill is designed to be loaded into a Claude Linux (computer use) session. Claude reads the `PII_DISCLOSURE_SKILL.md` instruction file and executes each phase using bash and Python tooling available in the container environment.

```
┌─────────────────────────────────────────────────────┐
│              PII Disclosure Checker                  │
│                                                     │
│   Input: Authorized domain                          │
│   Engine: Claude Linux (computer use)               │
│   Method: Passive reconnaissance only               │
│   Output: REPORT.md + structured JSON findings      │
└─────────────────────────────────────────────────────┘
```

### What It Does

- Enumerates all subdomains and assets via certificate transparency logs and passive DNS
- Probes 50+ documented sensitive paths for PII exposure
- Parses OpenAPI, Swagger, and GraphQL schemas for unauthenticated PII-returning endpoints
- Mines the Wayback Machine CDX API for historical data-exposure endpoints
- Tests cloud storage buckets (S3, GCS, Azure Blob, Firebase) for public accessibility
- Searches public GitHub and GitLab repositories for leaked credentials and PII
- Harvests publicly exposed company email addresses via OSINT sources
- Runs 22-pattern deep PII regex verification on all flagged content
- Generates a structured CISO-ready report with regulatory impact assessment

### What It Does Not Do

- No fuzzing or brute-force path enumeration
- No credential stuffing or authentication testing
- No active vulnerability exploitation
- No breach database or leaked credential database queries (handled by separate automated tooling)
- No modification of any discovered data

---

## Legal & Authorization Requirements

> **⚠ This tool must only be used against domains you own or have explicit written authorization to test.**

### Mandatory Pre-Conditions

1. **Written CISO authorization** must be obtained and retained on file before any scan is initiated
2. **Domain ownership** must be confirmed — the target must be a company-owned asset
3. **Scope boundaries** must be defined in writing, including which subdomains are in or out of scope
4. **Data handling policy** must cover how scan findings containing PII are stored and destroyed
5. **Responsible disclosure process** must be in place for findings

### Relevant Legal Frameworks

| Jurisdiction | Applicable Law | Key Provision |
|---|---|---|
| European Union | GDPR (Regulation 2016/679) | Art. 32 — technical measures; Art. 33 — breach notification |
| United States | Computer Fraud and Abuse Act (18 U.S.C. § 1030) | Unauthorized access prohibition |
| United States | CCPA (Cal. Civ. Code § 1798.100) | Consumer data rights |
| United Kingdom | UK GDPR / Data Protection Act 2018 | Equivalent to EU GDPR post-Brexit |
| Sri Lanka | Personal Data Protection Act No. 9 of 2022 | Data controller obligations |
| India | Digital Personal Data Protection Act 2023 | Data fiduciary obligations |
| Global | ISO/IEC 27001:2022 | Information security management |

### Unauthorized Use

Scanning domains without written authorization may violate:

- Computer fraud statutes in your jurisdiction
- Data protection regulations (GDPR Art. 83 fines up to €20M or 4% of global turnover)
- Terms of service of third-party services used during the scan

---

## Security Standards Compliance

This skill is designed and operated in alignment with the following international standards and frameworks:

### OWASP

| Standard | Version | Relevance |
|---|---|---|
| OWASP Testing Guide | v4.2 | Passive recon methodology |
| OWASP API Security Top 10 | 2023 | API surface analysis phases |
| OWASP Top 10 | 2021 | A01 Broken Access Control, A02 Cryptographic Failures |

### NIST

| Standard | Publication | Relevance |
|---|---|---|
| NIST SP 800-53 Rev. 5 | 2020 | RA-5 Vulnerability Monitoring, SI-7 Software Integrity |
| NIST SP 800-122 | 2010 | PII confidentiality protection guide |
| NIST CSF 2.0 | 2024 | Identify function — asset and data discovery |
| NIST SP 800-115 | 2008 | Technical guide to information security testing |

### ISO/IEC

| Standard | Year | Relevance |
|---|---|---|
| ISO/IEC 27001 | 2022 | A.8.8 — Vulnerability management |
| ISO/IEC 27002 | 2022 | 8.12 — Data leakage prevention |
| ISO/IEC 29101 | 2018 | Privacy architecture framework |
| ISO/IEC 27005 | 2022 | Information security risk management |

### PCI DSS

| Requirement | Description | Covered By |
|---|---|---|
| Req. 3 | Protect stored account data | Credit card PII detection patterns |
| Req. 6 | Develop and maintain secure systems | Exposed config and env file detection |
| Req. 11 | Test security regularly | Passive assessment methodology |

---

## Architecture

```
pii-disclosure-checker/
│
├── PII_DISCLOSURE_SKILL.md          ← Main skill file (Claude reads this)
├── README.md                        ← This document
│
└── /home/claude/pii_scan_{DOMAIN}/  ← Runtime output directory (created on scan)
    ├── findings.json                ← Live findings ledger (appended during scan)
    ├── REPORT.md                    ← Final CISO report
    │
    ├── subdomains/
    │   ├── crtsh.txt                ← Certificate transparency results
    │   ├── certspotter.txt          ← CertSpotter API results
    │   ├── hackertarget.txt         ← Passive DNS results
    │   ├── all_subdomains.txt       ← Merged deduplicated subdomain list
    │   ├── high_risk_subdomains.txt ← PII-risk-triaged subdomain list
    │   └── dns_records.txt          ← TXT, MX, SPF, DMARC, DKIM records
    │
    ├── endpoints/
    │   ├── sensitive_paths.json     ← Probed path results with PII hits
    │   ├── robots_txt.txt           ← robots.txt content
    │   ├── sitemap_urls.txt         ← All sitemap URL entries
    │   └── hunter_emails.json       ← Harvested email addresses (masked)
    │
    ├── api/
    │   ├── pii_endpoints.json       ← API endpoints exposing PII fields
    │   └── graphql_introspection_*  ← GraphQL schema dumps
    │
    ├── cloud/
    │   ├── open_buckets.json        ← Public cloud storage buckets
    │   ├── grayhatwarfare_results.txt
    │   └── firebase_exposure.json
    │
    ├── archive/
    │   ├── all_wayback_urls.txt     ← All CDX URLs (up to 2000)
    │   └── flagged_wayback_urls.txt ← PII-pattern-matched historical URLs
    │
    ├── code/
    │   ├── github_findings.json     ← GitHub code search results
    │   └── gitlab_findings.json     ← GitLab search results
    │
    ├── content/
    │   └── deep_pii_scan.json       ← Verified PII in response bodies
    │
    └── headers/
        └── header_analysis.json     ← Security header analysis per host
```

---

## Prerequisites

### System Requirements

- Ubuntu 22.04 LTS or later (Claude Linux environment)
- Python 3.10 or later
- curl 7.81 or later
- jq 1.6 or later

### Python Packages

```
requests>=2.31.0
dnspython>=2.4.0
```

### System Packages

```
curl
jq
whois
dnsutils
nmap
```

All dependencies are installed automatically by Phase 0 of the skill. No manual installation is required.

---

## Installation

### Step 1 — Place the skill file

Copy `PII_DISCLOSURE_SKILL.md` to a location accessible within your Claude Linux session:

```bash
cp PII_DISCLOSURE_SKILL.md /mnt/skills/user/pii-disclosure/SKILL.md
```

Or reference it directly from its download path:

```bash
/home/claude/PII_DISCLOSURE_SKILL.md
```

### Step 2 — Load into Claude Linux

In your Claude computer use session, instruct Claude to read and follow the skill:

```
view /path/to/PII_DISCLOSURE_SKILL.md and follow it to scan company.com
```

Claude will read the skill file and begin executing each phase using its bash and Python tools.

### Step 3 — Verify the working directory

After Phase 0 completes, confirm the working directory was created:

```bash
ls /home/claude/pii_scan_company.com/
```

Expected output:

```
subdomains/  endpoints/  content/  headers/  cloud/  archive/  code/  api/  reports/  findings.json
```

---

## Configuration

### Environment Variables

Set these before initiating a scan for enhanced capabilities. None are mandatory — the skill degrades gracefully when keys are absent.

| Variable | Service | Purpose | Free Tier |
|---|---|---|---|
| `GITHUB_TOKEN` | GitHub | Increases code search rate limit from 10 to 30 req/min | Yes |
| `HUNTER_API_KEY` | Hunter.io | Authenticated email harvesting API | 25 req/month |
| `SHODAN_API_KEY` | Shodan | Infrastructure discovery and port scanning | Paid ($1 one-time) |
| `VT_API_KEY` | VirusTotal | Passive DNS and subdomain enumeration | Yes |

### Setting Variables in Claude Linux

```bash
export DOMAIN="company.com"
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
export HUNTER_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### Obtaining a GitHub Token

1. Go to **GitHub → Settings → Developer Settings → Personal Access Tokens → Fine-grained tokens**
2. Create a new token with **no repository access** — public data only
3. Scopes required: none (public search works without scopes)
4. Set expiry to match your assessment window

---

## Usage

### Basic Scan

```
view PII_DISCLOSURE_SKILL.md and PII scan company.com
```

### Scan with GitHub Token

```bash
export GITHUB_TOKEN="ghp_yourtoken"
```
Then:
```
view PII_DISCLOSURE_SKILL.md and run PII disclosure check on company.com
```

### Single Phase Only

```
view PII_DISCLOSURE_SKILL.md — run only Phase 4 (cloud storage) for company.com
```

### Full Scan with Report

```
view PII_DISCLOSURE_SKILL.md and audit company.com for data exposure, run all phases and generate the CISO report
```

### Resume After Interruption

Findings are written to disk after each phase. If a session is interrupted, instruct Claude to:

```
view PII_DISCLOSURE_SKILL.md and run only Phase 8 (report generation) for company.com — previous phase outputs exist at /home/claude/pii_scan_company.com/
```

---

## Scan Phases

| Phase | Name | Duration | Key Output |
|---|---|---|---|
| 0 | Environment setup | < 1 min | Working directory, dependencies |
| 1 | Subdomain & asset enumeration | 2–5 min | `all_subdomains.txt`, `high_risk_subdomains.txt` |
| 2 | HTTP surface scanning | 5–15 min | `sensitive_paths.json`, `header_analysis.json` |
| 3 | API surface deep analysis | 3–8 min | `pii_endpoints.json`, `graphql_introspection_*.json` |
| 4 | Cloud storage exposure | 3–10 min | `open_buckets.json`, `firebase_exposure.json` |
| 5 | Code repository scanning | 5–15 min | `github_findings.json`, `gitlab_findings.json` |
| 6 | Email & identity OSINT | 1–3 min | `hunter_emails.json`, `linkedin_dorks.txt` |
| 7 | Content PII verification | 5–20 min | `deep_pii_scan.json` |
| 8 | Report generation | < 1 min | `REPORT.md`, final risk score |

**Total estimated duration:** 25–75 minutes depending on subdomain count and API rate limits.

---

## Scan Phases — Detailed

### Phase 0 — Environment Setup

Creates the working directory tree, installs Python packages (`requests`, `dnspython`) and system packages (`curl`, `jq`, `whois`, `dnsutils`), and initializes the JSON findings ledger.

---

### Phase 1 — Subdomain & Asset Enumeration

Builds a complete subdomain inventory before any PII-specific work begins. A comprehensive asset map is the foundation of an effective scan — PII leaks often live on forgotten subdomains.

**Sources used:**

1. `crt.sh` — Certificate transparency log aggregator. Queries all publicly trusted CAs for certificates issued to `*.{domain}`. Returns all Subject Alternative Names ever issued.
2. `CertSpotter API` — Secondary CT log source for cross-validation and coverage of CAs not indexed by crt.sh.
3. `HackerTarget HostSearch` — Passive DNS aggregator. Returns hostnames observed resolving to IPs associated with the domain.
4. DNS record analysis — Inspects TXT, MX, SPF, DMARC, and common DKIM selectors. SPF records frequently reveal internal mail relay infrastructure, third-party SaaS integrations, and IP ranges. TXT records sometimes contain internal service identifiers.

**PII-risk triage:** Subdomains matching patterns such as `hr.`, `payroll.`, `people.`, `crm.`, `export.`, `reports.`, `analytics.`, `legacy.`, `staging.`, `admin.` are written to a separate `high_risk_subdomains.txt` file and prioritized in subsequent phases.

---

### Phase 2 — HTTP Surface Scanning

#### 2a — Header Analysis

For every discovered subdomain, a HEAD request is made and the response headers are inspected for:

- **Technology disclosure** — `Server`, `X-Powered-By`, `X-ASPNet-Version`, `X-Generator` headers leak server stack information that assists targeted exploitation by third parties
- **Missing security headers** — `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
- **Cookie security flags** — `Secure`, `HttpOnly`, `SameSite` — absence of these flags on session cookies is a direct PII risk vector

#### 2b — Sensitive Path Probing

Probes 50+ well-known, publicly documented paths. This is not fuzzing — every path in the list is a known framework default, a documented API convention, or an industry-standard well-known URI. Paths include:

- Framework actuator endpoints (`/actuator/env`, `/actuator/configprops`, `/actuator/beans`)
- API documentation endpoints (`/swagger.json`, `/openapi.yaml`, `/v2/api-docs`, `/v3/api-docs`)
- Configuration files (`/.env`, `/config.json`, `/settings.json`)
- Debug interfaces (`/phpinfo.php`, `/debug/vars`, `/h2-console`)
- Database admin consoles (`/_cat/indices`, `/_cluster/health`)
- CMS user enumeration (`/wp-json/wp/v2/users`)
- Kubernetes API (`/api/v1/namespaces`)

Every HTTP 200 response body is immediately scanned with the PII regex engine (Phase 7 patterns).

#### 2c — robots.txt and Sitemap Analysis

Parses `robots.txt` for `Disallow` entries that reveal internal admin, HR, user management, or data export routes. Parses `sitemap.xml` for URLs matching data export, report download, or user account management patterns.

---

### Phase 3 — API Surface Deep Analysis

#### 3a — OpenAPI / Swagger Harvesting

Fetches API specification files from 14 common paths across the root domain and all API-pattern subdomains. For each valid spec found:

- Maps all endpoints to the PII fields they accept or return
- Checks each endpoint's `security` definition to determine if authentication is declared
- Classifies unauthenticated PII-returning endpoints as CRITICAL, authenticated ones as HIGH

PII fields checked against spec definitions: `email`, `phone`, `mobile`, `address`, `ssn`, `dob`, `birthdate`, `passport`, `national_id`, `nic`, `name`, `first_name`, `last_name`, `full_name`, `gender`, `salary`, `income`, `credit_card`, `card_number`, `cvv`, `account_number`, `ip_address`, `location`, `latitude`, `longitude`, `medical`, `health`, `diagnosis`, `password`.

#### 3b — GraphQL Introspection

Sends an introspection query (`{ __schema { types { name fields { name } } } }`) to 8 common GraphQL endpoint paths. If introspection is enabled, the full schema is downloaded and analyzed for type names matching PII-category keywords. Enabled introspection on production GraphQL endpoints is classified as at minimum MEDIUM severity and CRITICAL if unauthenticated PII types are exposed.

#### 3c — Wayback CDX Mining

Queries the Internet Archive CDX API for all HTTP 200 responses ever recorded for the domain (up to 2,000 URLs). Filters results against patterns matching:

- File extensions: `.csv`, `.xls`, `.xlsx`, `.json`, `.xml`, `.sql`, `.log`, `.bak`, `.dump`, `.env`
- Path patterns: `/api/`, `/export`, `/download`, `/report`, `/users`, `/customers`, `/employees`, `/admin`, `/debug`, `/config`, `/actuator`, `/swagger`, `/graphql`

Flagged historical URLs are then probed for liveness — endpoints that existed historically may still be accessible on legacy infrastructure or unreachable via the current application routing but still live on the origin server.

---

### Phase 4 — Cloud Storage Exposure

#### 4a — Bucket Enumeration

Generates a list of likely bucket names from the company name and domain using common suffixes and prefixes: `-backup`, `-data`, `-exports`, `-prod`, `-dev`, `-staging`, `-logs`, `-assets`, `-uploads`, `-reports`, `-hr`, `-finance`, `-analytics`, `-crm`, `-database`, `-dump`, and more.

For each variant, makes HEAD requests to:

- `https://{bucket}.s3.amazonaws.com` — Amazon S3
- `https://storage.googleapis.com/{bucket}` — Google Cloud Storage
- `https://{bucket}.blob.core.windows.net/{bucket}` — Azure Blob Storage

An HTTP 200 response indicates a publicly readable bucket. The bucket is then fetched for a directory listing and the listing is scanned for PII-associated file types.

> Note: HTTP 403 responses indicate the bucket exists but is properly access-controlled. These are not flagged as vulnerabilities.

#### 4b — GrayhatWarfare

Queries the GrayhatWarfare public bucket index API, which maintains a searchable database of known-public cloud storage buckets across all major providers. Searches by company name.

#### 4c — Firebase / Firestore

Tests 8 common Firebase Realtime Database URL patterns for public read access by requesting `/.json?shallow=true`. A non-null, non-empty HTTP 200 response indicates an open database. The shallow response (top-level keys only) is retrieved to assess scope without downloading bulk data.

---

### Phase 5 — Code Repository Scanning

#### 5a — GitHub Public Search

Executes 12 targeted search queries against the GitHub code search API. Queries are designed to surface:

- Hardcoded credentials (passwords, secrets, API keys, access tokens)
- Private key material (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`)
- AWS credential exposure (`AWS_SECRET`, `AWS_ACCESS`)
- Environment files and configuration files containing the domain or company name
- Database connection strings

Without a `GITHUB_TOKEN`, the unauthenticated rate limit is 10 requests per minute. The skill automatically applies a 6-second delay between queries in unauthenticated mode. With a token, the limit is 30 requests per minute and the delay is reduced to 2 seconds.

#### 5b — GitLab Public Search

Queries the GitLab.com public blob search endpoint for the domain name and common credential-related terms. Results include file paths and project IDs for manual review.

---

### Phase 6 — Email & Identity OSINT

#### 6a — Hunter.io Email Harvesting

If a `HUNTER_API_KEY` is set, queries the Hunter.io Domain Search API for all publicly indexed email addresses associated with the domain, including confidence scores, source URLs, and the detected email format pattern (e.g., `{first}.{last}@company.com`).

Without an API key, falls back to parsing the Hunter.io public web response for email addresses in the page source.

All harvested email addresses are masked in output (`john****@company.com`) before being written to disk.

#### 6b — LinkedIn OSINT Dork Generation

Generates ready-to-run Google search dorks targeting LinkedIn for employee enumeration, role mapping, former employee identification, and any LinkedIn profiles that have embedded contact information. These dorks are written to a file for manual execution — LinkedIn does not provide a usable public API and automated scraping violates their terms of service.

---

### Phase 7 — Content PII Verification

For all URLs flagged by previous phases, downloads response bodies (capped at 50 KB per response) and runs the full 22-pattern PII regex engine. This is the verification step — it confirms whether flagged endpoints actually contain PII and classifies the type and severity.

All regex matches are deduplicated and counted. Raw matched values are never printed to the terminal — only masked samples and counts are logged.

---

### Phase 8 — Report Generation

Aggregates all phase outputs from the JSON files on disk into a structured Markdown report. Calculates a weighted risk score (Critical ×25, High ×10, Medium ×3, Low ×1, capped at 100). Produces a remediation roadmap with SLA tiers, a regulatory impact table, and an evidence file index.

---

## PII Detection Patterns

The skill uses the following 22 regex patterns for PII detection across all content:

| Pattern ID | Type | Severity | Example Match |
|---|---|---|---|
| `email` | Email address | HIGH | `user@company.com` |
| `phone_intl` | International phone | HIGH | `+94 77 123 4567` |
| `phone_us` | US phone number | HIGH | `(415) 555-0172` |
| `ssn` | US Social Security Number | CRITICAL | `123-45-6789` |
| `credit_card_visa` | Visa card number | CRITICAL | `4111111111111111` |
| `credit_card_mc` | Mastercard number | CRITICAL | `5500005555555559` |
| `credit_card_amex` | Amex card number | CRITICAL | `371449635398431` |
| `iban` | International bank account | CRITICAL | `GB82WEST12345698765432` |
| `passport` | Passport number | HIGH | `A1234567` |
| `dob` | Date of birth | HIGH | `15/03/1988` |
| `ip_address` | IPv4 address | LOW | `192.168.1.100` |
| `jwt_token` | JSON Web Token | CRITICAL | `eyJhbGci...` |
| `aws_access_key` | AWS access key ID | CRITICAL | `AKIAIOSFODNN7EXAMPLE` |
| `aws_secret_key` | AWS secret access key | CRITICAL | `wJalrXUtnFEMI/K7MDENG...` |
| `private_key` | PEM private key | CRITICAL | `-----BEGIN RSA PRIVATE KEY-----` |
| `api_key` | Generic API/secret key | CRITICAL | `api_key=sk_live_abc123...` |
| `google_api_key` | Google API key | CRITICAL | `AIzaSyD...` |
| `stripe_key` | Stripe secret/publishable key | CRITICAL | `sk_live_...` |
| `nic_lk` | Sri Lanka National ID | CRITICAL | `987654321V` |
| `password_hash` | bcrypt / SHA-crypt hash | CRITICAL | `$2b$12$...` |
| `db_conn_string` | Database connection string | CRITICAL | `postgresql://user:pass@host` |

---

## Output & Reporting

### findings.json

A machine-readable ledger updated throughout the scan. Suitable for ingestion into SIEM platforms, ticketing systems (Jira, ServiceNow), or custom dashboards.

```json
{
  "domain": "company.com",
  "scan_started": "2025-06-01T09:00:00Z",
  "findings": [
    {
      "id": "PII-2025-001",
      "severity": "CRITICAL",
      "source": "Cloud Storage",
      "description": "Open S3 bucket company-exports publicly accessible",
      "url": "https://company-exports.s3.amazonaws.com",
      "pii_types": ["csv", "email", "name"],
      "estimated_records": "8500+",
      "regulatory": ["GDPR", "CCPA"],
      "remediation": "Set bucket ACL to private, enable S3 Block Public Access"
    }
  ]
}
```

### REPORT.md

A structured Markdown report containing:

- Executive summary with aggregate risk score
- Attack surface statistics table
- All findings organized by severity with descriptions and remediation steps
- Regulatory impact assessment table
- Prioritized remediation roadmap with SLA tiers
- Evidence file index pointing to all raw output files

The report is designed to be shared directly with a CISO or DPO without further editing.

---

## Severity Classification

| Severity | Score Weight | SLA | Examples |
|---|---|---|---|
| CRITICAL | 25 pts | 0–24 hours | Open cloud bucket with PII, private key in public repo, unauthenticated endpoint returning SSNs or credit card data |
| HIGH | 10 pts | 24–72 hours | Credentials in GitHub, unauthenticated API returning email+name, GraphQL introspection with PII types exposed |
| MEDIUM | 3 pts | 7 days | Missing security headers, exposed Swagger docs, verbose error pages, robots.txt revealing admin paths |
| LOW | 1 pt | 30 days | IP address exposure, employee name enumeration, email address disclosure without further PII |

The risk score is calculated as:

```
risk_score = min(100, (critical × 25) + (high × 10) + (medium × 3) + (low × 1))
```

---

## Regulatory Impact Matrix

| Regulation | Article / Section | Triggered When | Max Penalty |
|---|---|---|---|
| GDPR | Art. 5(1)(f) — Integrity & confidentiality | Any PII exposure to unauthorized parties | €20M or 4% global turnover |
| GDPR | Art. 25 — Privacy by design | Unauthenticated endpoints returning PII | €10M or 2% global turnover |
| GDPR | Art. 32 — Security of processing | Open buckets, missing encryption in transit | €10M or 2% global turnover |
| GDPR | Art. 33 — Breach notification (72h) | Confirmed unauthorized access to personal data | €10M or 2% global turnover |
| CCPA | § 1798.150 | CA resident PII exposed via unauthorized access | $100–$750 per consumer per incident |
| PCI DSS | Req. 3 | Cardholder data discoverable in plain text | $5,000–$100,000/month |
| PCI DSS | Req. 6 | Exposed config files, unpatched systems | $5,000–$100,000/month |
| HIPAA | 45 CFR § 164.312 | Health/medical data exposed | $100–$50,000 per violation |
| Sri Lanka PDPA | Sec. 39 | Personal data breach without notification | LKR 10M or 2% annual turnover |

---

## Remediation SLAs

### CRITICAL — 0 to 24 Hours

1. Immediately revoke any exposed credentials (API keys, AWS keys, database passwords)
2. Set all open cloud storage buckets to private and enable provider-level block public access
3. Take down or IP-restrict any unauthenticated endpoints returning bulk PII
4. Notify the Data Protection Officer (DPO)
5. Assess GDPR Article 33 breach notification obligation — 72-hour clock starts from awareness of breach
6. Preserve all evidence (response bodies, timestamps, access logs)

### HIGH — 24 to 72 Hours

1. Purge exposed credentials from git history using BFG Repo Cleaner or `git filter-repo`
2. Force password/MFA reset for all accounts associated with exposed email addresses
3. Implement authentication on all discovered unauthenticated PII-returning API endpoints
4. Disable GraphQL introspection on all production instances
5. Restrict API documentation (Swagger, OpenAPI) behind authentication
6. Document findings in the risk register

### MEDIUM — Within 7 Days

1. Implement all missing HTTP security headers across all subdomains
2. Disable verbose error output and stack traces on non-local environments
3. Audit and clean up robots.txt entries pointing to sensitive internal routes
4. Review and restrict sitemap entries for admin or data export pages
5. Decommission or network-isolate legacy and staging subdomains not required for production

### LOW — Within 30 Days

1. Request removal of company email addresses from Hunter.io and similar OSINT aggregators
2. Publish a `security.txt` file at `/.well-known/security.txt` per RFC 9116
3. Establish automated CT log monitoring for new subdomain detection
4. Enroll in HaveIBeenPwned domain monitoring (free for verified domain owners)
5. Schedule recurring passive PII scans (recommended: monthly)

---

## Scope Boundaries

### In Scope

- Passive HTTP requests to discovered subdomains and known sensitive paths
- Certificate transparency log queries
- Passive DNS queries via public aggregators
- Public cloud storage HEAD requests for accessibility checks
- GitHub and GitLab public code search
- Publicly accessible API specification files (Swagger, OpenAPI, GraphQL)
- Internet Archive CDX API queries
- Hunter.io public email OSINT
- DNS record inspection (TXT, MX, SPF, DMARC, DKIM)

### Out of Scope

- Any form of fuzzing, brute-force path enumeration, or directory scanning
- Authentication attempts or credential testing of any kind
- Exploitation of any discovered vulnerability
- Active port scanning beyond passive header inspection
- Breach database or leaked credential database lookups (handled by separate tooling)
- Any action that modifies, deletes, or exfiltrates discovered data
- Social engineering

---

## Contributing

Contributions are welcome from authorized security practitioners. Please follow these guidelines:

1. **Fork** the repository and create a feature branch from `main`
2. **Scope** — all additions must remain within passive reconnaissance techniques
3. **Code style** — Python code must pass `flake8` with a max line length of 120 characters
4. **Testing** — test against a domain you own or a dedicated lab environment before submitting
5. **Documentation** — update this README for any new phase, pattern, or configuration option added
6. **Pull request** — describe the technique added, its passive nature, and the PII risk category it targets

### Adding a New PII Pattern

Add entries to the `PII_PATTERNS` dictionary in Phase 7 of `PII_DISCLOSURE_SKILL.md`:

```python
"pattern_id": (re.compile(r'your_regex_here'), 'CRITICAL|HIGH|MEDIUM|LOW'),
```

Include in the PR:
- The regex pattern with a comment explaining its structure
- At least 3 test strings that should match
- At least 3 test strings that should not match
- The regulatory framework that classifies this data type as PII
- The applicable jurisdiction

---

## License

```
MIT License

Copyright (c) 2025 Nipun Dilshan Senevirathne
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

> **Disclaimer:** This tool is provided for authorized security assessments only. The authors and contributors accept no liability for use against systems without explicit written authorization. You are solely responsible for ensuring your use complies with all applicable laws and regulations in your jurisdiction.

---

*Maintained by the Security Engineering team. For issues or questions, open a GitHub issue or contact the CISO office.*
