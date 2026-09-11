# HELIOS Security Data & Benchmark Rulebook

This directory contains the security detection rules, CWE definitions, and benchmark datasets used by the HELIOS Autonomous Security Engine.

## Files
- `security_rules.json`: Canonical rule definitions for HTTP security headers and code patterns.

## Detection Rules Catalog
1. **HLS-WEB-001: Missing Content Security Policy (CSP)**
   - Severity: HIGH | CWE-1021 / CWE-79
   - Impact: Cross-Site Scripting (XSS) and unrestricted resource loading.
2. **HLS-WEB-002: Missing HTTP Strict Transport Security (HSTS)**
   - Severity: HIGH | CWE-319
   - Impact: Man-in-the-Middle (MitM) attacks via SSL stripping.
3. **HLS-WEB-003: Missing X-Frame-Options Header**
   - Severity: MEDIUM | CWE-1021
   - Impact: Clickjacking attacks via unauthorized iframe embedding.
4. **HLS-WEB-004: Missing X-Content-Type-Options Header**
   - Severity: LOW | CWE-704
   - Impact: MIME-sniffing and cross-site script execution.
5. **HLS-WEB-005: Server Header Information Disclosure**
   - Severity: LOW | CWE-200
   - Impact: Software version fingerprinting aids targeted exploits.

## Zero Fake Data Policy
HELIOS strictly measures security metrics based on actual network responses received from target domains during live execution. No randomized or fabricated values are ever used.
