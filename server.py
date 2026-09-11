#!/usr/bin/env python3
"""
HELIOS Autonomous Security Engineer - Unified Backend Server
Features:
- Gemini 3.5 / 2.0 / 1.5 Flash AI Brain Integration with Model Fallback
- ElevenLabs English Voice Response + Free Audio Stream Fallback
- Real-World URL Security Scanner & Live Header Probes
- Real Static Code Analysis & AI Coding Vulnerability Detection
- Voice Security Copilot Engine (/api/v1/voice/command & /api/v1/voice/tts)
- Settings & API Key persistence (.env)
- Zero mandatory external packages (uses Python standard library)
"""
import http.server
import socketserver
import urllib.request
import urllib.error
import urllib.parse
import ssl
import json
import re
import os
import time
from datetime import datetime

PORT = 3000
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(WORKSPACE_DIR, ".env")

# ─── Load Environment Variables from .env ───
def load_env():
    env_vars = {}
    if os.path.exists(ENV_FILE):
        try:
            with open(ENV_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        env_vars[k.strip()] = v.strip().strip("'").strip('"')
        except Exception:
            pass
    return env_vars

def save_env(updates):
    current = load_env()
    current.update(updates)
    try:
        with open(ENV_FILE, "w", encoding="utf-8") as f:
            for k, v in current.items():
                f.write(f"{k}={v}\n")
    except Exception as e:
        print(f"[HELIOS] Failed to write .env: {e}")

# ─── REAL-WORLD LIVE TARGET SCANNER ───
def analyze_url_security(target_url):
    """
    Performs real-world, safe, non-destructive security audits on a live website.
    Audits HTTP security headers, CORS, information leakage, cookie policies,
    and standard sensitive path exposures.
    """
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc
    scheme = parsed.scheme

    findings = []
    headers_detected = {}
    scan_logs = []
    
    start_time = time.time()
    scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Initiating defensive assessment for: {target_url}")
    scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Protocol: {scheme.upper()} | Target Host: {domain}")

    req = urllib.request.Request(
        target_url,
        headers={
            "User-Agent": "HELIOS-Security-Engine/1.0 (Defensive-Security-Audit; +https://helios.security)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
    )

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Transmitting probe request to primary endpoint...")
        with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
            status_code = response.getcode()
            res_headers = dict(response.info())
            raw_headers = {k.lower(): v for k, v in res_headers.items()}
            elapsed = round((time.time() - start_time) * 1000, 2)
            scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Received HTTP {status_code} response in {elapsed}ms.")
    except urllib.error.HTTPError as e:
        status_code = e.code
        raw_headers = {k.lower(): v for k, v in dict(e.headers).items()}
        scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Target responded with HTTP error {status_code}; continuing header audit.")
    except Exception as ex:
        scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Connection failed: {str(ex)}")
        return {
            "error": f"Failed to connect to target URL: {str(ex)}",
            "target_url": target_url,
            "scan_logs": scan_logs,
            "findings": []
        }

    headers_detected = raw_headers

    # 1. Content-Security-Policy (CSP)
    csp = raw_headers.get("content-security-policy")
    if not csp:
        findings.append({
            "id": "HLS-WEB-001",
            "title": "Missing Content-Security-Policy (CSP) Header",
            "category": "Web Application Security",
            "severity": "HIGH",
            "confidence": 100,
            "status": "Confirmed",
            "affected_component": f"{domain} (HTTP Response Headers)",
            "affected_endpoint": target_url,
            "evidence": [
                f"HTTP response status: {status_code}",
                "Header 'Content-Security-Policy' is completely absent from server response.",
                f"Total headers inspected: {len(raw_headers)}"
            ],
            "technical_explanation": "Content Security Policy (CSP) restricts origins of executable scripts, stylesheets, and frames to mitigate Cross-Site Scripting (XSS) and data injection.",
            "impact": "If an XSS flaw exists on any page, malicious scripts can execute unrestricted, harvest session tokens, or exfiltrate sensitive customer data.",
            "attack_path": "Untrusted User Input ➔ Unrestricted Script Execution ➔ Session Token Exfiltration",
            "remediation": {
                "problem": "Server does not restrict origins of executable assets.",
                "why_it_matters": "Increases vulnerability to stored and reflected Cross-Site Scripting.",
                "recommended_fix": "Add a restrictive Content-Security-Policy header.",
                "secure_snippet": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;"
            }
        })

    # 2. Strict-Transport-Security (HSTS)
    hsts = raw_headers.get("strict-transport-security")
    if scheme == "https" and not hsts:
        findings.append({
            "id": "HLS-WEB-002",
            "title": "Missing HTTP Strict-Transport-Security (HSTS)",
            "category": "Cryptographic & Transport Security",
            "severity": "HIGH",
            "confidence": 100,
            "status": "Confirmed",
            "affected_component": f"{domain} (Transport Layer)",
            "affected_endpoint": target_url,
            "evidence": [
                "Endpoint serves HTTPS traffic.",
                "Header 'Strict-Transport-Security' is absent.",
                "Browsers may attempt initial unencrypted HTTP connections."
            ],
            "technical_explanation": "HTTP Strict Transport Security (HSTS) prevents SSL-stripping and downgrade attacks by forcing browsers to only navigate via HTTPS.",
            "impact": "Attackers on local networks can intercept unencrypted HTTP redirects and steal session credentials.",
            "attack_path": "Attacker on Local Network ➔ SSL Stripping ➔ Cleartext Credential Interception",
            "remediation": {
                "problem": "Browser cannot enforce mandatory HTTPS navigation.",
                "why_it_matters": "Vulnerable to passive network eavesdropping.",
                "recommended_fix": "Enable HSTS with max-age=31536000 and includeSubDomains.",
                "secure_snippet": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
            }
        })

    # 3. X-Frame-Options (Clickjacking)
    xfo = raw_headers.get("x-frame-options")
    if not xfo and (not csp or "frame-ancestors" not in csp):
        findings.append({
            "id": "HLS-WEB-003",
            "title": "Missing Clickjacking Protection (X-Frame-Options)",
            "category": "Web Application Security",
            "severity": "MEDIUM",
            "confidence": 100,
            "status": "Confirmed",
            "affected_component": f"{domain} (UI Redressing Layer)",
            "affected_endpoint": target_url,
            "evidence": [
                "Neither 'X-Frame-Options' nor CSP 'frame-ancestors' header is present.",
                "Third-party origins can render this page inside an iframe."
            ],
            "technical_explanation": "Without X-Frame-Options or frame-ancestors, malicious websites can frame this application inside a transparent iframe to hijack user clicks.",
            "impact": "Unauthorized state-changing actions executed through UI redressing.",
            "attack_path": "Attacker Website ➔ Invisible Iframe ➔ User Click Redressing",
            "remediation": {
                "problem": "Application can be framed by external origins.",
                "why_it_matters": "Enables UI Redressing / Clickjacking attacks.",
                "recommended_fix": "Set X-Frame-Options to DENY or SAMEORIGIN.",
                "secure_snippet": "add_header X-Frame-Options \"DENY\" always;"
            }
        })

    # 4. X-Content-Type-Options
    xcto = raw_headers.get("x-content-type-options")
    if not xcto or xcto.lower() != "nosniff":
        findings.append({
            "id": "HLS-WEB-004",
            "title": "Missing X-Content-Type-Options: nosniff",
            "category": "MIME Security",
            "severity": "LOW",
            "confidence": 100,
            "status": "Confirmed",
            "affected_component": f"{domain} (MIME Dispatcher)",
            "affected_endpoint": target_url,
            "evidence": [
                f"X-Content-Type-Options header value: '{xcto or 'None'}'",
                "Browser MIME-type sniffing is not explicitly disabled."
            ],
            "technical_explanation": "Prevents browsers from MIME-sniffing a response away from the declared content-type, blocking script execution from image/text uploads.",
            "impact": "Drive-by script execution via user-supplied uploads.",
            "attack_path": "File Upload ➔ MIME Type Sniffing ➔ Cross-Site Script Execution",
            "remediation": {
                "problem": "Browser can override declared Content-Type header.",
                "why_it_matters": "Risk of cross-site scripting via uploaded content.",
                "recommended_fix": "Set X-Content-Type-Options to 'nosniff'.",
                "secure_snippet": "add_header X-Content-Type-Options \"nosniff\" always;"
            }
        })

    # 5. Information Disclosure (Server / X-Powered-By)
    server_banner = raw_headers.get("server")
    powered_by = raw_headers.get("x-powered-by")
    if server_banner or powered_by:
        leak = []
        if server_banner: leak.append(f"Server: {server_banner}")
        if powered_by: leak.append(f"X-Powered-By: {powered_by}")
        findings.append({
            "id": "HLS-WEB-005",
            "title": "Server Information Disclosure via HTTP Headers",
            "category": "Information Disclosure",
            "severity": "LOW",
            "confidence": 100,
            "status": "Confirmed",
            "affected_component": f"{domain} (Web Server)",
            "affected_endpoint": target_url,
            "evidence": leak,
            "technical_explanation": "The web server explicitly discloses software names and version details in response headers.",
            "impact": "Aids threat actors in fingerprinting backend architecture and deploying version-specific automated exploits.",
            "attack_path": "Header Reconnaissance ➔ Automated CVE Database Lookup ➔ Targeted Exploit",
            "remediation": {
                "problem": "Technology stack banners exposed in HTTP headers.",
                "why_it_matters": "Simplifies attacker reconnaissance and version fingerprinting.",
                "recommended_fix": "Disable version tokens in web server configurations.",
                "secure_snippet": "server_tokens off;"
            }
        })

    # 6. CORS Wildcard Configuration
    cors_origin = raw_headers.get("access-control-allow-origin")
    cors_cred = raw_headers.get("access-control-allow-credentials")
    if cors_origin == "*" and cors_cred == "true":
        findings.append({
            "id": "HLS-WEB-006",
            "title": "Dangerous CORS Wildcard with Credentials",
            "category": "Cross-Origin Resource Sharing",
            "severity": "CRITICAL",
            "confidence": 100,
            "status": "Confirmed",
            "affected_component": f"{domain} (API Gateway)",
            "affected_endpoint": target_url,
            "evidence": [
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Credentials: true"
            ],
            "technical_explanation": "Permitting wildcard origin with credentials allows any third-party website to make authenticated requests and read sensitive responses.",
            "impact": "Complete credentialed API hijacking and customer record exfiltration.",
            "attack_path": "Malicious Webpage ➔ Authenticated Browser Fetch ➔ CORS Response Extraction",
            "remediation": {
                "problem": "Universal wildcard origin combined with credentials.",
                "why_it_matters": "Allows unauthorized cross-origin data theft.",
                "recommended_fix": "Restrict allow_origins to explicit domain whitelist.",
                "secure_snippet": "allow_origins=['https://app.yourdomain.com']"
            }
        })

    # Calculate real contextual risk score
    crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    base_score = 15
    base_score += (crit_count * 25) + (high_count * 15) + (med_count * 8) + (low_count * 3)
    final_score = min(98, max(12, base_score))

    risk_level = "CRITICAL" if final_score >= 75 else "HIGH" if final_score >= 50 else "MEDIUM" if final_score >= 30 else "LOW"
    
    scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] Security evaluation finalized. {len(findings)} real-world findings detected.")
    scan_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] HELIOS Calculated Risk Score: {final_score}/100 ({risk_level}).")

    return {
        "target_url": target_url,
        "domain": domain,
        "status_code": status_code,
        "headers_inspected": raw_headers,
        "findings": findings,
        "scan_logs": scan_logs,
        "metrics": {
            "risk_score": final_score,
            "risk_level": risk_level,
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "total": len(findings),
            "headers_count": len(raw_headers)
        }
    }

# ─── REAL STATIC CODE ANALYZER ───
def analyze_code_security(code_snippet, filename="app.py"):
    findings = []
    lines = code_snippet.split("\n")
    
    # 1: SQL Injection
    for i, line in enumerate(lines):
        if re.search(r'\.execute\s*\(\s*f["\'].*\{.*\}', line) or re.search(r'SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*=.*\%s|WHERE.*=\s*[\'"].*\+', line, re.I):
            findings.append({
                "id": "HLS-COD-001",
                "title": "Raw String Concatenation in SQL Query (SQLi)",
                "category": "Code Security",
                "severity": "CRITICAL",
                "confidence": 98,
                "status": "Confirmed",
                "affected_component": filename,
                "affected_endpoint": f"Line {i + 1}",
                "evidence": [f"Vulnerable pattern on line {i + 1}:", line.strip()],
                "technical_explanation": "Dynamic SQL construction incorporates untrusted user input directly into the database command structure without bind parameters.",
                "impact": "Arbitrary SQL execution, data leakage, authentication bypass, database compromise.",
                "attack_path": "User Input ➔ Dynamic SQL String ➔ Unescaped Command Execution",
                "remediation": {
                    "problem": "String interpolation in SQL query execution.",
                    "why_it_matters": "Allows threat actors to escape query boundaries.",
                    "recommended_fix": "Use bound parameterized queries.",
                    "secure_snippet": "stmt = text('SELECT * FROM users WHERE username = :user')\ndb.execute(stmt, {'user': username})"
                },
                "vulnerable_code": line.strip(),
                "secure_code": "stmt = text('SELECT * FROM users WHERE id = :id')\ndb.execute(stmt, {'id': user_id})"
            })

    # 2: Hardcoded Secrets
    secret_patterns = [
        (r'(sk_[live|test]_[0-9a-zA-Z]{24,})', "Stripe Secret Key"),
        (r'(sk-proj-[0-9a-zA-Z_-]{30,})', "OpenAI API Key"),
        (r'([a-zA-Z0-9_-]*SECRET[a-zA-Z0-9_-]*\s*=\s*["\'][a-zA-Z0-9_!@#$%^&*]{8,}["\'])', "Hardcoded Secret / Token"),
        (r'(AIza[0-9A-Za-z-_]{35})', "Google API Key")
    ]
    for i, line in enumerate(lines):
        for pat, desc in secret_patterns:
            m = re.search(pat, line)
            if m:
                raw_secret = m.group(1)
                redacted = raw_secret[:6] + "*" * (len(raw_secret) - 8) + raw_secret[-2:] if len(raw_secret) > 8 else "******"
                findings.append({
                    "id": "HLS-COD-002",
                    "title": f"Exposed Hardcoded Secret ({desc})",
                    "category": "Secret Exposure",
                    "severity": "CRITICAL",
                    "confidence": 100,
                    "status": "Confirmed",
                    "affected_component": filename,
                    "affected_endpoint": f"Line {i + 1}",
                    "evidence": [f"Detected {desc} pattern on line {i + 1}", f"Redacted secret token: {redacted}"],
                    "technical_explanation": "Credential or API token is committed directly in source code.",
                    "impact": "Account takeover, unauthorized billing, administrative impersonation.",
                    "attack_path": "Source Repository ➔ Secret Extraction ➔ Authenticated Cloud Takeover",
                    "remediation": {
                        "problem": "Static secret in plaintext source code.",
                        "why_it_matters": "Credentials will leak to repository history.",
                        "recommended_fix": "Store in environment variables.",
                        "secure_snippet": "API_KEY = os.environ['SERVICE_API_KEY']"
                    },
                    "vulnerable_code": line.strip(),
                    "secure_code": "API_KEY = os.environ['SERVICE_API_KEY']"
                })

    # 3: Prompt Injection
    for i, line in enumerate(lines):
        if re.search(r'f["\'].*\{user_.*\}.*["\']', line) and any(w in line for w in ["prompt", "llm", "invoke", "messages", "openai", "claude"]):
            findings.append({
                "id": "HLS-AI-002",
                "title": "Direct Prompt Injection in AI/LLM Integration",
                "category": "AI Security (OWASP LLM01)",
                "severity": "HIGH",
                "confidence": 94,
                "status": "Confirmed",
                "affected_component": filename,
                "affected_endpoint": f"Line {i + 1}",
                "evidence": [f"Line {i + 1}: {line.strip()}", "Direct string interpolation of untrusted input into LLM prompt."],
                "technical_explanation": "Untrusted user input concatenated directly into system prompt without delimiters or role boundaries.",
                "impact": "Prompt injection, system instruction override, model jailbreaking.",
                "attack_path": "User Query ➔ Prompt Injection ➔ LLM Safety Guardrail Bypass",
                "remediation": {
                    "problem": "Unseparated prompt construction.",
                    "why_it_matters": "Allows attackers to overwrite system constraints.",
                    "recommended_fix": "Use structured ChatML messages with role separation.",
                    "secure_snippet": "messages = [\n    {'role': 'system', 'content': 'You are a secure assistant.'},\n    {'role': 'user', 'content': f'<query>{sanitize(user_input)}</query>'}\n]"
                }
            })

    return findings

# ─── GEMINI 3.5 / 2.0 FLASH BRAIN & ELEVENLABS TTS INTEGRATION ───
def query_gemini_brain(prompt, gemini_key, context=None, requested_model="gemini-2.0-flash"):
    """
    Calls Google Gemini API (Gemini 3.5 / 2.0 / 1.5) with automatic resilient model fallback.
    """
    # Build list of models to try in sequence
    models_to_try = []
    clean_model = requested_model.strip().lower()
    
    if "3.5" in clean_model:
        models_to_try.extend(["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-pro"])
    else:
        models_to_try.append(clean_model)
        if "gemini-2.0-flash" not in models_to_try:
            models_to_try.append("gemini-2.0-flash")
        if "gemini-1.5-flash" not in models_to_try:
            models_to_try.append("gemini-1.5-flash")

    system_instruction = (
        "You are HELIOS Voice Brain, an autonomous cybersecurity engineer copilot assisting SOC engineers. "
        "User speaks to you via voice. Parse their intent and output a strict JSON object with: "
        "1. tool: one of ['start_live_assessment', 'get_findings', 'execute_retest', 'navigate_dashboard', 'toggle_theme', 'conversational'] "
        "2. speech: short, confident spoken response (max 2 natural sentences, no markdown symbols or bullets) "
        "3. target_url: if user mentions a URL or asks to scan/run the active target, extract or provide it from context. "
        "Context provided includes current active_tab and target_url."
    )
    body = {
        "systemInstruction": {"parts": [{"text": system_instruction}]},
        "contents": [{"parts": [{"text": f"Current Context: {json.dumps(context or {})}\nUser Instruction: {prompt}"}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
    }
    payload = json.dumps(body).encode("utf-8")

    last_err = None
    for model in models_to_try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={gemini_key}"
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=9) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                raw_text = data["candidates"][0]["content"]["parts"][0]["text"]
                res_obj = json.loads(raw_text)
                res_obj["model_used"] = model
                return res_obj
        except Exception as e:
            last_err = e
            continue

    raise Exception(f"All Gemini models failed. Last error: {last_err}")

def synthesize_elevenlabs_audio(text, api_key, voice_id="21m00Tcm4TlvDq8ikWAM"):
    """
    Calls ElevenLabs text-to-speech API to produce natural English voice response MP3 bytes.
    Default voice_id: Rachel (21m00Tcm4TlvDq8ikWAM)
    """
    url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
    headers = {
        "Accept": "audio/mpeg",
        "Content-Type": "application/json",
        "xi-api-key": api_key
    }
    body = {
        "text": text,
        "model_id": "eleven_monolingual_v1",
        "voice_settings": {
            "stability": 0.5,
            "similarity_boost": 0.75
        }
    }
    payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers=headers)
    with urllib.request.urlopen(req, timeout=12) as resp:
        return resp.read()

def synthesize_free_google_tts(text):
    """
    Fallback free Google English TTS stream that returns standard MP3 bytes.
    Ensures voice output ALWAYS works out loud even without API keys!
    """
    encoded = urllib.parse.quote_plus(text[:250])
    url = f"https://translate.google.com/translate_tts?ie=UTF-8&client=tw-ob&tl=en&q={encoded}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    with urllib.request.urlopen(req, timeout=6) as resp:
        return resp.read()

# ─── VOICE SECURITY & COPILOT ENGINE ───
class VoiceEngine:
    BLOCKED_PATTERNS = [
        r"(ignore|disregard|override)\s+(all\s+)?(previous\s+)?(instructions|rules|system)",
        r"(drop|truncate|delete)\s+(table|database|all)",
        r"(curl|wget|bash|sh|powershell|cmd|exec)\s+",
        r"sk_live_[0-9a-zA-Z]{24,}",
        r"(format\s+c:|rm\s+-rf)",
    ]

    @classmethod
    def sanitize_for_tts(cls, text):
        text = re.sub(r'sk_[live|test]_[0-9a-zA-Z]{10,}', '[REDACTED KEY]', text)
        text = re.sub(r'Bearer\s+[0-9a-zA-Z\._\-]+', 'Bearer [REDACTED TOKEN]', text)
        text = re.sub(r'\bSQLi\b', 'Sequel Injection', text, flags=re.I)
        text = re.sub(r'\bBOLA\b', 'Bow-lah', text, flags=re.I)
        text = re.sub(r'\bIDOR\b', 'Eye-Door', text, flags=re.I)
        text = re.sub(r'\bCSP\b', 'C S P', text)
        text = re.sub(r'\bHSTS\b', 'H S T S', text)
        text = re.sub(r'\bCWE-(\d+)\b', r'C W E \1', text)
        text = re.sub(r'\bHLS-([A-Z]+)-(\d+)\b', r'H L S \1 \2', text)
        return text

    @classmethod
    def process_command(cls, transcript, context, confirmed=False, gemini_key=None, gemini_model="gemini-2.0-flash"):
        transcript_clean = transcript.strip()
        t_lower = transcript_clean.lower()

        # 1. Security firewall against prompt injection
        for pat in cls.BLOCKED_PATTERNS:
            if re.search(pat, transcript_clean, re.IGNORECASE):
                return {
                    "status": "SECURITY_BLOCK",
                    "speech": "Acoustic security alert. Command rejected due to prohibited instruction pattern.",
                    "ui_action": {}
                }

        # 2. Try Gemini Brain if key is available
        env_vars = load_env()
        active_gemini_key = gemini_key or env_vars.get("GEMINI_API_KEY")
        active_model = gemini_model or env_vars.get("GEMINI_MODEL", "gemini-2.0-flash")

        if active_gemini_key:
            try:
                ai_resp = query_gemini_brain(transcript_clean, active_gemini_key, context, requested_model=active_model)
                tool = ai_resp.get("tool")
                speech = ai_resp.get("speech", "Instruction processed.")
                target_url = ai_resp.get("target_url") or context.get("target_url") or "https://httpbin.org"

                if tool == "start_live_assessment":
                    res = analyze_url_security(target_url)
                    total = len(res.get("findings", []))
                    score = res.get("metrics", {}).get("risk_score", 0)
                    speech = f"Live security audit for {target_url} completed. Identified {total} security findings with risk score {score}."
                    return {
                        "status": "SUCCESS",
                        "tool": "start_live_assessment",
                        "speech": speech,
                        "model": ai_resp.get("model_used", active_model),
                        "ui_action": {"tab": "tracker", "scan_result": res}
                    }
                elif tool == "get_findings":
                    return {
                        "status": "SUCCESS",
                        "tool": "get_findings",
                        "speech": speech,
                        "model": ai_resp.get("model_used", active_model),
                        "ui_action": {"tab": "tracker"}
                    }
                elif tool == "execute_retest":
                    fid = context.get("active_finding_id") or "HLS-WEB-001"
                    fresh = analyze_url_security(target_url)
                    found = any(f["id"] == fid for f in fresh.get("findings", []))
                    res_status = "STILL VULNERABLE" if found else "RESOLVED"
                    return {
                        "status": "SUCCESS",
                        "tool": "execute_retest",
                        "speech": speech,
                        "model": ai_resp.get("model_used", active_model),
                        "ui_action": {"tab": "tracker", "retest_id": fid, "retest_status": res_status}
                    }
                elif tool == "navigate_dashboard":
                    dest = "tracker"
                    if "lab" in speech.lower(): dest = "lab"
                    elif "attack" in speech.lower() or "arch" in speech.lower(): dest = "architecture"
                    elif "report" in speech.lower(): dest = "report"
                    return {
                        "status": "SUCCESS",
                        "tool": "navigate_dashboard",
                        "speech": speech,
                        "model": ai_resp.get("model_used", active_model),
                        "ui_action": {"tab": dest}
                    }
                elif tool == "toggle_theme":
                    mode = "light" if "light" in speech.lower() else "dark"
                    return {
                        "status": "SUCCESS",
                        "tool": "toggle_theme",
                        "speech": speech,
                        "model": ai_resp.get("model_used", active_model),
                        "ui_action": {"theme": mode}
                    }
                else:
                    return {
                        "status": "SUCCESS",
                        "tool": "conversational",
                        "speech": speech,
                        "model": ai_resp.get("model_used", active_model),
                        "ui_action": {}
                    }
            except Exception as e:
                print(f"[HELIOS] Gemini brain query failed, falling back to local heuristic: {e}")

        # 3. High-Intelligence Local Heuristic Intent Parser (Fallback)

        # Match 0: Greeting & Welcome (User says hi/hello/welcome/who are you)
        if re.search(r'\b(welcome|hello|hi|hey|greetings|good\s+morning|good\s+afternoon|good\s+evening|how\s+are\s+you|who\s+are\s+you|what\s+can\s+you\s+do|help\s+me)\b', t_lower):
            return {
                "status": "SUCCESS",
                "tool": "conversational",
                "speech": "Welcome sir! How may I help you? I am your HELIOS security engineer, standing by to scan websites, verify vulnerabilities, or run security audits.",
                "ui_action": {}
            }

        # Match 1: Explicit URL Scan anywhere in transcript (e.g. "Scan https://example.com" or "Audit http://test.com")
        url_match = re.search(r'https?://[^\s,;]+', transcript_clean)
        if url_match and any(w in t_lower for w in ["scan", "audit", "test", "check", "analyze", "probe", "run", "inspect"]):
            url = url_match.group(0).rstrip('.')
            res = analyze_url_security(url)
            total = len(res.get("findings", []))
            score = res.get("metrics", {}).get("risk_score", 0)
            level = res.get("metrics", {}).get("risk_level", "CLEAN")
            return {
                "status": "SUCCESS",
                "tool": "start_live_assessment",
                "speech": f"Live security audit for {url} completed. Identified {total} security findings with risk score {score} out of 100, classified as {level}.",
                "ui_action": {"tab": "tracker", "scan_result": res}
            }

        # Match 2: Target / Pasted Link Scan (e.g. "scan it", "run scan", "scan website", "check security", "kindly run it for me")
        if any(w in t_lower for w in ["run", "scan", "audit", "check", "test", "analyze", "probe", "inspect", "start"]) and any(w in t_lower for w in ["it", "link", "url", "site", "website", "target", "app", "application", "for me", "this", "security", "assessment", "pasted"]):
            target_url = context.get("target_url") or "https://see-it-report-it.lovable.app"
            res = analyze_url_security(target_url)
            total = len(res.get("findings", []))
            score = res.get("metrics", {}).get("risk_score", 0)
            level = res.get("metrics", {}).get("risk_level", "CLEAN")
            speech = f"Running live security audit on {target_url}. Scan complete. Detected {total} security findings with overall risk score {score} out of 100, classified as {level}."
            return {
                "status": "SUCCESS",
                "tool": "start_live_assessment",
                "speech": speech,
                "ui_action": {"tab": "tracker", "scan_result": res}
            }

        # Match 3: Re-Test command (e.g. "retest", "re-test finding", "verify fix", "check again")
        if any(w in t_lower for w in ["retest", "re-test", "verify", "recheck", "check again", "is it resolved", "verify fix", "test again"]):
            fid_match = re.search(r'\b(hls-[a-z]+-[0-9]+)\b', t_lower)
            fid = (fid_match.group(1) if fid_match else (context.get("active_finding_id") or "HLS-WEB-001")).upper()
            target_url = context.get("target_url") or "https://see-it-report-it.lovable.app"
            fresh = analyze_url_security(target_url)
            found = any(f["id"] == fid for f in fresh.get("findings", []))
            res_status = "STILL VULNERABLE" if found else "RESOLVED"
            speech = (
                f"Re-test complete for {cls.sanitize_for_tts(fid)}. The issue is still active because the required security header remains absent on {target_url}."
                if found else
                f"Re-test verified! Finding {cls.sanitize_for_tts(fid)} has been successfully resolved on the target server."
            )
            return {
                "status": "SUCCESS",
                "tool": "execute_retest",
                "speech": speech,
                "ui_action": {"tab": "tracker", "retest_id": fid, "retest_status": res_status}
            }

        # Match 4: Show Findings / Critical / High
        if any(w in t_lower for w in ["critical", "high", "findings", "vulnerabilities", "show issues", "bugs", "threats", "tracker"]):
            return {
                "status": "SUCCESS",
                "tool": "get_findings",
                "speech": "Displaying active security findings in the Live Security Tracker.",
                "ui_action": {"tab": "tracker"}
            }

        # Match 5: Risk Score / Posture Overview
        if any(w in t_lower for w in ["risk score", "security score", "what is my score", "overview", "posture", "metric"]):
            return {
                "status": "SUCCESS",
                "tool": "get_project_summary",
                "speech": "Opening the security overview. Your target risk score is dynamically calculated from actual HTTP response data.",
                "ui_action": {"tab": "tracker"}
            }

        # Match 6: Attack Paths & Architecture
        if any(w in t_lower for w in ["attack path", "exploit chain", "architecture", "topology", "attack", "graph"]):
            return {
                "status": "SUCCESS",
                "tool": "navigate_dashboard",
                "speech": "Opening the attack path visualizer. Showing how missing headers chain into session hijacking.",
                "ui_action": {"tab": "architecture"}
            }

        # Match 7: Interactive Security Lab
        if any(w in t_lower for w in ["lab", "code", "workbench", "interactive", "sqli", "injection", "playground"]):
            return {
                "status": "SUCCESS",
                "tool": "navigate_dashboard",
                "speech": "Opening the HELIOS interactive security lab and code workbench.",
                "ui_action": {"tab": "lab"}
            }

        # Match 8: Light / Dark Mode Toggle
        if any(w in t_lower for w in ["light mode", "switch to light", "turn on light", "white mode", "enable light"]):
            return {
                "status": "SUCCESS",
                "tool": "toggle_theme",
                "speech": "Switched to enterprise light mode, sir.",
                "ui_action": {"theme": "light"}
            }
        if any(w in t_lower for w in ["dark mode", "switch to dark", "turn on dark", "cyber mode", "night mode", "black mode", "enable dark"]):
            return {
                "status": "SUCCESS",
                "tool": "toggle_theme",
                "speech": "Switched to cyber dark mode, sir.",
                "ui_action": {"theme": "dark"}
            }
        if any(w in t_lower for w in ["toggle theme", "switch theme", "change theme", "toggle mode"]):
            current_theme = context.get("theme", "dark")
            new_theme = "light" if current_theme == "dark" else "dark"
            return {
                "status": "SUCCESS",
                "tool": "toggle_theme",
                "speech": f"Toggled interface to {new_theme} mode, sir.",
                "ui_action": {"theme": new_theme}
            }

        # Match 9: Report Export
        if any(w in t_lower for w in ["report", "export", "pdf", "ciso", "download report", "print report"]):
            return {
                "status": "SUCCESS",
                "tool": "navigate_dashboard",
                "speech": "Opening the executive CISO security audit report.",
                "ui_action": {"tab": "report"}
            }

        # Match 10: Security Explanations (CSP, HSTS, Clickjacking, MIME)
        if any(w in t_lower for w in ["what is csp", "explain csp", "content security policy"]):
            return {
                "status": "SUCCESS",
                "tool": "conversational",
                "speech": "Content Security Policy restricts which scripts, styles, and resources a browser can load. It provides critical defense-in-depth against Cross-Site Scripting and data exfiltration.",
                "ui_action": {"tab": "tracker"}
            }
        if any(w in t_lower for w in ["what is hsts", "explain hsts", "strict transport"]):
            return {
                "status": "SUCCESS",
                "tool": "conversational",
                "speech": "HTTP Strict Transport Security forces browsers to interact with your server only over encrypted HTTPS, preventing SSL stripping and man-in-the-middle attacks.",
                "ui_action": {"tab": "tracker"}
            }
        if any(w in t_lower for w in ["clickjacking", "x-frame", "x frame"]):
            return {
                "status": "SUCCESS",
                "tool": "conversational",
                "speech": "Clickjacking embeds your website in an invisible iframe to hijack user clicks. Configuring X-Frame-Options to DENY or SAMEORIGIN stops this attack completely.",
                "ui_action": {"tab": "tracker"}
            }

        # Match 11: How to Fix / Remediation Queries
        if any(w in t_lower for w in ["how to fix", "how do i fix", "fix this", "remediation", "recommendation"]):
            return {
                "status": "SUCCESS",
                "tool": "conversational",
                "speech": "To remediate these issues, update your web server or edge proxy to set Content-Security-Policy, Strict-Transport-Security, and X-Frame-Options headers. Detailed code snippets are displayed in the tracker.",
                "ui_action": {"tab": "tracker"}
            }

        # Match 12: Dialogue Dismissal / Standby
        if any(w in t_lower for w in ["stop", "goodbye", "bye", "cancel", "stand down", "sleep", "mute"]):
            return {
                "status": "SUCCESS",
                "tool": "conversational",
                "speech": "Standing by, sir. Let me know whenever you need another security audit.",
                "ui_action": {"listening": False}
            }

        # Conversational fallback
        return {
            "status": "SUCCESS",
            "tool": "conversational",
            "speech": "Standing by, sir. You can say: scan website, show critical findings, retest finding, or switch to light mode.",
            "ui_action": {}
        }

class HeliosRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WORKSPACE_DIR, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/v1/voice/tts":
            self.handle_voice_tts(parsed.query)
        elif parsed.path == "/api/v1/settings":
            self.handle_get_settings()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == "/api/scan-url":
            self.handle_scan_url()
        elif self.path == "/api/retest-url":
            self.handle_retest_url()
        elif self.path == "/api/scan-code":
            self.handle_scan_code()
        elif self.path == "/api/v1/voice/command":
            self.handle_voice_command()
        elif self.path == "/api/v1/settings":
            self.handle_save_settings()
        else:
            self.send_error(404, "Endpoint not found")

    def handle_voice_tts(self, query_string):
        """
        Synthesizes English speech MP3 stream using ElevenLabs (if key provided)
        or high-fidelity free Google English audio stream.
        """
        params = urllib.parse.parse_qs(query_string)
        text = params.get("text", [""])[0].strip()
        if not text:
            self.send_error(400, "Text parameter required")
            return

        text = VoiceEngine.sanitize_for_tts(text)
        env_vars = load_env()
        eleven_key = params.get("eleven_key", [env_vars.get("ELEVENLABS_API_KEY", "")])[0].strip()
        voice_id = params.get("voice_id", [env_vars.get("ELEVENLABS_VOICE_ID", "21m00Tcm4TlvDq8ikWAM")])[0].strip()

        audio_bytes = None
        # Try ElevenLabs first if key provided
        if eleven_key:
            try:
                audio_bytes = synthesize_elevenlabs_audio(text, eleven_key, voice_id)
            except Exception as e:
                print(f"[HELIOS] ElevenLabs synthesis failed, falling back to free stream: {e}")

        # Fallback to free Google TTS audio stream
        if not audio_bytes:
            try:
                audio_bytes = synthesize_free_google_tts(text)
            except Exception as e:
                print(f"[HELIOS] Fallback TTS failed: {e}")
                self.send_error(500, "TTS generation failed")
                return

        self.send_response(200)
        self.send_header("Content-Type", "audio/mpeg")
        self.send_header("Content-Length", str(len(audio_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(audio_bytes)

    def handle_scan_url(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            payload = json.loads(post_data.decode("utf-8"))
            target_url = payload.get("url", "").strip()
            if not target_url:
                self.send_json({"error": "Target URL is required"}, status=400)
                return
            result = analyze_url_security(target_url)
            self.send_json(result)
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def handle_retest_url(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            payload = json.loads(post_data.decode("utf-8"))
            target_url = payload.get("url", "").strip()
            check_id = payload.get("check_id", "").strip()
            if not target_url:
                self.send_json({"error": "Target URL is required"}, status=400)
                return
            fresh_result = analyze_url_security(target_url)
            found = any(f["id"] == check_id for f in fresh_result.get("findings", []))
            
            self.send_json({
                "check_id": check_id,
                "target_url": target_url,
                "retest_status": "STILL VULNERABLE" if found else "RESOLVED",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "verification_note": "Re-test verified: Condition persists on target server." if found else "Re-test passed: Security check succeeded; vulnerability is no longer detectable.",
                "fresh_headers": fresh_result.get("headers_inspected", {})
            })
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def handle_scan_code(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            payload = json.loads(post_data.decode("utf-8"))
            code = payload.get("code", "")
            filename = payload.get("filename", "service.py")
            findings = analyze_code_security(code, filename)
            self.send_json({
                "filename": filename,
                "findings": findings,
                "total": len(findings),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def handle_voice_command(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            payload = json.loads(post_data.decode("utf-8"))
            transcript = payload.get("transcript", "")
            context = payload.get("context", {})
            confirmed = payload.get("confirmed", False)
            gemini_key = payload.get("gemini_key", "").strip()
            gemini_model = payload.get("gemini_model", "gemini-2.0-flash").strip()

            if not transcript.strip():
                self.send_json({"error": "Empty voice transcript"}, status=400)
                return

            result = VoiceEngine.process_command(
                transcript,
                context,
                confirmed=confirmed,
                gemini_key=gemini_key,
                gemini_model=gemini_model
            )
            
            # Attach audio URL so frontend can immediately play real MP3 audio
            speech_text = result.get("speech", "")
            if speech_text:
                result["audio_url"] = f"/api/v1/voice/tts?text={urllib.parse.quote_plus(speech_text)}"
            
            self.send_json(result)
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def handle_save_settings(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        try:
            payload = json.loads(post_data.decode("utf-8"))
            updates = {}
            if "gemini_key" in payload:
                updates["GEMINI_API_KEY"] = payload["gemini_key"].strip()
            if "gemini_model" in payload:
                updates["GEMINI_MODEL"] = payload["gemini_model"].strip()
            if "eleven_key" in payload:
                updates["ELEVENLABS_API_KEY"] = payload["eleven_key"].strip()
            if "voice_id" in payload:
                updates["ELEVENLABS_VOICE_ID"] = payload["voice_id"].strip()
            save_env(updates)
            self.send_json({"status": "SUCCESS", "message": "Settings saved to .env"})
        except Exception as e:
            self.send_json({"error": str(e)}, status=500)

    def handle_get_settings(self):
        env_vars = load_env()
        gk = env_vars.get("GEMINI_API_KEY", "")
        gm = env_vars.get("GEMINI_MODEL", "gemini-2.0-flash")
        ek = env_vars.get("ELEVENLABS_API_KEY", "")
        vid = env_vars.get("ELEVENLABS_VOICE_ID", "21m00Tcm4TlvDq8ikWAM")
        self.send_json({
            "has_gemini_key": bool(gk),
            "gemini_key_masked": (gk[:4] + "..." + gk[-4:]) if len(gk) > 8 else ("Set" if gk else ""),
            "gemini_model": gm,
            "has_eleven_key": bool(ek),
            "eleven_key_masked": (ek[:4] + "..." + ek[-4:]) if len(ek) > 8 else ("Set" if ek else ""),
            "voice_id": vid
        })

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

def run():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), HeliosRequestHandler) as httpd:
        print(f"[HELIOS] Unified Server + Gemini 3.5/2.0 Brain + ElevenLabs Voice serving on http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[HELIOS] Server stopping...")

if __name__ == "__main__":
    run()
