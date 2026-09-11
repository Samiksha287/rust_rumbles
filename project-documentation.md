# HELIOS: AI-Powered Autonomous Security Engineer
**Tagline:** *Build with AI. Secure with HELIOS.*  
**Track / Category:** Application Security & Autonomous AI Agents  
**Team Name:** Team HELIOS

---

## 1. Project Overview
HELIOS is an autonomous cybersecurity engineer designed to solve the critical security gap created by AI coding assistants (Cursor, Claude Code, GitHub Copilot, Lovable, Bolt, v0, Replit). 

AI coding tools produce fast, functional applications but frequently omit foundational defensive security controls—such as Content Security Policies (CSP), frame denial headers (anti-clickjacking), Strict-Transport-Security (HSTS), and parameter validation.

**HELIOS operates under a zero-fake-data policy:** It executes genuine HTTP network probes against targets, parses actual HTTP response headers, dynamically calculates objective risk scores (0–100), maps full attack paths, provides concrete remediation snippets, and conducts live re-testing to verify fixes.

---

## 2. Key Features

### 🛡️ Real-World Target Security Scanner
- Probes live web applications over HTTP/HTTPS.
- Audits critical security headers:
  - `Content-Security-Policy` (XSS & data exfiltration defense)
  - `Strict-Transport-Security` (SSL stripping & MitM defense)
  - `X-Frame-Options` (Clickjacking defense)
  - `X-Content-Type-Options` (MIME confusion defense)
  - Server disclosure & version fingerprinting
- Computes real-time risk scores categorized into CLEAN, MEDIUM, HIGH, and CRITICAL.

### 🎙️ Two-Way AI Voice Copilot
- **Voice Greeting:** Automatically greets aloud with *"Welcome sir, how may I help you?"* upon site open or clicking the mic.
- **Continuous Hands-Free Dialogue:** Automatically resumes listening after speaking answers so users can have continuous multi-turn conversations.
- **Smart Silence Detection:** 1.5-second silence timer ensures natural speaking cadence without premature cutoffs.
- **Dual Brain Architecture:** Powered by Google Gemini 3.5 / 2.0 with resilient local heuristic fallback.
- **English Voice Synthesis:** Powered by ElevenLabs text-to-speech with high-definition fallback.

### 🔄 Live Re-Testing Engine
- Verifies vulnerability remediation on live targets in real-time.
- Flags findings dynamically as `RESOLVED` or `STILL VULNERABLE`.

### ⚡ Attack-Path Visualizer
- Maps how absent security controls chain together into high-impact exploits (e.g. Missing HSTS $\to$ SSL Stripping $\to$ Plaintext Interception $\to$ Account Takeover).

### 📑 Executive CISO Audit Report
- Generates publication-ready compliance audits with print-to-PDF formatting.

---

## 3. System Architecture

```
+-------------------------------------------------------------+
|                  HELIOS Frontend (React)                    |
|  - Real-World Security Tracker   - Interactive Security Lab |
|  - Attack Paths & Topology Graph - Executive CISO Report    |
|  - Glassmorphism UI (Light / Dark Mode Toggle)              |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|               HELIOS Voice Copilot Engine                   |
|  - Web Speech API Continuous Audio Buffer                   |
|  - 1.5s Silence Detection   - Pure Web Audio Chimes         |
|  - Hands-Free Autonomous Turn-Taking Controller             |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|           HELIOS Autonomous Server (Python 3.13)            |
|  - Zero-Dependency Standard Library HTTP Engine             |
|  - Live HTTP Target Probe    - Heuristic Intent Engine      |
|  - CWE & CVE Knowledge Base  - Live Re-Test Verification    |
+--------------+-------------------------------+--------------+
               |                               |
               v                               v
+------------------------------+ +----------------------------+
|   Google Gemini 3.5 Brain    | |  ElevenLabs Voice Engine   |
| (Multi-Model Fallback Chain) | |   (High-Def English MP3)   |
+------------------------------+ +----------------------------+
```

---

## 4. API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan-url` | Performs live HTTP probe against target URL and evaluates security headers. |
| `POST` | `/api/retest-url` | Re-probes live target to verify if a security finding was resolved. |
| `POST` | `/api/scan-code` | Static analysis scanner for code injection, SQLi, and secret leakage. |
| `POST` | `/api/v1/voice/command` | Natural language voice intent parser (Gemini 3.5 + fallback). |
| `GET` | `/api/v1/voice/tts` | Synthesizes spoken English MP3 stream. |
| `POST` | `/api/v1/settings` | Updates Gemini model, Gemini API key, and ElevenLabs credentials. |

---

## 5. Security Threat Model
HELIOS is built with defense-in-depth principles:
1. **SSRF Mitigation:** Restricts outbound probes to valid HTTP/HTTPS schemes.
2. **Audio Sanitization:** Redacts API keys, authorization tokens, and credentials before TTS audio synthesis.
3. **Prompt Injection Firewall:** Blocks acoustic injection attacks (e.g. "ignore previous rules", "drop table").
4. **Zero Third-Party Vulnerabilities:** Core server utilizes standard library modules with zero unvetted external dependencies.
