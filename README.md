# HELIOS — AI-Powered Autonomous Security Engineer
> **Build with AI. Secure with HELIOS.**  
> *Autonomous AI Security Agent for Web Applications with Real-Time Two-Way Voice Copilot.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Model](https://img.shields.io/badge/Brain-Gemini%203.5-orange.svg)](https://deepmind.google/technologies/gemini/)
[![Voice](https://img.shields.io/badge/Voice-ElevenLabs-purple.svg)](https://elevenlabs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero-Dependency](https://img.shields.io/badge/Dependencies-Standard%20Library-brightgreen.svg)]()

---

## 📸 Screenshots

| Real-World Security Tracker & Posture HUD | Interactive Security Lab & Code Workbench |
| :---: | :---: |
| ![Screenshot 1](screenshots/screenshot-1.png) | ![Screenshot 2](screenshots/screenshot-2.png) |

---

## 🌟 Key Capabilities

- 🔍 **Real-World Security Scanner:** Conducts live HTTP network probes against real target websites (e.g. `https://see-it-report-it.lovable.app`), inspects response headers, and calculates authentic risk scores.
- 🎙️ **Hands-Free Two-Way Voice Copilot:**
  - Speaks aloud on site open: *"Welcome sir, how may I help you?"*
  - Continuous dialogue mode: automatically re-arms listening after speaking answers.
  - Smart 1.5s silence detection ensures speech is never cut off prematurely.
  - Generates synthetic Web Audio acoustic chimes.
- 🧠 **Gemini 3.5 Brain:** High-intelligence intent parsing with resilient multi-model fallback cascade (`gemini-3.5` $\to$ `gemini-2.0-flash` $\to$ `gemini-1.5-flash`).
- 🔄 **Live Re-Testing Verification:** Re-audits live targets on demand and marks vulnerabilities as `RESOLVED` or `STILL VULNERABLE`.
- ⚡ **Attack-Path Engine:** Maps chained vulnerabilities into visual exploit flows.
- 🌓 **Enterprise Light & Cyber Dark Mode:** High-contrast themes switchable with one click or voice command.
- 📑 **CISO Report Generator:** One-click executive audit report exportable to PDF.

---

## 📁 Repository Structure

```
KH001-TeamName/
├── README.md                     # Project overview, setup, and usage guide
├── LICENSE                       # MIT License
├── requirements.txt              # Dependency specification
├── .gitignore                    # Git ignore file
├── src/                          # Application source code
│   ├── server.py                 # Autonomous security server & voice engine
│   ├── helios.html               # Glassmorphism frontend & voice copilot
│   └── .env.example              # Environment variables template
├── docs/                         # Project documentation and architecture
│   ├── project-documentation.pdf # Complete PDF technical specification
│   ├── project-documentation.md  # Detailed markdown documentation
│   ├── architecture.png          # High-resolution system architecture diagram
│   └── other-diagrams/           # Exploit chain & attack path diagrams
│       └── attack-flow.png
├── screenshots/                  # High-resolution application UI screenshots
│   ├── screenshot-1.png          # Real-world target tracker
│   ├── screenshot-2.png          # Interactive security lab
│   └── screenshot-3.png          # Real-time voice copilot
└── data/                         # Security rules catalog and CWE datasets
    ├── README.md                 # Data documentation & zero fake data policy
    └── security_rules.json       # Security header benchmark rules
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.10 or higher.
- Modern web browser (Chrome, Edge, Safari, or Firefox).

### 2. Run HELIOS Locally
```bash
# Navigate to source directory
cd src

# Start the autonomous server
python server.py
```

### 3. Open in Browser
Visit **[http://localhost:3000/helios.html](http://localhost:3000/helios.html)** in your browser.

> **Voice Greeting:** Click anywhere on the page or tap the Voice Orb in the bottom-right corner. HELIOS will immediately speak:  
> *"Welcome sir, how may I help you?"*

---

## 🗣️ Voice Commands Cheatsheet

| Spoken Command | Action Taken |
| :--- | :--- |
| *"Kindly run security scan on this website"* | Probes the target server over HTTP, computes risk score, and reports findings. |
| *"Scan https://example.com"* | Audits the specified URL directly and updates the tracker. |
| *"Retest finding HLS-WEB-001"* | Performs live re-test and confirms if CSP was fixed. |
| *"Switch to light mode"* / *"Switch to dark mode"* | Toggles interface theme with spoken confirmation. |
| *"What is CSP?"* / *"Explain clickjacking"* | Explains vulnerability theory and displays remediation snippets. |
| *"Show attack paths"* / *"Open CISO report"* | Navigates directly to the requested view. |
| *"Goodbye"* / *"Stop"* | Puts the voice copilot into polite standby. |

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
