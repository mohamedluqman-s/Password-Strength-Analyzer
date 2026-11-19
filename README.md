# CyberShield Password Strength Analyzer 🛡️

> **An Enterprise-Grade, Zero-Knowledge Credential Security Audit & Entropy Evaluation Suite**  
> *Developed for the **Thiranex Cyber Security Internship**.*

---

## 📋 Table of Contents
1. [Project Introduction](#-project-introduction)
2. [Project Objectives](#-project-objectives)
3. [Technologies Used](#-technologies-used)
4. [Features and Functionalities](#-features-and-functionalities)
5. [Project Folder Structure](#-project-folder-structure)
6. [Installation and Execution Instructions](#-installation-and-execution-instructions)
   - [Method 1: Direct Web Browser Execution (Zero Setup)](#method-1-direct-web-browser-execution-zero-setup)
   - [Method 2: Python Standard Library Server](#method-2-python-standard-library-server)
   - [Method 3: Python Flask Server (With OWASP Security Headers)](#method-3-python-flask-server-with-owasp-security-headers)
7. [Automated Verification & Testing](#-automated-verification--testing)
8. [Cybersecurity References & Compliance](#-cybersecurity-references--compliance)

---

## 🌟 Project Introduction

In contemporary information security, compromised, weak, and predictable passwords represent the primary initial attack vector in more than **80% of data breaches and automated credential-stuffing campaigns** (Verizon DBIR, OWASP Top 10). Traditional client-side password strength checkers often mislead users by merely checking character length or enforcing basic character classes without assessing mathematical keyspace density, keyboard walk sequences, or breached wordlist prevalence.

The **CyberShield Password Strength Analyzer** is a defensive cybersecurity tool designed to provide real-time, mathematically grounded password evaluation. Built under a strict **Zero-Trust, Zero-Knowledge Architecture**, the application conducts all evaluations directly inside the user's browser runtime. Cleartext credentials never cross network boundaries, are never written to disk or browser storage, and are never logged to developer consoles.

---

## 🎯 Project Objectives

1. **Provide Real-Time Heuristic Password Strength Evaluation:** Implement dynamic, multi-factor credential auditing based on character diversity, length thresholds, pattern recognition, and breached password detection.
2. **Compute Mathematical Shannon Information Entropy:** Calculate informational unpredictability in bits ($E = L \times \log_2(R)$) to demonstrate mathematical keyspace depth.
3. **Simulate Adversarial Cracking Resilience:** Model theoretical brute-force cracking resistance across three attack models (Throttled Web App, Desktop CPU, and Modern GPU Rig at 10 GH/s).
4. **Enforce Absolute Zero-Knowledge Privacy:** Guarantee that user credentials are never transmitted over HTTP/WebSocket, never stored in `localStorage`, `sessionStorage`, or cookies, and never output to telemetry.
5. **Promote Defensive Security Hygiene:** Educate users on modern defensive practices aligned with **NIST SP 800-63B**, multi-word passphrases, Multi-Factor Authentication (MFA), and password managers.
6. **Provide Cryptographically Secure Key Generation:** Integrate a CSPRNG generator backed by `window.crypto.getRandomValues()` for generating random credentials locally.

---

## 🛠️ Technologies Used

| Technology | Layer | Purpose |
| :--- | :--- | :--- |
| **HTML5** | Presentation / DOM | Semantic structure, accessible form controls, ARIA labeling, and responsive container layout. |
| **CSS3** | Presentation / Styling | Cyberpunk dark navy theme (`#070b14`), glassmorphism, responsive grid/flexbox, custom properties, and animations. |
| **JavaScript (ES6+)** | Core Engine | Zero-knowledge client-side evaluation, Shannon entropy computation, regular expressions, and CSPRNG generation. |
| **Python (Flask & Standard Library)** | Backend Serving | Lightweight servers injecting OWASP-aligned HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options). |
| **Node.js** | Quality Assurance | Automated test runner executing comprehensive audit scripts. |
| **SVG (Scalable Vector Graphics)** | Visualization | Inline vector iconography and dynamic circular score gauge rendering. |

---

## ⚡ Features and Functionalities

### 1. Interactive Credential Input & Controls
- **Masked Input Field:** Monospace password field with real-time analysis triggered on typing.
- **Show/Hide Visibility Toggle:** SVG eye / eye-slash button with dynamic `aria-label` and `title` synchronization.
- **Single-Click Clear:** Instantly clears input text and resets character count.
- **Full Form Reset:** Purges input and restores all gauges, checklist indicators, telemetry boxes, and alerts to default states.

### 2. Multi-Factor Strength & Entropy Evaluation
- **Dynamic Strength Meter:** Real-time progress bar transitioning smoothly between 5 tiers:
  - *Very Weak* (`#ef4444`, Score $\le 25$)
  - *Weak* (`#f97316`, Score $26\text{--}50$)
  - *Medium* (`#f59e0b`, Score $51\text{--}74$)
  - *Strong* (`#38bdf8`, Score $75\text{--}89$)
  - *Very Strong* (`#10b981`, Score $90\text{--}100$)
- **Circular SVG Score Gauge:** Numerical rating from 0 to 100 with stroke-dashoffset transition.
- **Shannon Entropy Readout:** Calculates information entropy in bits ($E = L \times \log_2(R)$) adjusted for pattern penalties.
- **Theoretical Cracking Projections:** Projects approximate brute-force time against an offline 10 GH/s GPU cluster.
- **Comparative Attack Vectors Matrix:** Compares estimated resistance across:
  - Web Application ($100\text{ guesses/sec}$)
  - Desktop CPU ($50,000\text{ hashes/sec}$)
  - High-Performance GPU Rig ($10,000,000,000\text{ hashes/sec}$)

### 3. Seven-Point Security Criteria Checklist
Real-time visual checklist updating with green checkmarks (`✔`) or red crosses (`✖`):
1. **Minimum Length:** 8+ characters (with 12+ and 16+ bonus scaling).
2. **Uppercase Letters:** Detects characters `A-Z`.
3. **Lowercase Letters:** Detects characters `a-z`.
4. **Numeric Digits:** Detects characters `0-9`.
5. **Special Symbols:** Detects non-alphanumeric characters, symbols, and passphrase spaces (`/[^a-zA-Z0-9]/`).
6. **Breached Wordlist Check:** Offline dictionary verification against 144+ compromised passwords, root words, and leetspeak mutations (`p@ssw0rd`).
7. **Pattern & Sequence Detection:** Flags repeated characters (`aaa`, `121212`, `ababab`) and keyboard walks (`123456`, `qwerty`, `cba`).

### 4. CSPRNG Password Generator
- Generates cryptographically secure random credentials via `window.crypto.getRandomValues()`.
- Configurable length slider (8 to 32 characters).
- Independent character-set toggles (Uppercase, Lowercase, Numbers, Symbols) with guaranteed representation.
- "Copy to Clipboard" with animated toast notification and "Test in Analyzer" integration.

### 5. Sanitized Security Audit Report Export
- Single-click download of a structured text audit report (`Security_Audit_Report_<timestamp>.txt`).
- **Zero-Knowledge Sanitization:** Credentials are automatically masked (e.g. `T**********c`) so cleartext passwords are never exported to disk.
- Includes full criteria breakdown, entropy calculation, attack matrix, and defensive recommendations.

### 6. Interactive Slide Deck
- Embedded 7-slide presentation deck ([presentation.html](file:///c:/Users/moham/OneDrive/Documents/Password-Strength-Analyzer/presentation.html)) for internship presentations and viva reviews.

---

## 📁 Project Folder Structure

```text
Password-Strength-Analyzer/
│
├── index.html                  # Main responsive single-page web application
├── presentation.html           # Interactive 7-slide presentation deck
├── README.md                   # Technical overview and execution instructions
├── PROJECT_REPORT.md           # Formal academic internship project report
├── TEST_CASES.md               # Detailed test matrix and QA verification log
├── requirements.txt            # Optional Python Flask dependencies
├── app.py                      # Flask web server with OWASP security headers
├── server.py                   # Python standard library HTTP server (zero install)
├── .gitignore                  # Git exclusion rules for clean version control
│
├── css/
│   ├── style.css               # Primary styling (Dark navy theme, CSS grid, glassmorphism)
│   └── animations.css          # Keyframes for cyber pulses, glowing borders, and meters
│
├── js/
│   ├── common-passwords.js     # Breached credentials database, root words & keyboard patterns
│   └── script.js               # Core analysis engine, entropy math, CSPRNG generator & DOM logic
│
├── assets/
│   └── favicon.svg             # Cybersecurity shield logo
│
└── test/
    ├── test-analyzer.js        # 6-factor automated verification script
    └── comprehensive-audit.js  # 12-factor deep audit and 15 fictional passwords test runner
```

---

## 🚀 Installation and Execution Instructions

### Method 1: Direct Web Browser Execution (Zero Setup)
Because the core application is implemented purely in client-side HTML5, CSS3, and JavaScript, it requires no runtime installation, build step, or server:
1. Navigate to the project directory:
   ```bash
   cd Password-Strength-Analyzer
   ```
2. Double-click `index.html` or open it with any web browser (Google Chrome, Microsoft Edge, Mozilla Firefox, Brave, Safari).
3. The application is immediately operational.

---

### Method 2: Python Standard Library Server
Runs a local HTTP server using Python's built-in standard library (no `pip` dependencies required):
1. In your terminal, execute:
   ```bash
   python server.py
   ```
2. Open your browser and navigate to:
   ```text
   http://127.0.0.1:8000
   ```
3. To view the presentation deck:
   ```text
   http://127.0.0.1:8000/presentation.html
   ```

---

### Method 3: Python Flask Server (With OWASP Security Headers)
Hosts the application with enterprise HTTP security headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options):
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the application:
   ```bash
   python app.py
   ```
3. Access the application in your browser at:
   ```text
   http://127.0.0.1:5000
   ```

---

## 🧪 Automated Verification & Testing

The application includes two automated test suites built for Node.js:

1. **Core Verification Suite:**
   ```bash
   node test/test-analyzer.js
   ```
   Validates 6 fundamental scenarios (Empty, Short, Lowercase, Mixed Case, Complex, Compromised).

2. **Comprehensive 12-Factor Security Audit:**
   ```bash
   node test/comprehensive-audit.js
   ```
   Executes 31 validation assertions across character classes, leetspeak normalization, pattern algorithms, boundary scoring, generator logic, zero-storage verification, and 15 distinct fictional test passwords.

---

## 📚 Cybersecurity References & Compliance

- **NIST Special Publication 800-63B:** *Digital Identity Guidelines — Authentication and Lifecycle Management*. National Institute of Standards and Technology.
- **OWASP Application Security Verification Standard (ASVS):** Authentication Verification Requirements (v4.0).
- **OWASP Authentication Cheat Sheet:** Guidance on password complexity, storage, and dictionary validation.
- **CISA:** *Cyber Hygiene Guidelines — Securing Passwords and Multi-Factor Authentication*.
- **Shannon, C. E. (1948):** *A Mathematical Theory of Communication*. Bell System Technical Journal, 27(3), 379–423.

---

**Internship Project Attribution:**  
- **Project Name:** CyberShield Password Strength Analyzer  
- **Internship:** Thiranex Cyber Security Internship  
- **Author:** Mohamed Luqman  
