# Password Strength Analyzer 🛡️

> **A professional, zero-knowledge cybersecurity web application designed to evaluate password resilience, Shannon entropy, and brute-force cracking resistance.**  
> *Developed for the **Thiranex Cyber Security Internship**.*

---

## 📋 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Zero-Knowledge Privacy Architecture](#-zero-knowledge-privacy-architecture)
4. [Cybersecurity Methodology & Formulas](#-cybersecurity-methodology--formulas)
5. [Project Folder Structure](#-project-folder-structure)
6. [How to Run Locally](#-how-to-run-locally)
   - [Method 1: Direct in Browser (Zero Setup)](#method-1-direct-in-browser-zero-setup)
   - [Method 2: Python Standard Library Server](#method-2-python-standard-library-server)
   - [Method 3: Python Flask Server (With OWASP Security Headers)](#method-3-python-flask-server)
7. [Automated Testing & Verification](#-automated-testing--verification)
8. [Technologies Used](#-technologies-used)
9. [Internship Project Attribution](#-internship-project-attribution)

---

## 🌟 Project Overview

In contemporary cybersecurity, weak or compromised credentials account for over **80% of data breaches and account takeover (ATO) attacks**. The **Password Strength Analyzer** was engineered to provide users with an educational, real-time, and privacy-preserving platform to audit passwords against enterprise-grade defensive standards (NIST SP 800-63B, OWASP, and CISA).

Unlike simplistic checkers that merely count character length, this tool computes **mathematical information entropy**, evaluates character diversity, analyzes dictionary matches against known breached wordlists (SecLists / RockYou), detects keyboard walk patterns, and projects real-world cracking timelines against modern high-performance GPU clusters.

---

## ⚡ Key Features

- **Cybersecurity Dark Theme:** High-tech dark navy background (`#070b14`) accented with electric cyan (`#00f2fe`) and neon blue (`#38bdf8`), subtle grid lines, and glassmorphism cards.
- **Dynamic Real-Time Strength Meter:** Continuously updates strength tiers (`Very Weak`, `Weak`, `Medium`, `Strong`, `Very Strong`) with animated glowing color transitions.
- **Visual Circular Score Gauge:** 0 to 100 numerical score display with an animated SVG radial progress ring.
- **Interactive Security Checklist:** Dynamic indicators with green checkmarks (`✔`) and red crosses (`✖`) for:
  - Minimum 8 characters (12+ recommended).
  - Uppercase letters (`A-Z`).
  - Lowercase letters (`a-z`).
  - Numeric digits (`0-9`).
  - Special symbols (`!@#$%^&*...`).
  - Breached/common dictionary check.
  - Predictable keyboard sequence and repeated character detection.
- **Dynamic Improvement Recommendations:** Context-aware suggestions identifying missing criteria, keyboard walk sequences, and critical dictionary warnings.
- **Shannon Entropy & Cracking Time Telemetry:** Calculates theoretical entropy in bits and estimates cracking time at an offline attack rate of **10 billion guesses/second (10 GH/s)**.
- **CSPRNG Password Generator:** Integrated random password generator powered by `window.crypto.getRandomValues()` with customizable length and character sets.
- **Demonstration Presets:** One-click sample buttons to quickly showcase short, compromised, sequence-based, medium, and high-entropy passwords during evaluations.
- **Interactive Controls:** Show/Hide password toggle, single-click clear, and full analyzer reset.
- **Educational Security Tips:** Best practices on Passphrases, Password Managers, Multi-Factor Authentication (MFA), and Credential Stuffing prevention.

---

## 🔒 Zero-Knowledge Privacy Architecture

A core principle of cybersecurity is **Zero Trust**: **Never send a user's cleartext password across the internet.**

This project strictly enforces:
1. **100% Client-Side Execution:** All evaluations and algorithms run directly in the client's browser (V8 engine).
2. **Zero Network Transmission:** No `POST`, `fetch`, or `XMLHttpRequest` calls transmit the password.
3. **Zero Storage:** Passwords are never saved to `localStorage`, `sessionStorage`, `IndexedDB`, or `cookies`.
4. **Zero Console Logging:** Developer tools console logging is strictly prohibited.
5. **Memory Sanitization:** The memory and inputs are cleared on form reset and page unload.

---

## 🧮 Cybersecurity Methodology & Formulas

### 1. Shannon Information Entropy
Password entropy measures the computational unpredictability of a credential:

$$E = L \times \log_2(R)$$

Where:
- $L$ = Length of the password.
- $R$ = Size of the character pool:
  - Lowercase letters ($a-z$): $26$
  - Uppercase letters ($A-Z$): $26$
  - Numbers ($0-9$): $10$
  - Special characters: $33$

### 2. Brute-Force Cracking Time Estimate
Cracking time assumes an attacker using an offline modern GPU cluster testing $10^{10}$ (10 Billion) hashes/sec:

$$\text{Attempts} = \frac{R^L}{2}$$

$$\text{Time (seconds)} = \frac{\text{Attempts}}{10^{10}}$$

### 3. Pattern & Dictionary Penalties
- **Common Passwords:** Exact and root-word matches against top breached wordlists (e.g. `password123`, `123456`, `admin`, `qwerty`) cap the score at $\le 15$ and trigger a critical security alert.
- **Sequential Walks:** Sequences such as `1234`, `abc`, `qwerty` receive penalty deductions.
- **Consecutive Repeats:** Identical consecutive characters (e.g. `aaa`, `111`) are detected and penalized.

---

## 📁 Project Folder Structure

```text
Password-Strength-Analyzer/
│
├── index.html                  # Main responsive web application with all sections
│
├── css/
│   ├── style.css               # Dark navy cybersecurity theme, layout, and responsive rules
│   └── animations.css          # Glow effects, pulses, and transitions
│
├── js/
│   ├── common-passwords.js     # Breached passwords database and keyboard walk patterns
│   └── script.js               # Core analysis engine, entropy math, and UI interactivity
│
├── assets/
│   └── favicon.svg             # Cybersecurity shield logo favicon
│
├── python/                     # Optional Python hosting scripts
│   ├── app.py                  # Flask application serving with OWASP security headers
│   └── server.py               # Zero-dependency Python standard library server
│
├── app.py                      # Root shortcut to launch Flask server
├── server.py                   # Root shortcut to launch standard Python server
├── requirements.txt            # Optional dependencies (Flask)
│
├── test/
│   └── test-analyzer.js        # Automated verification script testing all 6 mandatory cases
│
└── README.md                   # Full documentation and internship project report
```

---

## 🚀 How to Run Locally

### Method 1: Direct in Browser (Zero Setup)
No installation or dependencies required:
1. Navigate to the project folder:
   ```bash
   cd Password-Strength-Analyzer
   ```
2. Double-click `index.html` or open it with any web browser (Chrome, Edge, Firefox, Brave, Safari).
3. The application is immediately fully functional!

---

### Method 2: Python Standard Library Server
Runs using Python's built-in standard library (no `pip` installs needed):
1. In your terminal, run:
   ```bash
   python server.py
   ```
2. Open your browser and visit:
   ```
   http://127.0.0.1:8000
   ```

---

### Method 3: Python Flask Server
Runs with Flask and applies hardened OWASP HTTP Security Headers:
1. Install Flask:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the Flask application:
   ```bash
   python app.py
   ```
3. Open your browser and visit:
   ```
   http://127.0.0.1:5000
   ```

---

## 🧪 Automated Testing & Verification

The project includes an automated test script (`test/test-analyzer.js`) that validates all required edge cases:

1. **Empty input:** Score 0, returns graceful awaiting state.
2. **Short password:** Input `< 8` characters (e.g., `"cat"`), flagged as `Very Weak`.
3. **Lowercase only:** Input with only `a-z` (e.g., `"supercalifragilistic"`), penalizes limited keyspace.
4. **Uppercase and Lowercase:** Mixed-case input (e.g., `"CyberSecurityDefense"`), checks case diversity.
5. **Numbers and Special Characters:** Full 4-class mix (e.g., `"Thiranex#2026!Sec"`), scores `Very Strong` with high entropy.
6. **Commonly Guessed Password:** Breached password (e.g., `"password123"`), hard-capped at $\le 15$ with critical security warning.

### Running the Test Suite:
```bash
node test/test-analyzer.js
```

### Test Suite Output:
```text
=================================================================
  PASSWORD STRENGTH ANALYZER - AUTOMATED VERIFICATION SUITE
  Thiranex Cyber Security Internship
=================================================================

[PASS] Test Case 1: Empty input
       Input: ""
       Detail: Passed: Handled empty state gracefully with 0 score.

[PASS] Test Case 2: Short password ('cat')
       Input: "cat"
       Detail: Passed: Identified as short (3 chars), tier: Very Weak, score: 4

[PASS] Test Case 3: Password containing only lowercase letters ('supercalifragilistic')
       Input: "supercalifragilistic"
       Detail: Passed: Verified lowercase-only constraint, penalized single-pool keyspace. Score: 40, Tier: Weak

[PASS] Test Case 4: Password containing uppercase and lowercase letters ('CyberSecurityDefense')
       Input: "CyberSecurityDefense"
       Detail: Passed: Both case sets detected. Score: 35, Tier: Weak, Entropy: 104 bits

[PASS] Test Case 5: Password containing numbers and special characters ('Thiranex#2026!Sec')
       Input: "Thiranex#2026!Sec"
       Detail: Passed: Full character diversity satisfied. Score: 100, Tier: Very Strong, Entropy: 112 bits

[PASS] Test Case 6: Commonly guessed password ('password123')
       Input: "password123"
       Detail: Passed: Correctly flagged as compromised/breached word. Score: 15, Tier: Very Weak (Compromised)

-----------------------------------------------------------------
TEST SUMMARY: 6 / 6 Tests Passed Successfully.
-----------------------------------------------------------------
STATUS: ALL CYBERSECURITY ENGINE TEST CRITERIA VALIDATED! [OK]
```

---

## 🛠️ Technologies Used

| Technology | Purpose |
| :--- | :--- |
| **HTML5** | Semantic structure, accessible ARIA attributes, responsive layout. |
| **CSS3** | Modern dark navy cyber UI, glassmorphism, flexbox/grid, CSS custom properties. |
| **JavaScript (ES6+)** | Zero-knowledge client-side entropy calculation, regex analysis, CSPRNG generation. |
| **Python (Standard Library & Flask)** | Hardened HTTP web server, OWASP security headers injection. |
| **SVG** | Vector graphics, responsive gauges, and crisp cybersecurity iconography. |

---

## 🎓 Internship Project Attribution

- **Project:** Password Strength Analyzer
- **Internship Program:** Cyber Security Internship
- **Organization:** Thiranex
- **Domain:** Application Security & Defensive Engineering

*Developed with a commitment to zero-trust privacy, credential hygiene, and user education.*

