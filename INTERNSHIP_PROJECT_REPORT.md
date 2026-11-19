# THIRANEX CYBER SECURITY INTERNSHIP
## FINAL PROJECT REPORT

---

# PASSWORD STRENGTH ANALYZER
### A Zero-Knowledge Client-Side Credential Resilience and Entropy Evaluation Suite

- **Candidate Name:** Mohamed Luqman
- **Internship Organization:** Thiranex
- **Domain:** Cyber Security & Defensive Engineering
- **Project Repository:** Password Strength Analyzer
- **Tech Stack:** HTML5, CSS3, JavaScript (ES6+), Python (Flask / Standard Library HTTP)
- **Evaluation Standard:** NIST SP 800-63B, OWASP Authentication Guidelines, CIS Benchmarks

---

## 1. ABSTRACT

In contemporary enterprise cybersecurity, compromised, weak, or re-used credentials account for over **80% of data breaches, unauthorized initial access, and Account Takeover (ATO) incidents**. Traditional password strength meters are frequently misleading: they count simple string lengths while ignoring real-world adversary tools, such as rule-based hybrid dictionary attacks (Hashcat, John the Ripper), automated keyboard walk masks, and breached password wordlists.

The **Password Strength Analyzer** was engineered as an enterprise-grade, privacy-first cybersecurity utility for the **Thiranex Cyber Security Internship**. It performs real-time heuristic security audits including:
1. **Mathematical Shannon Information Entropy** estimation in bits.
2. **Offline Multi-GPU Brute-Force Cracking Projections** based on modern hashcat benchmarks ($10 \text{ GH/s}$).
3. **Breached Wordlist Cross-Referencing** against the most commonly leaked credentials worldwide.
4. **Predictable Keyboard Walk & Repeated Character Detection**.
5. **CSPRNG Cryptographic Random Key Generation** backed by `window.crypto.getRandomValues()`.
6. **Sanitized Security Audit Report Exporting** with credential masking.

Crucially, the entire analysis operates under a **Zero-Trust, Zero-Knowledge Client-Side Architecture**: cleartext credentials are never transmitted over network protocols, never saved to storage or cookies, and never written to developer logs.

---

## 2. PROBLEM STATEMENT & THREAT LANDSCAPE

### 2.1 The Vulnerability of Passwords
Despite the advent of biometric authentication and FIDO2 hardware keys, passwords remain the primary authentication gate across corporate networks and consumer systems. Threat actors utilize several automated attack vectors:
- **Brute-Force Attacks:** Systematically testing every permutation of a character keyspace.
- **Dictionary Attacks:** Cross-referencing stolen hashes against billions of leaked passwords (e.g., RockYou, SecLists).
- **Rule-Based Hybrid Attacks:** Applying automated mutation rules (e.g., appending years, leetspeak replacements like `a` $\rightarrow$ `@`, `e` $\rightarrow$ `3`).
- **Credential Stuffing:** Replaying leaked email/password pairs across banking, email, and corporate VPN portals.

### 2.2 Shortcomings of Legacy Checkers
Many legacy checkers encourage false security by rewarding predictable patterns (e.g. `Password123!`), which technically meet 8-character and multi-case rules but are cracked in under a millisecond by modern dictionary tools.

---

## 3. ZERO-KNOWLEDGE ARCHITECTURE & DATA FLOW

A core tenet of cybersecurity defensive engineering is that **evaluating security must never introduce new attack surfaces**. Sending a user's password to an online server for analysis creates risks of Man-in-the-Middle (MitM) interception, server logging leakage, and third-party sniffing.

```text
+---------------------------------------------------------------------------------+
|                       USER BROWSER (V8 JAVASCRIPT ENGINE)                       |
|                                                                                 |
|  [ User Input / CSPRNG ]                                                        |
|           |                                                                     |
|           +---> [ Character Diversity ] ----> Pool Size (R: 10 - 95 chars)       |
|           |                                                                     |
|           +---> [ Shannon Entropy Engine ] -> E = L * log2(R) (Bits)            |
|           |                                                                     |
|           +---> [ Breached Wordlist Match ] -> SecLists / RockYou Dictionary    |
|           |                                                                     |
|           +---> [ Pattern & Sequence Walk ] -> Keyboard Walk / Repeats Check    |
|           |                                                                     |
|           v                                                                     |
|  [ Holistic Scoring (0-100) ] ===> [ Visual Meter, SVG Gauge, Telemetry Matrix ]|
+---------------------------------------------------------------------------------+
          |                                                     |
          x  BLOCKED: Zero Network Transmission                 x  BLOCKED: Zero Storage
          x  (No fetch / No XMLHttpRequest / No form post)      x  (No localStorage/Cookies)
```

### Architectural Guarantees:
- **No Network Transmission:** All algorithms evaluate strictly within local browser RAM.
- **No Persistent Storage:** `localStorage`, `sessionStorage`, `IndexedDB`, and `document.cookie` remain completely untouched.
- **No Logging:** Developer console logging is avoided to prevent in-memory inspection.
- **Sanitized Export:** When downloading audit reports, credentials are systematically masked (e.g., `T**********c`).

---

## 4. MATHEMATICAL FORMULAS & ALGORITHMIC METHODOLOGY

### 4.1 Shannon Information Entropy
Entropy measures the uncertainty and informational density of the password:

$$E = L \times \log_2(R)$$

Where:
- $L$ is the string length.
- $R$ is the size of the character pool derived from the character classes actively present:
  - Lowercase letters ($a-z$): $+26$
  - Uppercase letters ($A-Z$): $+26$
  - Numbers ($0-9$): $+10$
  - Special characters (!@#$%...): $+33$

### 4.2 Cracking Time Estimation Across Attack Vectors
The mathematical keyspace contains $R^L$ possible permutations. On average, an adversary cracks the credential after testing 50% of the keyspace ($R^L / 2$).

The application evaluates three adversarial threat models:
1. **Online Web Application (Throttled):**
   - Speed: $100 \text{ guesses/sec}$ (Rate-limited, CAPTCHA protected).
2. **Desktop Personal Computer (CPU Brute Force):**
   - Speed: $50,000 \text{ hashes/sec}$.
3. **High-Performance Multi-GPU Hashcat Cluster:**
   - Speed: $10,000,000,000 \text{ hashes/sec}$ ($10 \text{ GH/s}$).

### 4.3 Dictionary & Pattern Penalties
- If the credential matches the breached dictionary, its score is clamped to a maximum of **15 points**, and crack time is immediately reported as **Instant (< 1 millisecond)**.
- Consecutive repeated characters ($3+$ in a row, e.g., `aaa`) receive a $-15$ point deduction and $-10$ bit entropy deduction.
- Sequential keyboard patterns (`1234`, `qwerty`, `abcd`) receive a $-15$ point deduction.

---

## 5. EXPERIMENTAL VERIFICATION & TEST RESULTS

The application was tested against the 6 required test conditions using the automated test suite ([test/test-analyzer.js](file:///c:/Users/moham/OneDrive/Documents/Password-Strength-Analyzer/test/test-analyzer.js)):

| Test Case | Sample Input | Expected Behavior | Measured Score | Assigned Tier | Status |
| :---: | :--- | :--- | :---: | :---: | :---: |
| **TC-01** | `""` (Empty) | Graceful awaiting state | `0 / 100` | Awaiting Input | **PASS** |
| **TC-02** | `"cat"` (Short) | Length violation penalty ($< 8$ chars) | `4 / 100` | Very Weak | **PASS** |
| **TC-03** | `"supercalifragilistic"` | Lowercase only; single-pool penalty | `40 / 100` | Weak | **PASS** |
| **TC-04** | `"CyberSecurityDefense"` | Mixed case; missing digits & symbols | `35 / 100` | Weak | **PASS** |
| **TC-05** | `"Thiranex#2026!Sec"` | Full 4-class diversity, high entropy | `100 / 100` | Very Strong | **PASS** |
| **TC-06** | `"password123"` | Dictionary breach wordlist detection | `15 / 100` | Very Weak (Compromised) | **PASS** |

**Automated Test Summary:** 6 / 6 Test Cases Passed with 100% compliance.

---

## 6. OWASP HTTP SECURITY HEADERS (BACKEND HARDENING)

For deployment environments serving through the included Python Flask server ([app.py](file:///c:/Users/moham/OneDrive/Documents/Password-Strength-Analyzer/app.py)) or standard library server ([server.py](file:///c:/Users/moham/OneDrive/Documents/Password-Strength-Analyzer/server.py)), enterprise-grade HTTP response headers are enforced:

- `Content-Security-Policy (CSP)`: Restricts script, style, and media sources strictly to `'self'`.
- `X-Frame-Options`: Set to `DENY` to eliminate Clickjacking / UI Redressing attacks.
- `X-Content-Type-Options`: Set to `nosniff` to protect against MIME confusion vulnerabilities.
- `Referrer-Policy`: Set to `no-referrer` to prevent URL leakage.
- `Permissions-Policy`: Blocks camera, microphone, and geolocation access.

---

## 7. CONCLUSION & RECOMMENDATIONS

The **Password Strength Analyzer** provides a robust, scientifically backed, and privacy-preserving platform for credential strength assessment.

### Key Takeaways for Defensive Security:
1. **Length over Complexity:** Passphrases composed of 4–5 random words (e.g., `correct-horse-battery-staple`) provide greater brute-force resistance than 8-character complex words while remaining memorable.
2. **Mandatory MFA:** Passwords alone do not suffice. Multi-Factor Authentication (TOTP / FIDO2) must be enforced across all privileged access vectors.
3. **Password Managers:** Users should be guided away from reusing passwords and towards cryptographically secure password vaults (Bitwarden, 1Password, KeePass).

---

## 8. REFERENCES & STANDARDS

1. **NIST SP 800-63B:** *Digital Identity Guidelines — Authentication and Lifecycle Management*. National Institute of Standards and Technology.
2. **OWASP Foundation:** *Authentication Cheat Sheet & Password Storage Cheat Sheet*.
3. **CISA:** *Cyber Hygiene Services & Credential Protection Best Practices*. Cybersecurity and Infrastructure Security Agency.
4. **Shannon, C. E. (1948):** *A Mathematical Theory of Communication*. Bell System Technical Journal.
