/**
 * ============================================================================
 * PASSWORD STRENGTH ANALYZER - CORE CYBERSECURITY ENGINE
 * Thiranex Cyber Security Internship Project
 * ============================================================================
 * 
 * Objective:
 * Provides client-side, zero-knowledge password strength evaluation,
 * entropy estimation, cracking-time calculations, pattern detection,
 * and security suggestions.
 * 
 * Privacy & Security Architecture:
 * - 100% Client-side execution in the user's browser.
 * - Zero network requests: Passwords are NEVER transmitted over HTTP/WebSocket.
 * - Zero persistence: Passwords are NEVER written to localStorage, sessionStorage,
 *   IndexedDB, or cookies.
 * - Zero telemetry: Passwords are NEVER logged in console or sent to analytics.
 * ============================================================================
 */

(function () {
    "use strict";

    // ------------------------------------------------------------------------
    // DOM Elements Cache
    // ------------------------------------------------------------------------
    const passwordInput = document.getElementById("passwordInput");
    const toggleVisibilityBtn = document.getElementById("toggleVisibilityBtn");
    const toggleIcon = document.getElementById("toggleIcon");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const exportReportBtn = document.getElementById("exportReportBtn");
    const clearBtn = document.getElementById("clearBtn");
    const resetBtn = document.getElementById("resetBtn");

    // Indicator Elements
    const strengthBadge = document.getElementById("strengthBadge");
    const strengthMeterBar = document.getElementById("strengthMeterBar");
    const scoreNumber = document.getElementById("scoreNumber");
    const scoreCircle = document.getElementById("scoreCircle");
    const entropyValue = document.getElementById("entropyValue");
    const crackTimeValue = document.getElementById("crackTimeValue");
    const charCountValue = document.getElementById("charCountValue");
    const timeOnline = document.getElementById("timeOnline");
    const timeCpu = document.getElementById("timeCpu");
    const timeGpu = document.getElementById("timeGpu");

    // Checklist Elements
    const checkLength = document.getElementById("check-length");
    const checkUpper = document.getElementById("check-upper");
    const checkLower = document.getElementById("check-lower");
    const checkNumber = document.getElementById("check-number");
    const checkSpecial = document.getElementById("check-special");
    const checkCommon = document.getElementById("check-common");
    const checkPatterns = document.getElementById("check-patterns");

    // Suggestions & Alerts
    const suggestionsList = document.getElementById("suggestionsList");
    const alertBanner = document.getElementById("alertBanner");
    const alertMessage = document.getElementById("alertMessage");

    // Generator Elements
    const genLengthSlider = document.getElementById("genLengthSlider");
    const genLengthDisplay = document.getElementById("genLengthDisplay");
    const genUpperCheck = document.getElementById("genUpperCheck");
    const genLowerCheck = document.getElementById("genLowerCheck");
    const genNumbersCheck = document.getElementById("genNumbersCheck");
    const genSymbolsCheck = document.getElementById("genSymbolsCheck");
    const generateBtn = document.getElementById("generateBtn");
    const generatedPasswordInput = document.getElementById("generatedPasswordInput");
    const copyGeneratedBtn = document.getElementById("copyGeneratedBtn");
    const applyGeneratedBtn = document.getElementById("applyGeneratedBtn");
    const toastNotification = document.getElementById("toastNotification");

    // Quick Test Buttons
    const quickTestButtons = document.querySelectorAll(".quick-test-btn");

    // ------------------------------------------------------------------------
    // Configuration & Constants
    // ------------------------------------------------------------------------
    const SPECIAL_CHARS_REGEX = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/;
    const REPEATED_CHARS_REGEX = /(.)\1{2,}/i; // 3 or more consecutive identical chars

    // ------------------------------------------------------------------------
    // Helper: Toast Notification
    // ------------------------------------------------------------------------
    function showToast(message) {
        if (!toastNotification) return;
        toastNotification.textContent = message;
        toastNotification.classList.add("show");
        setTimeout(() => {
            toastNotification.classList.remove("show");
        }, 3000);
    }

    // ------------------------------------------------------------------------
    // Core Cybersecurity Logic: Analysis Engine
    // ------------------------------------------------------------------------

    /**
     * Checks if password contains sequential characters (e.g. "123", "abc", "qwerty")
     * @param {string} pwd
     * @returns {boolean} true if predictable sequence is detected
     */
    function detectSequentialPattern(pwd) {
        const lower = pwd.toLowerCase();
        if (lower.length < 3) return false;

        const patterns = (window.KEYBOARD_PATTERNS || [
            "abcdefghijklmnopqrstuvwxyz",
            "01234567890",
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ]);

        for (const pattern of patterns) {
            for (let i = 0; i <= pattern.length - 3; i++) {
                const sub = pattern.slice(i, i + 3);
                const revSub = sub.split("").reverse().join("");
                if (lower.includes(sub) || lower.includes(revSub)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if password exists in the breached/common password list
     * @param {string} pwd
     * @returns {boolean} true if common password
     */
    function isCommonPassword(pwd) {
        if (!pwd) return false;
        const normalized = pwd.trim().toLowerCase();
        const commonList = window.COMMON_PASSWORDS || [];

        // Exact match against breached dictionary
        if (commonList.includes(normalized)) {
            return true;
        }

        // Substring check for notorious root words if password length is small
        if (normalized.length <= 10) {
            const highRiskKeywords = ["password", "123456", "admin", "qwerty", "welcome", "iloveyou"];
            for (const word of highRiskKeywords) {
                if (normalized.includes(word)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Calculates Shannon entropy in bits for the password
     * E = L * log2(R)
     * where L = length, R = character pool size
     * @param {string} pwd
     * @param {object} criteria
     * @returns {number} entropy in bits
     */
    function calculateEntropy(pwd, criteria) {
        if (!pwd || pwd.length === 0) return 0;

        let poolSize = 0;
        if (criteria.hasLower) poolSize += 26;
        if (criteria.hasUpper) poolSize += 26;
        if (criteria.hasNumber) poolSize += 10;
        if (criteria.hasSpecial) poolSize += 33; // Standard printable ASCII special symbols

        if (poolSize === 0) poolSize = 10; // Fallback

        // Information entropy formula
        let entropy = pwd.length * (Math.log(poolSize) / Math.log(2));

        // Deductions for repetitive or predictable patterns
        if (criteria.hasRepeated) {
            entropy -= 10;
        }
        if (criteria.hasSequential) {
            entropy -= 10;
        }
        if (criteria.isCommon) {
            entropy = Math.min(entropy, 15); // Drastic reduction for breached words
        }

        return Math.max(0, Math.round(entropy));
    }

    /**
     * Estimates cracking time assuming an offline brute force cluster
     * calculating 10 billion (10^10) hashes/sec.
     * @param {number} entropyBits
     * @param {boolean} isBreached
     * @returns {string} human-readable cracking time
     */
    function estimateCrackingTime(entropyBits, isBreached) {
        if (isBreached) {
            return "Instant (< 1 millisecond - in breached wordlists)";
        }
        if (entropyBits === 0) return "0 seconds";

        // Total attempts on average is 2^(entropy - 1)
        // Rate: 10,000,000,000 guesses per second (10 GH/s)
        const guessesPerSecond = 1e10;
        const seconds = Math.pow(2, entropyBits - 1) / guessesPerSecond;

        if (seconds < 0.001) return "Instant (< 1 millisecond)";
        if (seconds < 1) return "Less than a second";
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
        if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)} years`;
        if (seconds < 31536000 * 10000) return `${Math.round(seconds / (31536000 * 100))} centuries`;
        return "Millions of years";
    }

    /**
     * Formats seconds into compact human-readable string for attack vectors
     */
    function formatSecondsCompact(seconds, isBreached) {
        if (isBreached) return "< 1ms";
        if (seconds <= 0) return "0s";
        if (seconds < 0.001) return "< 1ms";
        if (seconds < 1) return "< 1s";
        if (seconds < 60) return `${Math.round(seconds)}s`;
        if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
        if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
        if (seconds < 31536000) return `${Math.round(seconds / 86400)}d`;
        if (seconds < 31536000 * 100) return `${Math.round(seconds / 31536000)}y`;
        if (seconds < 31536000 * 10000) return `${Math.round(seconds / (31536000 * 100))} cent.`;
        return "> 1M yrs";
    }

    /**
     * Calculates comparative times across different adversary attack environments
     */
    function calculateAttackTimes(entropy, isBreached) {
        if (isBreached) {
            return { online: "< 1ms", cpu: "< 1ms", gpu: "< 1ms" };
        }
        if (entropy === 0) {
            return { online: "0s", cpu: "0s", gpu: "0s" };
        }
        const attempts = Math.pow(2, entropy - 1);
        return {
            online: formatSecondsCompact(attempts / 100, false),
            cpu: formatSecondsCompact(attempts / 50000, false),
            gpu: formatSecondsCompact(attempts / 1e10, false)
        };
    }

    /**
     * Computes holistic security score (0 to 100)
     * @param {string} pwd
     * @param {object} criteria
     * @returns {number} score between 0 and 100
     */
    function computeScore(pwd, criteria) {
        if (!pwd || pwd.length === 0) return 0;

        let score = 0;

        // 1. Length scoring (up to 40 points)
        const len = pwd.length;
        if (len < 6) {
            score += len * 3; // 0 - 15
        } else if (len < 8) {
            score += 15 + (len - 5) * 4; // 19 - 23
        } else if (len < 12) {
            score += 25 + (len - 8) * 3; // 25 - 34
        } else if (len < 16) {
            score += 35 + (len - 12) * 2; // 35 - 41
        } else {
            score += 45; // 16+ chars gets maximum length bonus
        }

        // 2. Character diversity (up to 45 points)
        if (criteria.hasLower) score += 10;
        if (criteria.hasUpper) score += 10;
        if (criteria.hasNumber) score += 10;
        if (criteria.hasSpecial) score += 15;

        // Bonus for having all 4 character classes
        if (criteria.hasLower && criteria.hasUpper && criteria.hasNumber && criteria.hasSpecial) {
            score += 10;
        }

        // Bonus for length >= 14 with good mix
        if (len >= 14 && criteria.hasNumber && criteria.hasSpecial) {
            score += 10;
        }

        // 3. Penalties & Deductions
        if (criteria.hasRepeated) {
            score -= 15;
        }
        if (criteria.hasSequential) {
            score -= 15;
        }
        // Only letters or only numbers penalty
        if ((criteria.hasLower || criteria.hasUpper) && !criteria.hasNumber && !criteria.hasSpecial) {
            score -= 15;
        }
        if (criteria.hasNumber && !criteria.hasLower && !criteria.hasUpper && !criteria.hasSpecial) {
            score -= 25;
        }

        // Short password hard cap
        if (len < 8) {
            score = Math.min(score, 30);
        }

        // Breached/Common password hard penalty
        if (criteria.isCommon) {
            score = Math.min(score, 15);
        }

        // Clamp between 0 and 100
        return Math.max(0, Math.min(100, Math.round(score)));
    }

    /**
     * Determines Strength Tier from Score and Criteria
     * @param {number} score
     * @param {object} criteria
     * @returns {object} tier object with label, class, color
     */
    function getStrengthTier(score, criteria) {
        if (criteria.isCommon) {
            return {
                label: "Very Weak (Compromised)",
                level: "very-weak",
                color: "#ef4444",
                percentage: Math.max(10, score)
            };
        }

        if (score === 0) {
            return {
                label: "Awaiting Input",
                level: "empty",
                color: "#64748b",
                percentage: 0
            };
        } else if (score < 30) {
            return {
                label: "Very Weak",
                level: "very-weak",
                color: "#ef4444",
                percentage: Math.max(15, score)
            };
        } else if (score < 55) {
            return {
                label: "Weak",
                level: "weak",
                color: "#f97316",
                percentage: score
            };
        } else if (score < 75) {
            return {
                label: "Medium",
                level: "medium",
                color: "#f59e0b",
                percentage: score
            };
        } else if (score < 90) {
            return {
                label: "Strong",
                level: "strong",
                color: "#38bdf8",
                percentage: score
            };
        } else {
            return {
                label: "Very Strong",
                level: "very-strong",
                color: "#10b981",
                percentage: score
            };
        }
    }

    /**
     * Generates actionable security recommendations based on analysis
     * @param {string} pwd
     * @param {object} criteria
     * @param {number} score
     * @returns {Array<string>} list of recommendations
     */
    function generateSuggestions(pwd, criteria, score) {
        const suggestions = [];

        if (!pwd || pwd.length === 0) {
            suggestions.push("Enter a password or generate one below to evaluate its cryptographic strength.");
            return suggestions;
        }

        // Critical alerts
        if (criteria.isCommon) {
            suggestions.push("CRITICAL: This password appears in publicly breached wordlists or common dictionary attacks. Attackers will crack it in milliseconds. Do not use it!");
        }

        // Length suggestions
        if (pwd.length < 8) {
            suggestions.push(`Increase password length: Currently ${pwd.length} characters. Minimum standard is 8 characters, but 12+ or 16+ is recommended for robust defense.`);
        } else if (pwd.length < 12) {
            suggestions.push(`Extend to 12+ or 16+ characters to exponentially increase the brute-force search space against modern GPU clusters.`);
        }

        // Character diversity suggestions
        if (!criteria.hasUpper) {
            suggestions.push("Add uppercase letters (A-Z) to expand character keyspace.");
        }
        if (!criteria.hasLower) {
            suggestions.push("Add lowercase letters (a-z) to prevent single-case dictionary matching.");
        }
        if (!criteria.hasNumber) {
            suggestions.push("Include numeric digits (0-9) to disrupt alphabetical word attacks.");
        }
        if (!criteria.hasSpecial) {
            suggestions.push("Include special symbols (e.g. !@#$%^&*()_+) to dramatically boost Shannon entropy.");
        }

        // Pattern suggestions
        if (criteria.hasRepeated) {
            suggestions.push("Avoid consecutive repeated characters (e.g. 'aaa', '111'), which drastically lower search entropy.");
        }
        if (criteria.hasSequential) {
            suggestions.push("Avoid predictable keyboard sequences (e.g. '123', 'abc', 'qwerty'). Password crackers test these first.");
        }

        // Positive feedback if high security
        if (score >= 85 && suggestions.length === 0) {
            suggestions.push("Excellent security posture! This password meets enterprise cryptographic standards.");
            suggestions.push("Pro-Tip: Ensure Multi-Factor Authentication (MFA) is enabled wherever this credential is used.");
            suggestions.push("Store this securely in a trusted password manager rather than browser autofill.");
        }

        return suggestions;
    }

    // ------------------------------------------------------------------------
    // UI Update Methods
    // ------------------------------------------------------------------------

    /**
     * Updates an individual checklist item UI
     * @param {HTMLElement} element
     * @param {boolean} isSatisfied
     * @param {string} validText
     * @param {string} invalidText
     */
    function updateChecklistItem(element, isSatisfied, validText, invalidText) {
        if (!element) return;
        const iconSpan = element.querySelector(".check-icon");
        const statusSpan = element.querySelector(".check-status");

        if (isSatisfied) {
            element.classList.remove("invalid");
            element.classList.add("valid");
            if (iconSpan) iconSpan.innerHTML = "&#10004;"; // Checkmark
            if (statusSpan) statusSpan.textContent = validText || "Satisfied";
        } else {
            element.classList.remove("valid");
            element.classList.add("invalid");
            if (iconSpan) iconSpan.innerHTML = "&#10008;"; // Cross
            if (statusSpan) statusSpan.textContent = invalidText || "Not satisfied";
        }
    }

    /**
     * Updates the SVG Score Circle gauge
     * @param {number} score
     * @param {string} color
     */
    function updateScoreGauge(score, color) {
        if (!scoreCircle || !scoreNumber) return;

        scoreNumber.textContent = score;
        scoreNumber.style.color = color;

        // Circumference of r=52 circle is 2 * PI * 52 ≈ 326.7
        const circumference = 326.7;
        const offset = circumference - (score / 100) * circumference;

        scoreCircle.style.strokeDasharray = `${circumference}`;
        scoreCircle.style.strokeDashoffset = `${offset}`;
        scoreCircle.style.stroke = color;
    }

    /**
     * Executes the full analysis and refreshes all UI components
     */
    function runAnalysis() {
        const pwd = passwordInput.value;
        const charCount = pwd.length;

        if (charCountValue) {
            charCountValue.textContent = `${charCount} char${charCount === 1 ? "" : "s"}`;
        }

        // Empty state handling
        if (!pwd || pwd.length === 0) {
            renderEmptyState();
            return;
        }

        // Perform evaluations
        const criteria = {
            isLengthValid: pwd.length >= 8,
            hasUpper: /[A-Z]/.test(pwd),
            hasLower: /[a-z]/.test(pwd),
            hasNumber: /[0-9]/.test(pwd),
            hasSpecial: SPECIAL_CHARS_REGEX.test(pwd),
            isCommon: isCommonPassword(pwd),
            hasRepeated: REPEATED_CHARS_REGEX.test(pwd),
            hasSequential: detectSequentialPattern(pwd)
        };

        const score = computeScore(pwd, criteria);
        const entropy = calculateEntropy(pwd, criteria);
        const crackTime = estimateCrackingTime(entropy, criteria.isCommon);
        const attackTimes = calculateAttackTimes(entropy, criteria.isCommon);
        const tier = getStrengthTier(score, criteria);
        const suggestions = generateSuggestions(pwd, criteria, score);

        // Update Strength Meter Bar
        if (strengthMeterBar) {
            strengthMeterBar.style.width = `${tier.percentage}%`;
            strengthMeterBar.style.backgroundColor = tier.color;
            strengthMeterBar.className = `meter-fill ${tier.level}`;
        }

        // Update Strength Badge
        if (strengthBadge) {
            strengthBadge.textContent = tier.label;
            strengthBadge.className = `strength-badge ${tier.level}`;
        }

        // Update Metric Counters
        if (entropyValue) entropyValue.textContent = `${entropy} bits`;
        if (crackTimeValue) crackTimeValue.textContent = crackTime;
        if (timeOnline) timeOnline.textContent = attackTimes.online;
        if (timeCpu) timeCpu.textContent = attackTimes.cpu;
        if (timeGpu) timeGpu.textContent = attackTimes.gpu;

        // Update Score Gauge
        updateScoreGauge(score, tier.color);

        // Update Checklist Items
        updateChecklistItem(
            checkLength,
            criteria.isLengthValid,
            `Satisfied (${pwd.length}/8+ chars)`,
            `Too short (${pwd.length}/8 chars min)`
        );
        updateChecklistItem(
            checkUpper,
            criteria.hasUpper,
            "Satisfied (Uppercase found)",
            "Missing uppercase (A-Z)"
        );
        updateChecklistItem(
            checkLower,
            criteria.hasLower,
            "Satisfied (Lowercase found)",
            "Missing lowercase (a-z)"
        );
        updateChecklistItem(
            checkNumber,
            criteria.hasNumber,
            "Satisfied (Digit found)",
            "Missing numbers (0-9)"
        );
        updateChecklistItem(
            checkSpecial,
            criteria.hasSpecial,
            "Satisfied (Symbol found)",
            "Missing special character (!@#$...)"
        );
        updateChecklistItem(
            checkCommon,
            !criteria.isCommon,
            "Satisfied (Not in breached list)",
            "FAIL: In common breached passwords!"
        );
        updateChecklistItem(
            checkPatterns,
            !criteria.hasRepeated && !criteria.hasSequential,
            "Satisfied (No obvious sequences)",
            criteria.hasRepeated ? "Pattern: Consecutive repeats" : "Pattern: Sequential keys"
        );

        // Update Alert Banner if compromised
        if (alertBanner && alertMessage) {
            if (criteria.isCommon) {
                alertBanner.classList.remove("hidden");
                alertMessage.textContent = "Warning: This password was identified in breached database wordlists. It offers virtually zero defense against credential stuffing!";
            } else if (criteria.hasRepeated || criteria.hasSequential) {
                alertBanner.classList.remove("hidden");
                alertMessage.textContent = "Notice: Predictable patterns or keyboard walks detected. Hackers use rule-based masks to crack these rapidly.";
            } else {
                alertBanner.classList.add("hidden");
            }
        }

        // Render Suggestions List
        renderSuggestions(suggestions);
    }

    /**
     * Renders clean initial / empty state
     */
    function renderEmptyState() {
        if (charCountValue) charCountValue.textContent = "0 chars";
        if (strengthBadge) {
            strengthBadge.textContent = "Awaiting Input";
            strengthBadge.className = "strength-badge empty";
        }
        if (strengthMeterBar) {
            strengthMeterBar.style.width = "0%";
            strengthMeterBar.style.backgroundColor = "#64748b";
            strengthMeterBar.className = "meter-fill empty";
        }
        if (entropyValue) entropyValue.textContent = "0 bits";
        if (crackTimeValue) crackTimeValue.textContent = "0 seconds";
        if (timeOnline) timeOnline.textContent = "0s";
        if (timeCpu) timeCpu.textContent = "0s";
        if (timeGpu) timeGpu.textContent = "0s";

        updateScoreGauge(0, "#64748b");

        // Reset checklist
        const allChecks = [
            checkLength, checkUpper, checkLower, checkNumber,
            checkSpecial, checkCommon, checkPatterns
        ];
        allChecks.forEach(item => {
            if (item) {
                item.classList.remove("valid", "invalid");
                const icon = item.querySelector(".check-icon");
                const status = item.querySelector(".check-status");
                if (icon) icon.innerHTML = "&#9675;"; // Neutral circle
                if (status) status.textContent = "Pending";
            }
        });

        if (alertBanner) alertBanner.classList.add("hidden");

        renderSuggestions([
            "Enter a password above or click 'Generate Password' to begin real-time cryptographic analysis.",
            "All password analysis is executed strictly in your local browser using client-side JavaScript. No data is stored or transmitted."
        ]);
    }

    /**
     * Populates the suggestions card
     * @param {Array<string>} suggestions
     */
    function renderSuggestions(suggestions) {
        if (!suggestionsList) return;
        suggestionsList.innerHTML = "";

        suggestions.forEach(item => {
            const li = document.createElement("li");
            li.className = "suggestion-item";

            const icon = document.createElement("span");
            icon.className = "suggestion-icon";
            icon.innerHTML = "&#8250;"; // Chevron

            const text = document.createElement("span");
            text.className = "suggestion-text";
            text.textContent = item;

            li.appendChild(icon);
            li.appendChild(text);
            suggestionsList.appendChild(li);
        });
    }

    // ------------------------------------------------------------------------
    // Cryptographically Secure Password Generator
    // ------------------------------------------------------------------------

    /**
     * Generates a CSPRNG-backed random password using window.crypto
     * @returns {string} secure password
     */
    function generateSecurePassword() {
        const length = parseInt(genLengthSlider ? genLengthSlider.value : 16, 10);
        const useUpper = genUpperCheck ? genUpperCheck.checked : true;
        const useLower = genLowerCheck ? genLowerCheck.checked : true;
        const useNumbers = genNumbersCheck ? genNumbersCheck.checked : true;
        const useSymbols = genSymbolsCheck ? genSymbolsCheck.checked : true;

        let charPool = "";
        const guaranteed = [];

        if (useLower) {
            const lowerSet = "abcdefghijklmnopqrstuvwxyz";
            charPool += lowerSet;
            guaranteed.push(getRandomChar(lowerSet));
        }
        if (useUpper) {
            const upperSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            charPool += upperSet;
            guaranteed.push(getRandomChar(upperSet));
        }
        if (useNumbers) {
            const numberSet = "0123456789";
            charPool += numberSet;
            guaranteed.push(getRandomChar(numberSet));
        }
        if (useSymbols) {
            const symbolSet = "!@#$%^&*()_+-=[]{};:,.<>?";
            charPool += symbolSet;
            guaranteed.push(getRandomChar(symbolSet));
        }

        if (charPool.length === 0) {
            showToast("Please select at least one character set!");
            return "";
        }

        const remainingLength = Math.max(0, length - guaranteed.length);
        const randomChars = [];

        // Cryptographically secure random values
        const randomValues = new Uint32Array(remainingLength);
        window.crypto.getRandomValues(randomValues);

        for (let i = 0; i < remainingLength; i++) {
            const index = randomValues[i] % charPool.length;
            randomChars.push(charPool[index]);
        }

        // Combine and shuffle guaranteed + random characters
        const combined = guaranteed.concat(randomChars);
        return secureShuffle(combined).join("");
    }

    /**
     * Securely picks a character from a string using window.crypto
     */
    function getRandomChar(str) {
        const arr = new Uint32Array(1);
        window.crypto.getRandomValues(arr);
        return str[arr[0] % str.length];
    }

    /**
     * Fisher-Yates shuffle using window.crypto CSPRNG
     */
    function secureShuffle(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const rand = new Uint32Array(1);
            window.crypto.getRandomValues(rand);
            const j = rand[0] % (i + 1);
            const temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
        return array;
    }

    // ------------------------------------------------------------------------
    // Event Listeners & Binding
    // ------------------------------------------------------------------------

    // Real-time analysis on typing
    if (passwordInput) {
        passwordInput.addEventListener("input", runAnalysis);

        // Analyze button explicit trigger with ripple/pulse feedback
        if (analyzeBtn) {
            analyzeBtn.addEventListener("click", () => {
                runAnalysis();
                analyzeBtn.classList.add("pulsing");
                setTimeout(() => analyzeBtn.classList.remove("pulsing"), 500);
                showToast("Analysis refreshed!");
            });
        }

        // Show/Hide Password Toggle
        if (toggleVisibilityBtn) {
            toggleVisibilityBtn.addEventListener("click", () => {
                const isPassword = passwordInput.type === "password";
                passwordInput.type = isPassword ? "text" : "password";
                toggleVisibilityBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");

                // Toggle eye icon
                if (toggleIcon) {
                    if (isPassword) {
                        // Eye with slash (Hide)
                        toggleIcon.innerHTML = `
                            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                            <line x1="1" y1="1" x2="23" y2="23"></line>
                        `;
                    } else {
                        // Eye (Show)
                        toggleIcon.innerHTML = `
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                            <circle cx="12" cy="12" r="3"></circle>
                        `;
                    }
                }
            });
        }

        // Clear Password Button
        if (clearBtn) {
            clearBtn.addEventListener("click", () => {
                passwordInput.value = "";
                runAnalysis();
                passwordInput.focus();
                showToast("Password input cleared.");
            });
        }

        // Reset Form & Analysis Button
        if (resetBtn) {
            resetBtn.addEventListener("click", () => {
                passwordInput.value = "";
                passwordInput.type = "password";
                if (toggleIcon) {
                    toggleIcon.innerHTML = `
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                    `;
                }
                renderEmptyState();
                showToast("Analyzer reset to initial state.");
            });
        }

        // Export Sanitized Security Audit Report (Zero-Knowledge)
        if (exportReportBtn) {
            exportReportBtn.addEventListener("click", () => {
                const pwd = passwordInput ? passwordInput.value : "";
                if (!pwd) {
                    showToast("Please enter or generate a password to export audit report.");
                    return;
                }

                const criteria = {
                    isLengthValid: pwd.length >= 8,
                    hasUpper: /[A-Z]/.test(pwd),
                    hasLower: /[a-z]/.test(pwd),
                    hasNumber: /[0-9]/.test(pwd),
                    hasSpecial: SPECIAL_CHARS_REGEX.test(pwd),
                    isCommon: isCommonPassword(pwd),
                    hasRepeated: REPEATED_CHARS_REGEX.test(pwd),
                    hasSequential: detectSequentialPattern(pwd)
                };

                const score = computeScore(pwd, criteria);
                const entropy = calculateEntropy(pwd, criteria);
                const tier = getStrengthTier(score, criteria);
                const crackTime = estimateCrackingTime(entropy, criteria.isCommon);
                const attackTimes = calculateAttackTimes(entropy, criteria.isCommon);
                const suggestions = generateSuggestions(pwd, criteria, score);

                // Zero-knowledge mask: never write cleartext password into the report file!
                const masked = pwd.length > 2
                    ? pwd[0] + "*".repeat(pwd.length - 2) + pwd[pwd.length - 1]
                    : "*".repeat(pwd.length);

                const timestamp = new Date().toISOString().replace("T", " ").substring(0, 19);

                const reportLines = [
                    "================================================================================",
                    "                       PASSWORD SECURITY AUDIT REPORT",
                    "                  Thiranex Cyber Security Internship Project",
                    "================================================================================",
                    `Audit Timestamp         : ${timestamp} UTC`,
                    `Audit Mode              : Zero-Knowledge Client-Side Heuristic Evaluation`,
                    `Credential Length       : ${pwd.length} characters`,
                    `Masked Credential       : ${masked} (Sanitized to prevent cleartext exposure)`,
                    "--------------------------------------------------------------------------------",
                    "SECURITY EVALUATION POSTURE:",
                    `  * Security Score      : ${score} / 100 Points`,
                    `  * Strength Tier       : ${tier.label.toUpperCase()}`,
                    `  * Shannon Entropy     : ${entropy} bits`,
                    `  * Primary Crack Time  : ${crackTime}`,
                    "--------------------------------------------------------------------------------",
                    "BRUTE-FORCE ATTACK SCENARIOS MATRIX:",
                    `  * Web Application (100 guesses/sec)       : ${attackTimes.online}`,
                    `  * Desktop CPU (50,000 guesses/sec)        : ${attackTimes.cpu}`,
                    `  * GPU Cluster Rig (10,000,000,000/sec)    : ${attackTimes.gpu}`,
                    "--------------------------------------------------------------------------------",
                    "SECURITY CRITERIA BREAKDOWN:",
                    `  [${criteria.isLengthValid ? "PASS" : "FAIL"}] Minimum 8 Characters (Length: ${pwd.length})`,
                    `  [${criteria.hasUpper ? "PASS" : "FAIL"}] Uppercase Letters (A-Z)`,
                    `  [${criteria.hasLower ? "PASS" : "FAIL"}] Lowercase Letters (a-z)`,
                    `  [${criteria.hasNumber ? "PASS" : "FAIL"}] Numeric Digits (0-9)`,
                    `  [${criteria.hasSpecial ? "PASS" : "FAIL"}] Special Symbols (!@#$%... )`,
                    `  [${!criteria.isCommon ? "PASS" : "FAIL"}] Breached Wordlist Immunity (SecLists check)`,
                    `  [${!criteria.hasRepeated && !criteria.hasSequential ? "PASS" : "FAIL"}] Predictable Sequence & Walk Check`,
                    "--------------------------------------------------------------------------------",
                    "ACTIONABLE REMEDIATION RECOMMENDATIONS:",
                    ...suggestions.map(s => `  * ${s}`),
                    "================================================================================",
                    "Project Attribution : Thiranex Cyber Security Internship",
                    "Privacy Guarantee   : This audit ran locally in-browser. Zero network transmission.",
                    "================================================================================"
                ];

                const blob = new Blob([reportLines.join("\r\n")], { type: "text/plain;charset=utf-8" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `Security_Audit_Report_${Date.now()}.txt`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                showToast("Security Audit Report downloaded successfully!");
            });
        }
    }

    // Generator Slider Listener
    if (genLengthSlider && genLengthDisplay) {
        genLengthSlider.addEventListener("input", (e) => {
            genLengthDisplay.textContent = e.target.value;
        });
    }

    // Generate Password Button
    if (generateBtn && generatedPasswordInput) {
        generateBtn.addEventListener("click", () => {
            const pwd = generateSecurePassword();
            if (pwd) {
                generatedPasswordInput.value = pwd;
                showToast("Cryptographically secure password generated!");
            }
        });
    }

    // Copy Generated Password
    if (copyGeneratedBtn && generatedPasswordInput) {
        copyGeneratedBtn.addEventListener("click", async () => {
            const pwd = generatedPasswordInput.value;
            if (!pwd) {
                showToast("Generate a password first!");
                return;
            }
            try {
                await navigator.clipboard.writeText(pwd);
                showToast("Password copied to clipboard securely!");
            } catch (err) {
                generatedPasswordInput.select();
                document.execCommand("copy");
                showToast("Password copied to clipboard!");
            }
        });
    }

    // Apply Generated Password to Main Analyzer
    if (applyGeneratedBtn && generatedPasswordInput && passwordInput) {
        applyGeneratedBtn.addEventListener("click", () => {
            const pwd = generatedPasswordInput.value;
            if (!pwd) {
                showToast("Generate a password first!");
                return;
            }
            passwordInput.value = pwd;
            runAnalysis();
            passwordInput.scrollIntoView({ behavior: "smooth", block: "center" });
            showToast("Password loaded into analyzer!");
        });
    }

    // Quick Test Presets
    quickTestButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const sample = btn.getAttribute("data-sample") || "";
            if (passwordInput) {
                passwordInput.value = sample;
                runAnalysis();
                passwordInput.scrollIntoView({ behavior: "smooth", block: "center" });
                showToast(`Loaded sample: "${btn.textContent.trim()}"`);
            }
        });
    });

    // Mobile Navbar Menu Toggle
    const mobileMenuBtn = document.getElementById("mobileMenuBtn");
    const navLinks = document.getElementById("navLinks");
    if (mobileMenuBtn && navLinks) {
        mobileMenuBtn.addEventListener("click", () => {
            navLinks.classList.toggle("open");
        });
        // Close menu on nav item click
        navLinks.querySelectorAll("a").forEach(link => {
            link.addEventListener("click", () => {
                navLinks.classList.remove("open");
            });
        });
    }

    // ------------------------------------------------------------------------
    // Privacy and Memory Safeguards
    // ------------------------------------------------------------------------
    // Explicitly guarantee no passwords leak via page unload or console
    window.addEventListener("beforeunload", () => {
        if (passwordInput) passwordInput.value = "";
        if (generatedPasswordInput) generatedPasswordInput.value = "";
    });

    // Initial render
    renderEmptyState();

})();

