/**
 * ============================================================================
 * AUTOMATED TEST SUITE: PASSWORD STRENGTH ANALYZER
 * Thiranex Cyber Security Internship Project
 * ============================================================================
 * Validates the 6 mandatory test cases:
 *  1. Empty input
 *  2. Short password
 *  3. Password containing only lowercase letters
 *  4. Password containing uppercase and lowercase letters
 *  5. Password containing numbers and special characters
 *  6. A commonly guessed password
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');

const window = {};
eval(fs.readFileSync(path.join(__dirname, '../js/common-passwords.js'), 'utf8'));

const SPECIAL_CHARS_REGEX = /[^a-zA-Z0-9]/;

function detectSequentialPattern(pwd) {
    if (!pwd || pwd.length < 3) return false;
    const lower = pwd.toLowerCase();
    const patterns = window.KEYBOARD_PATTERNS;

    for (const pattern of patterns) {
        for (let i = 0; i <= pattern.length - 3; i++) {
            const sub = pattern.slice(i, i + 3);
            const revSub = sub.split("").reverse().join("");
            if (lower.includes(sub) || lower.includes(revSub)) return true;
        }
    }
    for (let i = 0; i < lower.length - 2; i++) {
        const c1 = lower.charCodeAt(i);
        const c2 = lower.charCodeAt(i + 1);
        const c3 = lower.charCodeAt(i + 2);
        if (c2 === c1 + 1 && c3 === c2 + 1) return true;
        if (c2 === c1 - 1 && c3 === c2 - 1) return true;
    }
    return false;
}

function detectRepeatedPattern(pwd) {
    if (!pwd || pwd.length < 3) return false;
    if (/(.)\1{2,}/i.test(pwd)) return true;
    if (/(..+)\1{2,}/i.test(pwd)) return true;
    return false;
}

function normalizeLeetspeak(str) {
    return str.toLowerCase()
        .replace(/[@4]/g, "a")
        .replace(/[3]/g, "e")
        .replace(/[1!|]/g, "i")
        .replace(/[0]/g, "o")
        .replace(/[\$5]/g, "s")
        .replace(/[7]/g, "t");
}

function isCommonPassword(pwd) {
    if (!pwd) return false;
    const normalized = pwd.trim().toLowerCase();
    const commonList = window.COMMON_PASSWORDS || [];
    const rootWords = window.COMMON_ROOT_WORDS || [];

    if (commonList.includes(normalized)) return true;
    const leetNormalized = normalizeLeetspeak(normalized);
    if (commonList.includes(leetNormalized)) return true;

    if (normalized.length <= 16) {
        for (const root of rootWords) {
            if (normalized.includes(root) || leetNormalized.includes(root)) return true;
        }
        const strippedCore = normalized.replace(/^[^a-z]+|[^a-z]+$/g, "");
        if (strippedCore.length >= 4 && rootWords.includes(strippedCore)) return true;
    }
    return false;
}

function calculateEntropy(pwd, criteria) {
    if (!pwd || pwd.length === 0) return 0;
    let poolSize = 0;
    if (criteria.hasLower) poolSize += 26;
    if (criteria.hasUpper) poolSize += 26;
    if (criteria.hasNumber) poolSize += 10;
    if (criteria.hasSpecial) poolSize += 33;
    if (poolSize === 0) poolSize = 10;

    let entropy = pwd.length * (Math.log(poolSize) / Math.log(2));
    if (criteria.hasRepeated) entropy -= 10;
    if (criteria.hasSequential) entropy -= 10;
    if (criteria.isCommon) entropy = Math.min(entropy, 15);

    return Math.max(0, Math.round(entropy));
}

function computeScore(pwd, criteria) {
    if (!pwd || pwd.length === 0) return 0;
    let score = 0;
    const len = pwd.length;

    if (len < 6) {
        score += len * 2;
    } else if (len < 8) {
        score += 10 + (len - 5) * 3;
    } else if (len < 12) {
        score += 18 + (len - 8) * 3;
    } else if (len < 16) {
        score += 28 + (len - 12) * 3;
    } else {
        score += 40;
    }

    if (criteria.hasLower) score += 10;
    if (criteria.hasUpper) score += 10;
    if (criteria.hasNumber) score += 10;
    if (criteria.hasSpecial) score += 15;

    if (criteria.hasLower && criteria.hasUpper && criteria.hasNumber && criteria.hasSpecial) {
        score += 5;
    }
    if (len >= 16 && criteria.hasLower && criteria.hasUpper && criteria.hasNumber && criteria.hasSpecial) {
        score += 10;
    }

    if (criteria.hasRepeated) score -= 15;
    if (criteria.hasSequential) score -= 15;
    if ((criteria.hasLower || criteria.hasUpper) && !criteria.hasNumber && !criteria.hasSpecial) {
        score -= 15;
    }
    if (criteria.hasNumber && !criteria.hasLower && !criteria.hasUpper && !criteria.hasSpecial) {
        score -= 25;
    }

    if (len < 6) score = Math.min(score, 15);
    else if (len < 8) score = Math.min(score, 25);
    if (criteria.isCommon) score = Math.min(score, 15);

    return Math.max(0, Math.min(100, Math.round(score)));
}

function getStrengthTier(score, criteria, isEmpty) {
    if (isEmpty) return "Awaiting Input";
    if (criteria.isCommon) return "Very Weak (Compromised)";
    if (score <= 25) return "Very Weak";
    if (score <= 50) return "Weak";
    if (score <= 74) return "Medium";
    if (score <= 89) return "Strong";
    return "Very Strong";
}

function analyze(pwd) {
    const isEmpty = (!pwd || pwd.length === 0);
    const criteria = {
        isLengthValid: pwd.length >= 8,
        hasUpper: /[A-Z]/.test(pwd),
        hasLower: /[a-z]/.test(pwd),
        hasNumber: /[0-9]/.test(pwd),
        hasSpecial: SPECIAL_CHARS_REGEX.test(pwd),
        isCommon: isCommonPassword(pwd),
        hasRepeated: detectRepeatedPattern(pwd),
        hasSequential: detectSequentialPattern(pwd)
    };
    const score = computeScore(pwd, criteria);
    const entropy = calculateEntropy(pwd, criteria);
    const tier = getStrengthTier(score, criteria, isEmpty);
    return { criteria, score, entropy, tier };
}

// ----------------------------------------------------------------------------
// Test Runner
// ----------------------------------------------------------------------------
console.log("=================================================================");
console.log("  PASSWORD STRENGTH ANALYZER - AUTOMATED VERIFICATION SUITE");
console.log("  Thiranex Cyber Security Internship");
console.log("=================================================================\n");

const testCases = [
    {
        name: "Test Case 1: Empty input",
        input: "",
        validate: (res) => {
            if (res.score !== 0) throw new Error(`Expected score 0, got ${res.score}`);
            if (res.tier !== "Awaiting Input") throw new Error(`Expected 'Awaiting Input', got ${res.tier}`);
            return "Passed: Handled empty state gracefully with 0 score.";
        }
    },
    {
        name: "Test Case 2: Short password ('cat')",
        input: "cat",
        validate: (res) => {
            if (res.criteria.isLengthValid !== false) throw new Error("Length criteria should be false");
            if (res.score > 25) throw new Error(`Score should be capped <= 25 for short password, got ${res.score}`);
            if (res.tier !== "Very Weak") throw new Error(`Expected tier 'Very Weak', got ${res.tier}`);
            return `Passed: Identified as short (3 chars), tier: ${res.tier}, score: ${res.score}`;
        }
    },
    {
        name: "Test Case 3: Password containing only lowercase letters ('supercalifragilistic')",
        input: "supercalifragilistic",
        validate: (res) => {
            if (!res.criteria.hasLower) throw new Error("Lowercase should be true");
            if (res.criteria.hasUpper) throw new Error("Uppercase should be false");
            if (res.criteria.hasNumber) throw new Error("Number should be false");
            if (res.tier !== "Weak") throw new Error(`Expected tier 'Weak', got ${res.tier}`);
            return `Passed: Verified lowercase-only constraint, penalized single-pool keyspace. Score: ${res.score}, Tier: ${res.tier}`;
        }
    },
    {
        name: "Test Case 4: Password containing uppercase and lowercase letters ('CyberSecurityDefense')",
        input: "CyberSecurityDefense",
        validate: (res) => {
            if (!res.criteria.hasLower) throw new Error("Lowercase should be true");
            if (!res.criteria.hasUpper) throw new Error("Uppercase should be true");
            if (res.criteria.hasNumber) throw new Error("Number should be false");
            if (res.criteria.isLengthValid !== true) throw new Error("Length should be valid");
            return `Passed: Both case sets detected. Score: ${res.score}, Tier: ${res.tier}, Entropy: ${res.entropy} bits`;
        }
    },
    {
        name: "Test Case 5: Password containing numbers and special characters ('Thiranex#2026!Sec')",
        input: "Thiranex#2026!Sec",
        validate: (res) => {
            if (!res.criteria.hasUpper || !res.criteria.hasLower || !res.criteria.hasNumber || !res.criteria.hasSpecial) {
                throw new Error("All 4 character classes should be satisfied!");
            }
            if (res.score < 85) throw new Error(`Expected robust score >= 85, got ${res.score}`);
            return `Passed: Full character diversity satisfied. Score: ${res.score}, Tier: ${res.tier}, Entropy: ${res.entropy} bits`;
        }
    },
    {
        name: "Test Case 6: Commonly guessed password ('password123')",
        input: "password123",
        validate: (res) => {
            if (!res.criteria.isCommon) throw new Error("Should be flagged as common/breached password");
            if (res.score > 15) throw new Error(`Score should be hard-capped <= 15 for breached password, got ${res.score}`);
            if (res.tier !== "Very Weak (Compromised)") throw new Error(`Expected tier 'Very Weak (Compromised)', got ${res.tier}`);
            return `Passed: Correctly flagged as compromised/breached word. Score: ${res.score}, Tier: ${res.tier}`;
        }
    }
];

let passedCount = 0;
testCases.forEach((tc) => {
    try {
        const result = analyze(tc.input);
        const feedback = tc.validate(result);
        console.log(`[PASS] ${tc.name}`);
        console.log(`       Input: "${tc.input}"`);
        console.log(`       Detail: ${feedback}\n`);
        passedCount++;
    } catch (err) {
        console.error(`[FAIL] ${tc.name}`);
        console.error(`       Error: ${err.message}\n`);
    }
});

console.log("-----------------------------------------------------------------");
console.log(`TEST SUMMARY: ${passedCount} / ${testCases.length} Tests Passed Successfully.`);
console.log("-----------------------------------------------------------------");

if (passedCount === testCases.length) {
    console.log("STATUS: ALL CYBERSECURITY ENGINE TEST CRITERIA VALIDATED! [OK]");
    process.exit(0);
} else {
    process.exit(1);
}
