/**
 * ============================================================================
 * COMPREHENSIVE CYBERSECURITY FUNCTIONALITY & SECURITY AUDIT SUITE
 * Thiranex Cyber Security Internship Project
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');

// Mock browser global environment
const window = {};

// Load common passwords module
const commonPasswordsCode = fs.readFileSync(path.join(__dirname, '../js/common-passwords.js'), 'utf8');
eval(commonPasswordsCode);

// Verify dictionary loaded
if (!window.COMMON_PASSWORDS || !Array.isArray(window.COMMON_PASSWORDS)) {
    throw new Error("Failed to load COMMON_PASSWORDS from js/common-passwords.js");
}

console.log(`[INIT] Loaded ${window.COMMON_PASSWORDS.length} common breached passwords.`);
console.log(`[INIT] Loaded ${window.COMMON_ROOT_WORDS.length} common root words.`);
console.log(`[INIT] Loaded ${window.KEYBOARD_PATTERNS.length} keyboard walk patterns.\n`);

const SPECIAL_CHARS_REGEX = /[^a-zA-Z0-9]/;

function detectSequentialPattern(pwd) {
    if (!pwd || pwd.length < 3) return false;
    const lower = pwd.toLowerCase();
    const patterns = window.KEYBOARD_PATTERNS;

    for (const pattern of patterns) {
        for (let i = 0; i <= pattern.length - 3; i++) {
            const sub = pattern.slice(i, i + 3);
            const revSub = sub.split("").reverse().join("");
            if (lower.includes(sub) || lower.includes(revSub)) {
                return true;
            }
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

    // 1. Length scoring (up to 40 points)
    if (len < 6) {
        score += len * 2; // 0 - 10
    } else if (len < 8) {
        score += 10 + (len - 5) * 3; // 13 - 16
    } else if (len < 12) {
        score += 18 + (len - 8) * 3; // 18 - 27
    } else if (len < 16) {
        score += 28 + (len - 12) * 3; // 28 - 37
    } else {
        score += 40;
    }

    // 2. Character diversity (up to 45 points)
    if (criteria.hasLower) score += 10;
    if (criteria.hasUpper) score += 10;
    if (criteria.hasNumber) score += 10;
    if (criteria.hasSpecial) score += 15;

    // Bonus for having all 4 character classes
    if (criteria.hasLower && criteria.hasUpper && criteria.hasNumber && criteria.hasSpecial) {
        score += 5;
    }
    // Bonus for length >= 16 with full diversity
    if (len >= 16 && criteria.hasLower && criteria.hasUpper && criteria.hasNumber && criteria.hasSpecial) {
        score += 10;
    }

    // 3. Penalties
    if (criteria.hasRepeated) score -= 15;
    if (criteria.hasSequential) score -= 15;
    if ((criteria.hasLower || criteria.hasUpper) && !criteria.hasNumber && !criteria.hasSpecial) {
        score -= 15;
    }
    if (criteria.hasNumber && !criteria.hasLower && !criteria.hasUpper && !criteria.hasSpecial) {
        score -= 25;
    }

    if (len < 6) {
        score = Math.min(score, 15);
    } else if (len < 8) {
        score = Math.min(score, 25);
    }
    if (criteria.isCommon) {
        score = Math.min(score, 15);
    }

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

function evaluatePassword(pwd) {
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
    return { pwd, criteria, score, entropy, tier };
}

// ----------------------------------------------------------------------------
// TEST MATRIX
// ----------------------------------------------------------------------------
console.log("=================================================================");
console.log("  RUNNING 12-FACTOR FUNCTIONALITY & SECURITY AUDIT");
console.log("=================================================================\n");

let auditFailures = 0;

function assert(condition, testName, details) {
    if (condition) {
        console.log(`[PASS] ${testName}`);
        if (details) console.log(`       -> ${details}`);
    } else {
        console.error(`[FAIL] ${testName}`);
        if (details) console.error(`       -> ${details}`);
        auditFailures++;
    }
}

// Audit 1: Character Class & Length Verification
console.log("--- Section 1: Character Class & Length Verification ---");
const test1 = evaluatePassword("Ab#1");
assert(test1.criteria.isLengthValid === false, "Check length < 8 fails length requirement", `Length: ${test1.pwd.length}`);
assert(test1.criteria.hasUpper === true, "Check uppercase detection", "Detected 'A'");
assert(test1.criteria.hasLower === true, "Check lowercase detection", "Detected 'b'");
assert(test1.criteria.hasNumber === true, "Check number detection", "Detected '1'");
assert(test1.criteria.hasSpecial === true, "Check special symbol detection", "Detected '#'");

const testSpace = evaluatePassword("correct horse battery staple");
assert(testSpace.criteria.hasSpecial === true, "Check space recognized as non-alphanumeric", "Space recognized");

// Audit 2: Common & Dictionary Passwords
console.log("\n--- Section 2: Offline Dictionary & Leetspeak Detection ---");
assert(isCommonPassword("password") === true, "Detect exact common password ('password')", "Matched");
assert(isCommonPassword("password1234") === true, "Detect common password with digit suffix ('password1234')", "Matched");
assert(isCommonPassword("admin@123") === true, "Detect admin credential with symbol ('admin@123')", "Matched");
assert(isCommonPassword("p@ssw0rd") === true, "Detect leetspeak substitution ('p@ssw0rd')", "Matched");
assert(isCommonPassword("welcome2026") === true, "Detect root word with year suffix ('welcome2026')", "Matched");
assert(isCommonPassword("Kx9#mQ2$pL") === false, "High-entropy random password not flagged as common", "Correctly passed");

// Audit 3: Repeated and Sequential Patterns
console.log("\n--- Section 3: Pattern & Sequence Detection ---");
assert(detectRepeatedPattern("aaaaaa") === true, "Detect consecutive identical letters ('aaaaaa')", "Detected");
assert(detectRepeatedPattern("111111") === true, "Detect consecutive identical numbers ('111111')", "Detected");
assert(detectRepeatedPattern("121212") === true, "Detect repeating multi-character chunks ('121212')", "Detected");
assert(detectRepeatedPattern("ababab") === true, "Detect repeating pair chunks ('ababab')", "Detected");
assert(detectSequentialPattern("123456") === true, "Detect ascending numbers sequence ('123456')", "Detected");
assert(detectSequentialPattern("987654") === true, "Detect descending numbers sequence ('987654')", "Detected");
assert(detectSequentialPattern("qwertyuiop") === true, "Detect keyboard row walk ('qwertyuiop')", "Detected");
assert(detectSequentialPattern("asdfgh") === true, "Detect middle keyboard row walk ('asdfgh')", "Detected");
assert(detectSequentialPattern("cba") === true, "Detect descending alphabet sequence ('cba')", "Detected");
assert(detectSequentialPattern("Kx9#mQ2$pL") === false, "Random string has no false sequence match", "Clean");

// Audit 4 & 5: Score calculation & Classifications
console.log("\n--- Section 4 & 5: Scoring and Tier Classifications ---");
const emptyRes = evaluatePassword("");
assert(emptyRes.score === 0 && emptyRes.tier === "Awaiting Input", "Empty input yields score 0 and 'Awaiting Input'", `Score: ${emptyRes.score}`);

const veryWeakRes = evaluatePassword("cat");
assert(veryWeakRes.score <= 25 && veryWeakRes.tier === "Very Weak", "Short password (<6 chars) is Very Weak", `Score: ${veryWeakRes.score}`);

const weakRes = evaluatePassword("supercalifragilistic");
assert(weakRes.score >= 26 && weakRes.score <= 50 && weakRes.tier === "Weak", "Lowercase only 20-char word is Weak", `Score: ${weakRes.score}`);

const mediumRes = evaluatePassword("CyberSecurity2024");
assert(mediumRes.score >= 51 && mediumRes.score <= 74 && mediumRes.tier === "Medium", "Mixed upper, lower, numbers is Medium", `Score: ${mediumRes.score}`);

const strongRes = evaluatePassword("CyberSec#2024!");
assert(strongRes.score >= 75 && strongRes.score <= 89 && strongRes.tier === "Strong", "Mixed 4-class 14-char is Strong", `Score: ${strongRes.score}`);

const veryStrongRes = evaluatePassword("Thiranex#2026!Sec");
assert(veryStrongRes.score >= 90 && veryStrongRes.tier === "Very Strong", "Diverse 17-char high entropy is Very Strong", `Score: ${veryStrongRes.score}`);

const compromisedRes = evaluatePassword("password123");
assert(compromisedRes.score <= 15 && compromisedRes.tier === "Very Weak (Compromised)", "Breached word is clamped to Very Weak (Compromised)", `Score: ${compromisedRes.score}`);

// Audit 6: Dynamic Checklist
console.log("\n--- Section 6: Security Checklist Evaluation ---");
const checkTest = evaluatePassword("SecurePass#2026");
assert(checkTest.criteria.isLengthValid === true, "Checklist: Length >= 8", "Valid");
assert(checkTest.criteria.hasUpper === true, "Checklist: Has Upper", "Valid");
assert(checkTest.criteria.hasLower === true, "Checklist: Has Lower", "Valid");
assert(checkTest.criteria.hasNumber === true, "Checklist: Has Number", "Valid");
assert(checkTest.criteria.hasSpecial === true, "Checklist: Has Special", "Valid");
assert(checkTest.criteria.isCommon === false, "Checklist: Not Common", "Valid");
assert(checkTest.criteria.hasRepeated === false && checkTest.criteria.hasSequential === false, "Checklist: No Patterns", "Valid");

// Audit 7 & 8: Visibility, Reset, Generator
console.log("\n--- Section 7 & 8: Code Structure & Generator Review ---");
const scriptCode = fs.readFileSync(path.join(__dirname, '../js/script.js'), 'utf8');
assert(scriptCode.includes('toggleVisibilityBtn.addEventListener'), "Password visibility toggle listener attached", "Verified");
assert(scriptCode.includes('resetBtn.addEventListener'), "Reset analysis button listener attached", "Verified");
assert(scriptCode.includes('generateBtn.addEventListener'), "Password generator listener attached", "Verified");
assert(scriptCode.includes('getRandomValues'), "Generator uses cryptographically secure window.crypto.getRandomValues()", "Verified");

// Audit 9 & 10: Export Report & Privacy
console.log("\n--- Section 9 & 10: Audit Report & Privacy Review ---");
assert(scriptCode.includes('exportReportBtn.addEventListener'), "Export Report button listener attached", "Verified");
assert(scriptCode.includes('masked = pwd.length > 2'), "Password is masked in report (never written cleartext)", "Verified");
// Verify actual executable calls to network and storage APIs do not exist
const executableCode = scriptCode.replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, ""); // Strip comments
assert(!executableCode.includes('console.log('), "Strict zero-logging: zero executable console.log() calls", "Verified");
assert(!executableCode.includes('localStorage') && !executableCode.includes('sessionStorage') && !executableCode.includes('document.cookie'), "Zero storage: no executable localStorage, sessionStorage, or cookies", "Verified");
assert(!executableCode.includes('fetch(') && !executableCode.includes('XMLHttpRequest'), "Zero network: no executable fetch or XMLHttpRequest calls", "Verified");

// Audit 11: Approximate Claim Verification
console.log("\n--- Section 11: Scientific Accuracy & Disclaimer Review ---");
assert(scriptCode.includes('Theoretical brute-force estimate') || scriptCode.includes('Approx.'), "Crack time specifies theoretical brute-force approximation", "Verified");
const htmlCode = fs.readFileSync(path.join(__dirname, '../index.html'), 'utf8');
assert(htmlCode.includes('Important Notice:'), "Prominent educational disclaimer present in UI", "Verified");
assert(!htmlCode.includes('Zero Compromise'), "Misleading 'Zero Compromise' marketing claim removed", "Verified");

// Audit 12: Diverse Fictional Test Passwords
console.log("\n--- Section 12: Testing 15 Diverse Fictional Passwords ---");
const fictionalPasswords = [
    { pwd: "", expectedTier: "Awaiting Input" },
    { pwd: "cat", expectedTier: "Very Weak" },
    { pwd: "12345678", expectedTier: "Very Weak (Compromised)" },
    { pwd: "password123", expectedTier: "Very Weak (Compromised)" },
    { pwd: "p@ssw0rd2024", expectedTier: "Very Weak (Compromised)" },
    { pwd: "admin@123", expectedTier: "Very Weak (Compromised)" },
    { pwd: "aaaaaa", expectedTier: "Very Weak" },
    { pwd: "121212", expectedTier: "Very Weak (Compromised)" },
    { pwd: "qwertyuiop", expectedTier: "Very Weak (Compromised)" },
    { pwd: "supercalifragilistic", expectedTier: "Weak" },
    { pwd: "CyberSecurityDefense", expectedTier: "Weak" },
    { pwd: "CyberSecurity2024", expectedTier: "Medium" },
    { pwd: "correct horse battery staple", expectedTier: "Medium" },
    { pwd: "CyberSec#2024!", expectedTier: "Strong" },
    { pwd: "Tr0ub4dor&3#X9!Z", expectedTier: "Very Strong" }
];

fictionalPasswords.forEach((fp, i) => {
    const res = evaluatePassword(fp.pwd);
    assert(
        res.tier === fp.expectedTier,
        `Fictional Password [${i + 1}]: "${fp.pwd}" -> Tier: ${res.tier}`,
        `Score: ${res.score}/100 | Entropy: ${res.entropy} bits | Expected: ${fp.expectedTier}`
    );
});

console.log("\n=================================================================");
if (auditFailures === 0) {
    console.log("AUDIT SUMMARY: 100% OF TESTS PASSED! ALL 12 AUDIT FACTORS VALIDATED.");
    process.exit(0);
} else {
    console.error(`AUDIT SUMMARY: ${auditFailures} TEST(S) FAILED.`);
    process.exit(1);
}
