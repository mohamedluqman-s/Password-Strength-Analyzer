// ============================================================================
// Password Strength Analyzer - Common & Compromised Passwords Database
// Thiranex Cyber Security Internship Project
// ============================================================================
// This database contains the most frequently used, cracked, and breached
// passwords worldwide (sourced from common wordlists like RockYou, SecLists,
// and annual threat intelligence reports).
// All matching is performed strictly offline in the client's browser.
// ============================================================================

const COMMON_PASSWORDS = [
    // Top 10 most common global passwords
    "123456",
    "password",
    "123456789",
    "12345",
    "12345678",
    "111111",
    "1234567",
    "123123",
    "qwerty",
    "admin",

    // Common numeric sequences & pins
    "000000",
    "666666",
    "123321",
    "654321",
    "7777777",
    "987654321",
    "1234567890",
    "0123456789",
    "112233",
    "121212",
    "11111111",
    "999999",
    "555555",
    "888888",
    "444444",
    "333333",
    "222222",
    "102030",
    "12344321",

    // Common words and dictionary entries
    "welcome",
    "login",
    "guest",
    "pass1234",
    "password123",
    "password1",
    "passcode",
    "changeme",
    "secret",
    "default",
    "master",
    "testing",
    "test1234",
    "access",
    "oracle",
    "root",
    "toor",
    "service",
    "support",
    "operator",
    "administrator",

    // Popular phrases, cultural & personal words
    "iloveyou",
    "princess",
    "sunshine",
    "dragon",
    "football",
    "baseball",
    "basketball",
    "soccer",
    "shadow",
    "superman",
    "batman",
    "starwars",
    "monkey",
    "killer",
    "trustno1",
    "letmein",
    "freedom",
    "mustang",
    "jordan",
    "harley",
    "charlie",
    "michelle",
    "jessica",
    "ashley",
    "bailey",
    "hockey",
    "matrix",
    "cookie",
    "cheese",
    "banana",
    "winner",
    "champion",
    "forever",
    "hello123",
    "internet",
    "computer",
    "system",
    "server",

    // Keyboard walk patterns
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "qazwsx",
    "wsxedc",
    "1q2w3e4r",
    "zaq12wsx",
    "1qaz2wsx",
    "qwertz",
    "azerty",
    "qweasdzxc",

    // Leetspeak variants of common words
    "p@ssw0rd",
    "p@ssword",
    "passw0rd",
    "p@55w0rd",
    "adm1n",
    "w3lc0me",
    "s3cr3t",
    "l0v3y0u",
    "qw3rty"
];

// Common sequential alphabet and number sequences for pattern detection
const KEYBOARD_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "01234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm"
];

// Export to window global for client-side zero-dependency script usage
if (typeof window !== "undefined") {
    window.COMMON_PASSWORDS = COMMON_PASSWORDS;
    window.KEYBOARD_PATTERNS = KEYBOARD_PATTERNS;
}

