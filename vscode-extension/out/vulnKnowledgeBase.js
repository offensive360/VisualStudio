"use strict";
/**
 * Offensive360 SAST - Embedded Vulnerability Knowledge Base
 *
 * Provides offline fix guidance, descriptions, and remediation hints
 * for common vulnerability types detected by O360 SAST scanner.
 *
 * No external dependencies, no network calls, no AI.
 * Works with on-premises and air-gapped deployments.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.lookupVuln = lookupVuln;
exports.getFixHint = getFixHint;
exports.getFullHelp = getFullHelp;
exports.filterReferences = filterReferences;
exports.checkTokenExpiry = checkTokenExpiry;
exports.getAuthErrorMessage = getAuthErrorMessage;
const KB_DATA = {
    'sql_injection': {
        title: 'SQL Injection',
        shortDescription: 'User input is concatenated into SQL queries without sanitization, allowing attackers to manipulate database operations.',
        riskExplanation: 'Critical — can lead to full database compromise, data theft, authentication bypass, and data modification.',
        howToFix: 'Use parameterized queries (prepared statements) instead of string concatenation. Use ORM frameworks. Validate and sanitize all user input before use in queries.',
        codePatternBad: 'var query = "SELECT * FROM users WHERE id = " + userId;',
        codePatternGood: 'var query = "SELECT * FROM users WHERE id = @id"; cmd.Parameters.AddWithValue("@id", userId);',
        cwes: ['CWE-89']
    },
    'sql_injection_via_string_concatenation': {
        title: 'SQL Injection via String Concatenation',
        shortDescription: 'SQL query is built by concatenating user-controlled strings, enabling SQL injection attacks.',
        riskExplanation: 'Critical — attacker can read, modify, or delete any data in the database and potentially execute system commands.',
        howToFix: 'Replace string concatenation with parameterized queries. Use an ORM or query builder. Never embed user input directly into SQL strings.',
        codePatternBad: '"SELECT * FROM users WHERE name = \'" + userName + "\'"',
        codePatternGood: 'db.query("SELECT * FROM users WHERE name = ?", [userName])',
        cwes: ['CWE-89']
    },
    'cross_site_scripting': {
        title: 'Cross-Site Scripting (XSS)',
        shortDescription: 'User input is rendered in HTML without proper encoding, allowing attackers to inject malicious scripts.',
        riskExplanation: 'High — can steal session cookies, redirect users to malicious sites, deface pages, or perform actions on behalf of users.',
        howToFix: 'Encode all user input before rendering in HTML. Use framework-provided auto-escaping. Implement Content Security Policy (CSP) headers.',
        codePatternBad: 'element.innerHTML = userInput;',
        codePatternGood: 'element.textContent = userInput; // or use DOMPurify.sanitize(userInput)',
        cwes: ['CWE-79']
    },
    'os_command_injection': {
        title: 'OS Command Injection',
        shortDescription: 'User input is passed to system shell commands without sanitization, allowing arbitrary command execution.',
        riskExplanation: 'Critical — attacker can execute any operating system command, potentially taking full control of the server.',
        howToFix: 'Avoid calling shell commands with user input. Use language-native APIs instead of shell commands. If shell execution is unavoidable, use allowlists and strict input validation.',
        codePatternBad: 'exec("ping " + userInput)',
        codePatternGood: 'execFile("ping", ["-c", "1", validatedHost]) // Use execFile with argument array',
        cwes: ['CWE-78']
    },
    'hard_coded_password': {
        title: 'Hard-coded Password',
        shortDescription: 'Credentials or secrets are embedded directly in source code rather than stored securely.',
        riskExplanation: 'High — anyone with access to the code (including version control history) can extract the credentials.',
        howToFix: 'Store secrets in environment variables, secret managers (e.g., Azure Key Vault, AWS Secrets Manager), or encrypted configuration files. Never commit credentials to source control.',
        codePatternBad: 'const password = "admin123";',
        codePatternGood: 'const password = process.env.DB_PASSWORD; // Read from environment variable',
        cwes: ['CWE-798']
    },
    'hard_coded_credentials': {
        title: 'Hard-coded Credentials',
        shortDescription: 'Authentication credentials are embedded directly in source code.',
        riskExplanation: 'High — credentials in code can be extracted by anyone with repository access, enabling unauthorized system access.',
        howToFix: 'Use environment variables, secret managers, or secure vaults for credential storage. Rotate any credentials found in code immediately.',
        codePatternBad: 'connection.login("admin", "P@ssw0rd");',
        codePatternGood: 'connection.login(env.DB_USER, env.DB_PASS); // Use environment variables',
        cwes: ['CWE-798']
    },
    'path_traversal': {
        title: 'Path Traversal',
        shortDescription: 'User input is used to construct file paths without validation, allowing access to files outside the intended directory.',
        riskExplanation: 'High — attacker can read sensitive files (e.g., /etc/passwd, configuration files) or overwrite critical system files.',
        howToFix: 'Validate and sanitize file paths. Use allowlists for permitted directories. Resolve paths and verify they stay within the intended base directory.',
        codePatternBad: 'readFile("/uploads/" + userFilename)',
        codePatternGood: 'const safePath = path.resolve(baseDir, userFilename); if (!safePath.startsWith(baseDir)) throw new Error("Invalid path");',
        cwes: ['CWE-22']
    },
    'ssrf': {
        title: 'Server-Side Request Forgery (SSRF)',
        shortDescription: 'The application makes HTTP requests to URLs controlled by user input, allowing access to internal services.',
        riskExplanation: 'High — attacker can scan internal networks, access cloud metadata endpoints, or interact with internal services.',
        howToFix: 'Validate and allowlist permitted URLs/domains. Block requests to internal/private IP ranges. Use a URL parser to enforce scheme and host restrictions.',
        codePatternBad: 'fetch(userProvidedUrl)',
        codePatternGood: 'if (isAllowedDomain(url)) { fetch(url); } // Validate against allowlist',
        cwes: ['CWE-918']
    },
    'xxe': {
        title: 'XML External Entity (XXE)',
        shortDescription: 'XML parser processes external entity references, potentially exposing local files or causing denial of service.',
        riskExplanation: 'High — can lead to local file disclosure, SSRF, denial of service, or remote code execution.',
        howToFix: 'Disable external entity processing in XML parsers. Use JSON instead of XML where possible. Configure parser to disallow DTDs.',
        codePatternBad: 'parser.parse(xmlInput) // Default settings allow XXE',
        codePatternGood: 'parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
        cwes: ['CWE-611']
    },
    'insecure_deserialization': {
        title: 'Insecure Deserialization',
        shortDescription: 'Untrusted data is deserialized without validation, potentially allowing remote code execution.',
        riskExplanation: 'Critical — can lead to remote code execution, privilege escalation, or denial of service.',
        howToFix: 'Avoid deserializing untrusted data. Use safe serialization formats (JSON). Implement integrity checks (signatures). Use allowlists for permitted types.',
        codePatternBad: 'ObjectInputStream.readObject(untrustedStream)',
        codePatternGood: 'JSON.parse(data) // Use safe formats; validate schema before processing',
        cwes: ['CWE-502']
    },
    'open_redirect': {
        title: 'Open Redirect',
        shortDescription: 'Application redirects users to URLs controlled by user input without validation.',
        riskExplanation: 'Medium — can be used in phishing attacks by redirecting users to malicious sites that appear legitimate.',
        howToFix: 'Validate redirect URLs against an allowlist of permitted domains. Use relative URLs instead of absolute. Never use user input directly as redirect target.',
        codePatternBad: 'res.redirect(req.query.returnUrl)',
        codePatternGood: 'if (isLocalUrl(req.query.returnUrl)) { res.redirect(req.query.returnUrl); }',
        cwes: ['CWE-601']
    },
    'csrf': {
        title: 'Cross-Site Request Forgery (CSRF)',
        shortDescription: 'Application does not verify that requests originate from the legitimate user interface.',
        riskExplanation: 'Medium — attacker can trick users into performing unintended actions (fund transfers, password changes) on authenticated sessions.',
        howToFix: 'Implement anti-CSRF tokens in forms. Use SameSite cookie attribute. Verify Origin/Referer headers for state-changing requests.',
        codePatternBad: 'app.post("/transfer", handleTransfer) // No CSRF protection',
        codePatternGood: 'app.post("/transfer", csrfProtection, handleTransfer) // CSRF middleware',
        cwes: ['CWE-352']
    },
    'unrestricted_file_upload': {
        title: 'Unrestricted File Upload',
        shortDescription: 'Application accepts file uploads without validating file type, size, or content.',
        riskExplanation: 'High — attacker can upload malicious scripts (web shells) to gain remote code execution on the server.',
        howToFix: 'Validate file extensions and MIME types against an allowlist. Scan uploaded files for malware. Store uploads outside the web root. Rename files on upload.',
        codePatternBad: 'app.post("/upload", (req, res) => { saveFile(req.file); })',
        codePatternGood: 'if (ALLOWED_TYPES.includes(file.mimetype) && file.size < MAX_SIZE) { saveFile(file); }',
        cwes: ['CWE-434']
    },
    'information_disclosure': {
        title: 'Information Disclosure',
        shortDescription: 'Application exposes sensitive information such as stack traces, internal paths, or configuration details.',
        riskExplanation: 'Medium — leaked information helps attackers map the application and plan targeted attacks.',
        howToFix: 'Implement custom error pages that hide internal details. Remove debug information in production. Avoid exposing stack traces, version numbers, or internal paths.',
        codePatternBad: 'catch (e) { res.status(500).send(e.stack); }',
        codePatternGood: 'catch (e) { logger.error(e); res.status(500).send("An internal error occurred."); }',
        cwes: ['CWE-200']
    },
    'missing_authentication': {
        title: 'Missing Authentication',
        shortDescription: 'Critical functionality is accessible without requiring user authentication.',
        riskExplanation: 'Critical — unauthorized users can access sensitive operations or data without proving their identity.',
        howToFix: 'Require authentication for all sensitive endpoints. Implement middleware that verifies auth tokens/sessions. Apply the principle of least privilege.',
        codePatternBad: 'app.get("/admin/users", listAllUsers) // No auth check',
        codePatternGood: 'app.get("/admin/users", requireAuth, requireAdmin, listAllUsers)',
        cwes: ['CWE-306']
    },
    'weak_cryptography': {
        title: 'Weak Cryptographic Algorithm',
        shortDescription: 'Application uses outdated or weak cryptographic algorithms that can be broken by attackers.',
        riskExplanation: 'High — weak encryption can be broken, exposing sensitive data. Weak hashing allows password recovery.',
        howToFix: 'Use modern algorithms: AES-256 for encryption, SHA-256+ for hashing, bcrypt/scrypt/argon2 for passwords. Avoid MD5, SHA1, DES, RC4.',
        codePatternBad: 'crypto.createHash("md5").update(password)',
        codePatternGood: 'await bcrypt.hash(password, 12) // Use bcrypt for passwords',
        cwes: ['CWE-327']
    },
    'buffer_overflow': {
        title: 'Buffer Overflow',
        shortDescription: 'Data is written beyond the bounds of allocated memory, potentially allowing code execution.',
        riskExplanation: 'Critical — can lead to remote code execution, crashes, or privilege escalation.',
        howToFix: 'Use bounds-checking functions. Validate input lengths. Use safe string handling functions. Enable compiler protections (ASLR, stack canaries).',
        codePatternBad: 'strcpy(buffer, userInput); // No bounds checking',
        codePatternGood: 'strncpy(buffer, userInput, sizeof(buffer) - 1); buffer[sizeof(buffer) - 1] = \'\\0\';',
        cwes: ['CWE-120']
    },
    'race_condition': {
        title: 'Race Condition',
        shortDescription: 'Application behavior depends on timing of concurrent operations, leading to inconsistent state.',
        riskExplanation: 'Medium — can lead to privilege escalation, data corruption, or security bypasses in concurrent environments.',
        howToFix: 'Use proper synchronization (locks, mutexes, semaphores). Implement atomic operations. Use database transactions for concurrent data access.',
        codePatternBad: 'if (balance >= amount) { balance -= amount; } // TOCTOU race',
        codePatternGood: 'await db.transaction(async (tx) => { /* atomic check and update */ });',
        cwes: ['CWE-362']
    },
    'null_pointer_dereference': {
        title: 'Null Pointer Dereference',
        shortDescription: 'Application accesses a null or undefined reference, causing crashes or unexpected behavior.',
        riskExplanation: 'Medium — can cause application crashes (denial of service) or bypass security checks that depend on the null value.',
        howToFix: 'Check for null/undefined before accessing object properties. Use optional chaining (?.) or null-safe operators. Implement proper error handling.',
        codePatternBad: 'user.getName() // user could be null',
        codePatternGood: 'if (user != null) { user.getName(); } // or user?.getName()',
        cwes: ['CWE-476']
    },
    'improper_input_validation': {
        title: 'Improper Input Validation',
        shortDescription: 'Application does not properly validate user input, allowing malformed or malicious data.',
        riskExplanation: 'High — root cause of many vulnerabilities including injection attacks, buffer overflows, and logic errors.',
        howToFix: 'Validate all input on the server side. Use allowlists (not blocklists). Validate type, length, format, and range. Reject unexpected input.',
        codePatternBad: 'processOrder(req.body) // No validation',
        codePatternGood: 'const validated = schema.validate(req.body); if (validated.error) throw validated.error;',
        cwes: ['CWE-20']
    },
    'integer_overflow': {
        title: 'Integer Overflow',
        shortDescription: 'Arithmetic operation produces a value outside the representable range, wrapping around unexpectedly.',
        riskExplanation: 'High — can lead to buffer overflows, incorrect calculations, or security bypasses when used in size/length checks.',
        howToFix: 'Check for overflow before arithmetic operations. Use safe math libraries. Use appropriate data types for expected value ranges.',
        codePatternBad: 'int total = price * quantity; // Can overflow',
        codePatternGood: 'if (quantity > 0 && price > Integer.MAX_VALUE / quantity) throw new OverflowException();',
        cwes: ['CWE-190']
    }
};
// Domains to filter from references
const COMPETITOR_DOMAINS = [];
/**
 * Look up a vulnerability type in the knowledge base.
 * Does fuzzy matching by normalizing the type string.
 */
function lookupVuln(vulnType) {
    if (!vulnType) {
        return undefined;
    }
    // Normalize: lowercase, replace spaces/hyphens with underscore, strip non-alphanumeric
    const key = vulnType.toLowerCase()
        .replace(/[\s\-]+/g, '_')
        .replace(/[^a-z0-9_]/g, '');
    // Direct match
    if (KB_DATA[key]) {
        return KB_DATA[key];
    }
    // Partial match: check if any KB key is contained in the input or vice versa
    for (const [kbKey, entry] of Object.entries(KB_DATA)) {
        if (key.includes(kbKey) || kbKey.includes(key)) {
            return entry;
        }
        // Also match on title (normalized)
        const titleKey = entry.title.toLowerCase().replace(/[\s\-]+/g, '_').replace(/[^a-z0-9_]/g, '');
        if (key.includes(titleKey) || titleKey.includes(key)) {
            return entry;
        }
    }
    return undefined;
}
/**
 * Get a short fix hint for a vulnerability type (1 line).
 */
function getFixHint(vulnType) {
    const entry = lookupVuln(vulnType);
    if (!entry) {
        return '';
    }
    // Return first sentence of howToFix
    const firstSentence = entry.howToFix.split('.')[0];
    return firstSentence ? firstSentence + '.' : entry.howToFix;
}
/**
 * Get full help text for a vulnerability (multi-line, formatted for display).
 */
function getFullHelp(vulnType) {
    const entry = lookupVuln(vulnType);
    if (!entry) {
        return `No fix guidance available for "${vulnType}". Check O360 dashboard for more details.`;
    }
    return [
        `## ${entry.title}`,
        '',
        `**Description:** ${entry.shortDescription}`,
        '',
        `**Risk:** ${entry.riskExplanation}`,
        '',
        `**How to Fix:** ${entry.howToFix}`,
        '',
        `**Vulnerable Pattern:**`,
        '```',
        entry.codePatternBad,
        '```',
        '',
        `**Secure Pattern:**`,
        '```',
        entry.codePatternGood,
        '```',
        '',
        `**Reference:** ${entry.cwes.join(', ')}`,
    ].join('\n');
}
/**
 * Filter out competitor URLs from a references string.
 * References may be pipe-delimited or comma-delimited.
 */
function filterReferences(references) {
    if (!references) {
        return [];
    }
    const urls = references.split(/[|,]/).map(u => u.trim()).filter(u => u.startsWith('http'));
    return urls.filter(url => {
        const lower = url.toLowerCase();
        return !COMPETITOR_DOMAINS.some(domain => lower.includes(domain));
    });
}
/**
 * Decode JWT token and check expiry.
 * Returns { valid, expired, expiresAt, remainingDays }.
 */
function checkTokenExpiry(token) {
    try {
        if (!token || !token.startsWith('ey')) {
            return { valid: false, expired: false, expiresAt: null, remainingDays: 0 };
        }
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, expired: false, expiresAt: null, remainingDays: 0 };
        }
        // Decode payload (base64url)
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
        const exp = payload.exp;
        if (!exp) {
            // No expiry claim — token doesn't expire
            return { valid: true, expired: false, expiresAt: null, remainingDays: Infinity };
        }
        const expiresAt = new Date(exp * 1000);
        const now = new Date();
        const expired = expiresAt <= now;
        const remainingMs = expiresAt.getTime() - now.getTime();
        const remainingDays = Math.floor(remainingMs / (1000 * 60 * 60 * 24));
        return { valid: !expired, expired, expiresAt, remainingDays };
    }
    catch {
        return { valid: false, expired: false, expiresAt: null, remainingDays: 0 };
    }
}
/**
 * Get a user-friendly error message based on the error type.
 */
function getAuthErrorMessage(statusCode, isNetworkError) {
    if (isNetworkError) {
        return 'Cannot reach the O360 server. Check your network connection and verify the server URL in settings.';
    }
    switch (statusCode) {
        case 401:
            return 'Your API token has expired or is invalid. Please ask your O360 administrator to generate a new token from Dashboard > Settings > Tokens.';
        case 403:
            return 'Your API token does not have sufficient permissions for this operation. Contact your O360 administrator.';
        case 404:
            return 'The O360 server endpoint was not found. Verify the server URL in your settings.';
        case 500:
            return 'The O360 server encountered an internal error. Please try again later or contact your administrator.';
        case 413:
            return 'The project is too large for the server upload limit. Try scanning a subfolder or contact your admin to increase the limit.';
        default:
            return `Unexpected server response (${statusCode || 'unknown'}). Please check your settings and try again.`;
    }
}
//# sourceMappingURL=vulnKnowledgeBase.js.map