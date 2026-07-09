// Built-in vulnerability template library — shared by migrate.js (seeds it on
// deploy) and test/helpers.js (reseeds it after each TRUNCATE, since
// vuln_templates.created_by REFERENCES users(id), so TRUNCATE users CASCADE
// wipes this table too even though the built-in rows have created_by=NULL).

const BUILTIN_TEMPLATES = [
  { name: 'SQL Injection', category: 'Injection', severity: 'critical', cwe: 'CWE-89',
    description: 'The application constructs SQL queries using unsanitized user input, allowing an attacker to manipulate the query logic. This can lead to unauthorized data access, data modification, authentication bypass, or remote code execution depending on the database configuration.',
    remediation: 'Use parameterized queries or prepared statements for all database interactions. Apply the principle of least privilege to database accounts. Implement input validation and consider using an ORM that handles query parameterization automatically.' },

  { name: 'Blind SQL Injection', category: 'Injection', severity: 'high', cwe: 'CWE-89',
    description: 'The application is vulnerable to SQL injection but does not return query results or errors directly. An attacker can infer information through boolean-based or time-based techniques, enabling enumeration of the database schema and extracted data.',
    remediation: 'Use parameterized queries or prepared statements for all database interactions. Apply the principle of least privilege to database accounts and disable verbose error messages in production.' },

  { name: 'Reflected Cross-Site Scripting (XSS)', category: 'XSS', severity: 'medium', cwe: 'CWE-79',
    description: 'User-supplied input is reflected in the HTTP response without proper encoding, allowing an attacker to inject and execute arbitrary JavaScript in a victim browser. Exploitation typically requires the victim to visit a crafted URL, making it suitable for phishing attacks.',
    remediation: 'Encode all user-supplied output using context-appropriate encoding (HTML, JavaScript, URL). Implement a Content Security Policy (CSP) header. Validate and sanitize inputs server-side using an allowlist approach.' },

  { name: 'Stored Cross-Site Scripting (XSS)', category: 'XSS', severity: 'high', cwe: 'CWE-79',
    description: 'Malicious scripts supplied by an attacker are persistently stored in the application database and executed in the browser of every user who views the affected content. This enables session hijacking, credential theft, and defacement affecting all users without requiring social engineering.',
    remediation: 'Sanitize and encode all user-supplied content before storing and rendering it. Use a Content Security Policy (CSP) header and restrict the allowed HTML tags with a strict allowlist if rich content is required (e.g., DOMPurify).' },

  { name: 'DOM-Based Cross-Site Scripting (XSS)', category: 'XSS', severity: 'medium', cwe: 'CWE-79',
    description: 'The application writes user-controlled data to the DOM using unsafe sinks (innerHTML, document.write, eval) without sanitization. The payload is never sent to the server, bypassing server-side defenses, and executes entirely in the victim browser.',
    remediation: 'Use safe DOM APIs (textContent, setAttribute) instead of innerHTML. Avoid passing user-controlled data to eval or similar sinks. Implement a strict Content Security Policy to reduce exploitability.' },

  { name: 'Command Injection', category: 'Injection', severity: 'critical', cwe: 'CWE-78',
    description: 'The application passes user-controlled data to a system shell without adequate sanitization, allowing an attacker to execute arbitrary OS commands with the privileges of the web server process. Full system compromise is typically achievable.',
    remediation: 'Avoid invoking OS commands from application code wherever possible. If system calls are necessary, use language-native APIs instead of shell invocation and validate inputs against a strict allowlist. Apply the principle of least privilege to the web server process.' },

  { name: 'Path Traversal', category: 'Injection', severity: 'high', cwe: 'CWE-22',
    description: 'The application uses user-supplied input to construct file paths without proper validation, allowing an attacker to traverse the directory structure and read or write arbitrary files outside the intended directory. Sensitive configuration files, credentials, or source code may be exposed.',
    remediation: 'Resolve file paths server-side and verify they reside within the intended base directory using canonical path comparison. Avoid using user input to construct file paths; use indirect references mapped server-side. Apply the principle of least privilege to file system permissions.' },

  { name: 'Server-Side Request Forgery (SSRF)', category: 'SSRF', severity: 'high', cwe: 'CWE-918',
    description: 'The application fetches remote resources based on user-supplied URLs without sufficient validation, allowing an attacker to cause the server to make requests to internal services, cloud metadata endpoints, or other restricted resources. In cloud environments this commonly leads to credential exposure via the instance metadata service.',
    remediation: 'Validate and sanitize all user-supplied URLs against an allowlist of permitted schemes, hosts, and ports. Block requests to private IP ranges (RFC 1918), loopback, and metadata endpoints. Disable HTTP redirects or validate the final destination after resolution.' },

  { name: 'XML External Entity Injection (XXE)', category: 'XXE', severity: 'high', cwe: 'CWE-611',
    description: 'The application parses XML input with external entity processing enabled, allowing an attacker to read arbitrary files from the server, perform SSRF, or cause denial of service. XXE is particularly impactful when combined with SSRF to reach internal services.',
    remediation: 'Disable external entity and DTD processing in the XML parser. Use a simpler data format such as JSON where XML is not strictly required. Keep XML parser libraries up to date.' },

  { name: 'Insecure Direct Object Reference (IDOR)', category: 'Access Control', severity: 'high', cwe: 'CWE-639',
    description: 'The application exposes internal object identifiers in requests and does not verify that the authenticated user is authorized to access the referenced object. An attacker can enumerate or modify these identifiers to access or manipulate other users data.',
    remediation: 'Enforce authorization checks on every resource access server-side, validating that the authenticated user owns or has permission to access the requested object. Avoid using predictable sequential identifiers; prefer UUIDs. Implement centralized authorization logic.' },

  { name: 'Broken Access Control', category: 'Access Control', severity: 'high', cwe: 'CWE-284',
    description: 'The application does not consistently enforce authorization restrictions, allowing users to access functionality or data beyond their intended privilege level. This may include accessing admin panels, other users records, or privileged API endpoints by manipulating requests.',
    remediation: 'Implement server-side authorization checks on every request using a centralized access control mechanism. Deny by default and explicitly grant permissions. Regularly audit access control logic and test with lower-privileged accounts.' },

  { name: 'Cross-Site Request Forgery (CSRF)', category: 'Auth', severity: 'medium', cwe: 'CWE-352',
    description: 'The application performs state-changing actions without verifying that the request originates from the legitimate user. An attacker can craft a malicious page that causes a victim browser to send authenticated requests to the application, performing actions such as account changes or transactions on their behalf.',
    remediation: 'Implement anti-CSRF tokens (synchronizer token pattern) for all state-changing requests. Use the SameSite=Strict or SameSite=Lax cookie attribute. Verify the Origin and Referer headers for sensitive operations.' },

  { name: 'Open Redirect', category: 'Redirect', severity: 'medium', cwe: 'CWE-601',
    description: 'The application accepts a user-controlled URL parameter and redirects the user to it without validation, allowing attackers to craft legitimate-looking URLs that redirect victims to malicious sites. This is commonly used in phishing campaigns to bypass URL reputation checks.',
    remediation: 'Validate redirect destinations against an allowlist of permitted URLs or domains. Avoid using user-supplied input in redirect parameters. If dynamic redirects are necessary, use indirect references mapped server-side.' },

  { name: 'JWT Algorithm Confusion', category: 'Auth', severity: 'high', cwe: 'CWE-347',
    description: 'The application accepts JWTs signed with the "none" algorithm or allows the client to specify the signing algorithm, enabling an attacker to forge arbitrary tokens without a valid signature. This leads to authentication bypass and privilege escalation.',
    remediation: 'Explicitly specify the expected signing algorithm server-side and reject tokens using unexpected algorithms, especially "none". Use a well-maintained JWT library and keep it updated. Rotate signing keys regularly.' },

  { name: 'Broken Authentication', category: 'Auth', severity: 'high', cwe: 'CWE-287',
    description: 'The application implements authentication mechanisms incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users identities temporarily or permanently.',
    remediation: 'Implement multi-factor authentication. Use strong adaptive hashing for passwords (bcrypt, argon2). Invalidate session tokens on logout and after a configurable timeout. Implement account lockout and rate limiting on authentication endpoints.' },

  { name: 'Sensitive Data Exposure', category: 'Info Disclosure', severity: 'medium', cwe: 'CWE-200',
    description: 'The application transmits, stores, or displays sensitive information (credentials, PII, session tokens, internal paths) in an insufficiently protected manner. An attacker with network access or access to logs can retrieve this information.',
    remediation: 'Identify and classify sensitive data. Encrypt sensitive data at rest and in transit using strong, current standards. Minimize data exposure by returning only what is necessary. Remove debugging information, stack traces, and internal paths from production responses.' },

  { name: 'CORS Misconfiguration', category: 'Misconfiguration', severity: 'medium', cwe: 'CWE-346',
    description: 'The application Cross-Origin Resource Sharing policy is overly permissive, reflecting arbitrary Origin headers or allowing credentials from untrusted origins. An attacker can make cross-origin requests from a malicious site and read the response, effectively bypassing same-origin protections.',
    remediation: 'Define an explicit allowlist of trusted origins and validate against it server-side. Never reflect the incoming Origin header directly. Set Access-Control-Allow-Credentials: true only for explicitly trusted, non-wildcard origins.' },

  { name: 'Missing Security Headers', category: 'Misconfiguration', severity: 'low', cwe: null,
    description: 'The application does not set critical security headers, leaving users exposed to clickjacking, MIME-type sniffing, cross-site scripting, and information disclosure attacks. While often low severity individually, missing headers represent a defense-in-depth gap.',
    remediation: 'Configure the following headers: Content-Security-Policy, X-Frame-Options (or frame-ancestors CSP directive), X-Content-Type-Options: nosniff, Strict-Transport-Security, Referrer-Policy, and Permissions-Policy. Use securityheaders.com to validate the configuration.' },

  { name: 'Clickjacking', category: 'Misconfiguration', severity: 'low', cwe: 'CWE-1021',
    description: 'The application does not prevent its pages from being loaded in an iframe, allowing an attacker to overlay a transparent iframe on a legitimate-looking page to trick users into clicking interface elements they cannot see, performing unintended actions.',
    remediation: 'Set the X-Frame-Options header to DENY or SAMEORIGIN, or use the Content-Security-Policy frame-ancestors directive. Prefer the CSP approach as X-Frame-Options is deprecated in newer specifications.' },

  { name: 'Directory Listing Enabled', category: 'Info Disclosure', severity: 'low', cwe: 'CWE-548',
    description: 'The web server is configured to display directory contents when no index file is present, exposing the file structure and potentially sensitive files such as configuration files, backups, or source code to unauthenticated users.',
    remediation: 'Disable directory listing in the web server configuration (e.g., Options -Indexes in Apache, autoindex off in Nginx). Ensure all directories that should not be publicly accessible have proper access controls applied.' },

  { name: 'Default Credentials', category: 'Auth', severity: 'critical', cwe: 'CWE-1392',
    description: 'The application or a component (admin panel, database, network device) is accessible using publicly known default credentials. An attacker can immediately gain unauthorized access without any exploitation.',
    remediation: 'Change all default credentials during initial setup and enforce this as part of the deployment process. Implement a credential policy that requires strong, unique passwords. Consider removing or disabling default accounts entirely where not required.' },

  { name: 'Account Enumeration', category: 'Info Disclosure', severity: 'low', cwe: 'CWE-204',
    description: 'The application returns different responses for valid and invalid usernames, allowing an attacker to enumerate registered users. This information can be leveraged for targeted attacks or credential stuffing campaigns.',
    remediation: 'Return identical error messages and status codes for invalid username and invalid password scenarios. Normalize response times for authentication failures using constant-time comparison. Implement rate limiting and account lockout policies.' },

  { name: 'Subdomain Takeover', category: 'Misconfiguration', severity: 'high', cwe: 'CWE-284',
    description: 'A DNS entry for a subdomain points to an external service (GitHub Pages, Heroku, S3) that has been deprovisioned or is not claimed. An attacker can claim the service and serve arbitrary content under the organization domain, enabling phishing, cookie theft, and CSP bypass.',
    remediation: 'Audit DNS records regularly and remove CNAME entries pointing to deprovisioned services. Implement a process to remove DNS entries before deprovisioning cloud services. Monitor subdomains using automated tools.' },

  { name: 'Host Header Injection', category: 'Injection', severity: 'medium', cwe: 'CWE-644',
    description: 'The application uses the HTTP Host header to construct URLs (password reset links, redirects) without validating it against an allowlist. An attacker can manipulate the Host header to poison the password reset flow, cause cache poisoning, or bypass security controls.',
    remediation: 'Validate the Host header against an allowlist of legitimate domain names. Configure the web server to reject requests with unexpected Host headers. Use absolute URLs constructed from server-side configuration, not from request headers.' },

  { name: 'Insecure Deserialization', category: 'Injection', severity: 'high', cwe: 'CWE-502',
    description: 'The application deserializes user-controlled data without integrity checks or type validation, allowing an attacker to manipulate serialized objects to achieve remote code execution, privilege escalation, or denial of service.',
    remediation: 'Avoid deserializing data from untrusted sources. If deserialization is necessary, use safe serialization formats (JSON over native formats) and implement integrity checks with digital signatures. Apply the principle of least privilege to processes that perform deserialization.' },

  { name: 'HTTP Request Smuggling', category: 'Injection', severity: 'high', cwe: 'CWE-444',
    description: 'The application is vulnerable to HTTP request smuggling due to discrepancies in how front-end and back-end servers parse Transfer-Encoding and Content-Length headers. An attacker can poison the request queue to bypass security controls, hijack user sessions, or perform cache poisoning.',
    remediation: 'Ensure consistent HTTP specification compliance across all servers in the chain. Configure front-end servers to use HTTP/2 for back-end connections where possible. Normalize ambiguous requests at the edge and reject those with conflicting framing headers.' },

  { name: 'Weak Password Policy', category: 'Auth', severity: 'medium', cwe: 'CWE-521',
    description: 'The application does not enforce a minimum password strength requirement, allowing users to set trivially guessable passwords. This increases the risk of successful brute-force, credential stuffing, and password spray attacks.',
    remediation: 'Enforce a minimum password length of at least 12 characters. Check passwords against known breached password lists (e.g., HaveIBeenPwned API). Implement multi-factor authentication and account lockout after repeated failed attempts.' },

  { name: 'SSL/TLS Misconfiguration', category: 'Crypto', severity: 'medium', cwe: 'CWE-326',
    description: 'The application supports outdated TLS versions (TLS 1.0/1.1), weak cipher suites, or has other TLS configuration weaknesses such as missing HSTS or improper certificate validation. This exposes communications to downgrade attacks and interception.',
    remediation: 'Enforce TLS 1.2 as the minimum supported version with TLS 1.3 preferred. Disable weak and export cipher suites. Implement HTTP Strict Transport Security (HSTS) with a minimum max-age of one year. Use certificates from a trusted CA.' },

  { name: 'GraphQL Introspection Enabled', category: 'Misconfiguration', severity: 'info', cwe: null,
    description: 'The GraphQL endpoint has introspection enabled in production, exposing the complete API schema including all types, queries, mutations, and arguments. This significantly aids attackers in mapping the attack surface and crafting targeted queries.',
    remediation: 'Disable introspection in production environments. If introspection is required for internal tooling, restrict access by IP allowlist or authentication. Consider applying query depth and complexity limits as an additional defense.' },

  { name: 'GraphQL Batching Attack', category: 'Misconfiguration', severity: 'medium', cwe: null,
    description: 'The GraphQL endpoint allows query batching without rate limiting, enabling an attacker to send hundreds of queries in a single HTTP request to perform brute-force attacks, bypass rate limiting, or amplify server load.',
    remediation: 'Implement query complexity and depth limits. Apply per-operation rate limiting rather than per-request. Consider disabling or restricting query batching in production if not required by legitimate clients.' },

  { name: 'Unrestricted File Upload', category: 'Upload', severity: 'high', cwe: 'CWE-434',
    description: 'The application accepts file uploads without adequately validating the file type, content, or name. An attacker can upload malicious files such as web shells, scripts, or polyglots that may be executed server-side or served to other users, leading to remote code execution or stored XSS.',
    remediation: 'Validate file type using server-side content inspection (magic bytes), not only the file extension or MIME type provided by the client. Store uploaded files outside the web root and serve them through a dedicated endpoint. Rename files on upload and restrict execution permissions on the upload directory.' },

  { name: 'Server-Side Template Injection (SSTI)', category: 'Injection', severity: 'critical', cwe: 'CWE-94',
    description: 'User-supplied input is embedded in a server-side template and evaluated by the template engine (Jinja2, Twig, Freemarker, Pebble, etc.) without sanitization. An attacker can inject template directives to read server files, enumerate environment variables, and achieve remote code execution.',
    remediation: 'Never pass user-controlled data directly into template strings. Use sandboxed template rendering where available and treat all user input as data, not as template code. Consider switching to logic-less templates (Mustache) for contexts where user input influences output.' },

  { name: 'Mass Assignment', category: 'Access Control', severity: 'high', cwe: 'CWE-915',
    description: 'The application binds HTTP request parameters directly to internal model objects without filtering, allowing an attacker to set fields that should not be user-controlled (e.g., is_admin, role, balance). This commonly leads to privilege escalation or data integrity issues.',
    remediation: 'Use explicit allowlists of permitted fields when binding request input to model objects. Never deserialize request bodies directly into database models. Apply strong input validation and use DTOs (Data Transfer Objects) to separate external input from internal state.' },

  { name: 'NoSQL Injection', category: 'Injection', severity: 'high', cwe: 'CWE-943',
    description: 'The application constructs NoSQL queries (MongoDB, Redis, CouchDB) using unsanitized user input, allowing an attacker to manipulate query operators to bypass authentication, extract data, or modify documents. Common attack vectors include injecting MongoDB operators such as $where, $gt, or $regex.',
    remediation: 'Validate and sanitize all user-supplied input before using it in database queries. Use typed query builders or ODMs that prevent operator injection. Reject input containing unexpected object structures or NoSQL operator keys.' },

  { name: 'Missing Rate Limiting', category: 'Misconfiguration', severity: 'medium', cwe: 'CWE-770',
    description: 'Critical endpoints (login, password reset, OTP verification, registration) do not implement rate limiting or account lockout, allowing an attacker to perform unlimited brute-force or enumeration attempts. This significantly reduces the effective security of any password or OTP-based control.',
    remediation: 'Implement rate limiting on all authentication and sensitive endpoints. Apply exponential backoff or temporary lockout after a configurable number of failed attempts. Use CAPTCHA for high-risk flows and alert on anomalous request volumes.' },

  { name: 'Insecure Password Reset', category: 'Auth', severity: 'high', cwe: 'CWE-640',
    description: 'The password reset mechanism contains one or more weaknesses: tokens are predictable, do not expire, can be reused after use, or are transmitted insecurely. An attacker can exploit these flaws to take over arbitrary user accounts without knowing the original password.',
    remediation: 'Generate password reset tokens using a cryptographically secure random source with at least 128 bits of entropy. Invalidate tokens after a single use and set a short expiry (15-30 minutes). Transmit tokens only over HTTPS and never include them in URLs that may be logged.' },

  { name: 'Session Fixation', category: 'Auth', severity: 'medium', cwe: 'CWE-384',
    description: 'The application does not regenerate the session identifier after a successful authentication event, allowing an attacker who has obtained a pre-authentication session ID (via XSS, network interception, or explicit fixation) to hijack the authenticated session.',
    remediation: 'Regenerate the session identifier upon every authentication event (login, privilege change). Invalidate all pre-authentication session tokens. Ensure session IDs are not accepted from URL parameters.' },

  { name: 'OAuth Misconfiguration', category: 'Auth', severity: 'high', cwe: 'CWE-601',
    description: 'The OAuth 2.0 implementation contains weaknesses such as an open redirect_uri, missing or predictable state parameter, or authorization code reuse. An attacker can exploit these to steal authorization codes, hijack OAuth flows, and gain unauthorized access to user accounts.',
    remediation: 'Register and validate exact redirect_uri values; reject partial or wildcard matches. Enforce the state parameter as a CSRF token with adequate entropy. Bind authorization codes to the client and ensure single use. Use PKCE for public clients.' },

  { name: 'Hardcoded Secrets', category: 'Info Disclosure', severity: 'high', cwe: 'CWE-798',
    description: 'Sensitive credentials, API keys, cryptographic secrets, or connection strings are hardcoded in application source code, configuration files, or JavaScript bundles. These secrets are accessible to anyone with access to the codebase, build artifacts, or browser developer tools.',
    remediation: 'Remove all hardcoded secrets from source code immediately and rotate the exposed credentials. Use environment variables or a secrets management solution (Vault, AWS Secrets Manager) to inject secrets at runtime. Add secret scanning to the CI/CD pipeline to prevent future occurrences.' },

  { name: 'Verbose Error Messages', category: 'Info Disclosure', severity: 'low', cwe: 'CWE-209',
    description: 'The application returns detailed error messages, stack traces, or debug information to end users in production. This reveals internal paths, library versions, database schema details, and implementation logic that significantly aids an attacker in profiling the target.',
    remediation: 'Configure the application to return generic error messages to users while logging detailed errors server-side. Disable debug mode and developer toolbars in production. Implement a centralized error handler that sanitizes output before returning it in HTTP responses.' },

  { name: 'Prototype Pollution', category: 'Injection', severity: 'high', cwe: 'CWE-1321',
    description: 'The application merges or clones user-supplied objects without sanitizing __proto__, constructor, or prototype keys, allowing an attacker to inject properties into the global Object prototype. This can lead to denial of service, property injection, or remote code execution in Node.js environments.',
    remediation: 'Use Object.create(null) for objects used as maps. Sanitize user input to reject keys such as __proto__ and constructor. Use safe merge libraries (e.g., lodash >= 4.17.21 with the merge fix applied) or implement recursive key validation before merging objects.' },

  { name: 'Race Condition', category: 'Logic', severity: 'high', cwe: 'CWE-362',
    description: 'The application performs multi-step operations (balance checks, coupon redemptions, vote counts, file writes) without adequate locking or atomicity, allowing an attacker to send concurrent requests that exploit the time-of-check to time-of-use (TOCTOU) window to obtain resources or permissions beyond what is authorized.',
    remediation: 'Use database-level atomic operations and transactions with appropriate isolation levels. Implement pessimistic locking for critical state changes. Avoid check-then-act patterns; use atomic compare-and-swap operations where possible. Apply per-user rate limiting on sensitive operations.' },

  { name: 'Business Logic Bypass', category: 'Logic', severity: 'high', cwe: 'CWE-840',
    description: 'The application enforces business rules (pricing, step sequences, quantity limits, discount application) only client-side or in a way that can be circumvented by manipulating request parameters. An attacker can bypass intended workflows to gain unauthorized discounts, skip verification steps, or manipulate financial values.',
    remediation: 'Enforce all business rules server-side and treat all client-supplied values as untrusted. Validate state transitions server-side and ensure multi-step flows cannot be completed out of order. Implement server-side recalculation of prices and quantities rather than accepting them from the client.' },

  { name: 'Exposed Admin Interface', category: 'Misconfiguration', severity: 'high', cwe: 'CWE-284',
    description: 'Administrative interfaces (/admin, /manager, phpMyAdmin, Kibana, Grafana, Jenkins) are exposed to the public internet without IP restriction or strong authentication. An attacker can attempt brute-force attacks or exploit default credentials to gain full administrative control.',
    remediation: 'Restrict access to administrative interfaces by IP allowlist or VPN. Enforce multi-factor authentication for all admin accounts. Remove or disable admin interfaces that are not required in production. Monitor for unauthorized access attempts.' },

  { name: 'LDAP Injection', category: 'Injection', severity: 'high', cwe: 'CWE-90',
    description: 'The application constructs LDAP queries using unsanitized user input, allowing an attacker to manipulate the query to bypass authentication, extract directory information, or enumerate users and groups from the LDAP directory.',
    remediation: 'Escape all user-supplied input before incorporating it into LDAP queries using a library-provided escaping function. Use parameterized LDAP APIs where available. Apply the principle of least privilege to the LDAP service account used by the application.' },

  { name: 'HTTP Method Override', category: 'Misconfiguration', severity: 'medium', cwe: 'CWE-650',
    description: 'The application or an intermediate proxy honors method override headers (X-HTTP-Method-Override, X-Method-Override, _method parameter), allowing an attacker to perform PUT, DELETE, or PATCH requests from a context where only GET and POST are permitted, bypassing firewall rules or access controls based on HTTP method.',
    remediation: 'Disable method override headers if not required by the application. If method override is necessary, validate that the requester has permission to use the overridden method and ensure the authorization logic uses the effective method, not the transport method.' },

  { name: 'WebSocket Injection', category: 'Injection', severity: 'high', cwe: 'CWE-79',
    description: 'The application processes WebSocket messages without adequate input validation or authorization checks, allowing an attacker to inject malicious payloads, perform cross-site WebSocket hijacking (CSWSH), or access WebSocket functionality without proper authentication.',
    remediation: 'Validate and sanitize all data received over WebSocket connections. Implement authentication for WebSocket handshakes (validate the Origin header and require session tokens). Apply the same authorization controls to WebSocket messages as to equivalent HTTP requests.' },

  { name: 'Two-Factor Authentication Bypass', category: 'Auth', severity: 'high', cwe: 'CWE-287',
    description: 'The two-factor authentication implementation can be bypassed through brute force of short OTP codes, reuse of previously valid codes, manipulation of the authentication flow to skip the 2FA step, or exploitation of backup code weaknesses.',
    remediation: 'Implement rate limiting and lockout on OTP verification attempts. Invalidate OTP codes immediately after use and enforce short expiry windows (30-60 seconds for TOTP). Ensure the 2FA verification step cannot be skipped by manipulating session state or request parameters.' },

  { name: 'Regular Expression Denial of Service (ReDoS)', category: 'Injection', severity: 'medium', cwe: 'CWE-1333',
    description: 'The application uses regular expressions with catastrophic backtracking properties on user-controlled input, allowing an attacker to supply crafted strings that cause the regex engine to consume excessive CPU time, leading to denial of service.',
    remediation: 'Audit regular expressions for catastrophic backtracking using tools such as safe-regex or rxxr2. Replace vulnerable patterns with linear-time alternatives. Implement input length limits before regex evaluation and consider using a regex timeout or a non-backtracking engine.' },

  { name: 'Insecure Direct Object Reference via Parameter Tampering', category: 'Access Control', severity: 'high', cwe: 'CWE-639',
    description: 'The application exposes sequential or predictable identifiers in hidden form fields, cookies, or request parameters that control which resource is accessed or modified. An attacker can tamper with these values to access or manipulate other users resources without authorization.',
    remediation: 'Validate server-side that the authenticated user is authorized to access or modify the referenced resource on every request. Use non-predictable identifiers (UUIDs) and implement a centralized authorization check rather than relying on the secrecy of parameter values.' },
];

async function seedTemplates(db) {
  let added = 0;
  for (const t of BUILTIN_TEMPLATES) {
    const { rowCount } = await db.query(
      `INSERT INTO vuln_templates (name, category, severity, cwe, description, remediation, is_builtin)
       SELECT $1,$2,$3,$4,$5,$6,TRUE
       WHERE NOT EXISTS (SELECT 1 FROM vuln_templates WHERE name=$1::varchar AND is_builtin=TRUE)`,
      [t.name, t.category, t.severity, t.cwe || null, t.description, t.remediation]
    );
    added += rowCount;
  }
  if (added > 0) console.log(`  ✦ Seeded ${added} built-in vulnerability templates`);
}


module.exports = { BUILTIN_TEMPLATES, seedTemplates };
