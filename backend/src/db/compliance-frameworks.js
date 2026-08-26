// Compliance framework reference catalogs — static lookup data served by
// routes/compliance.js so the frontend can offer a picker of control IDs to
// tag findings with (custom_vulns.compliance_tags). PCI-DSS only for v1;
// this file follows the same array-of-objects convention as vuln-templates.js
// (BUILTIN_TEMPLATES) so future frameworks can be added as sibling exports.

const PCI_DSS_CONTROLS = [
  { control_id: '2',     title: 'Apply secure configurations to all system components', description: 'Default credentials, unnecessary services/ports, and insecure default configurations.' },
  { control_id: '3',     title: 'Protect stored account data', description: 'Sensitive data exposure, cleartext storage of cardholder or authentication data.' },
  { control_id: '4',     title: 'Protect cardholder data with strong cryptography during transmission over open, public networks', description: 'Weak TLS configuration, missing encryption in transit, deprecated cipher suites.' },
  { control_id: '6.5.1', title: 'Injection flaws (SQL, OS command, LDAP, XPath, etc.)' },
  { control_id: '6.5.2', title: 'Buffer overflow' },
  { control_id: '6.5.3', title: 'Insecure cryptographic storage' },
  { control_id: '6.5.4', title: 'Insecure communications' },
  { control_id: '6.5.5', title: 'Improper error handling' },
  { control_id: '6.5.6', title: 'All "high risk" vulnerabilities identified in the vulnerability identification process' },
  { control_id: '6.5.7', title: 'Cross-site scripting (XSS)' },
  { control_id: '6.5.8', title: 'Improper access control (insecure direct object references, failure to restrict URL access, directory traversal)' },
  { control_id: '6.5.9', title: 'Cross-site request forgery (CSRF)' },
  { control_id: '6.5.10',title: 'Broken authentication and session management' },
  { control_id: '7',     title: 'Restrict access to system components and cardholder data by business need to know', description: 'Broken access control, privilege escalation, missing authorization checks.' },
  { control_id: '8',     title: 'Identify users and authenticate access to system components', description: 'Weak passwords, missing MFA, broken authentication.' },
];

module.exports = { PCI_DSS_CONTROLS };
