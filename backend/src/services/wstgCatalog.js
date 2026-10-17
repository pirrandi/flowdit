// Catálogo OWASP WSTG del lado del servidor: id de test → nombre, y prefijo →
// categoría. Lo usan el export DOCX y la proyección del portal en
// routes/wstg.js, que necesita devolver nombre y categoría sin depender del
// catálogo del frontend (frontend/js/data.js; mismos ids).

const WSTG_NAMES = {
  'WSTG-INFO-01':'Search Engine Discovery & Recon',
  'WSTG-INFO-02':'Fingerprint Web Server',
  'WSTG-INFO-03':'Review Webserver Metafiles for Information Leakage',
  'WSTG-INFO-04':'Enumerate Applications on Webserver',
  'WSTG-INFO-05':'Review Webpage Content for Information Leakage',
  'WSTG-INFO-06':'Identify Application Entry Points',
  'WSTG-INFO-07':'Map Execution Paths Through Application',
  'WSTG-INFO-08':'Fingerprint Web Application Framework',
  'WSTG-INFO-09':'Fingerprint Web Application',
  'WSTG-INFO-10':'Map Application Architecture',
  'WSTG-CONF-01':'Test Network Infrastructure Configuration',
  'WSTG-CONF-02':'Test Application Platform Configuration',
  'WSTG-CONF-03':'Test File Extensions Handling',
  'WSTG-CONF-04':'Review Old Backup and Unreferenced Files',
  'WSTG-CONF-05':'Enumerate Admin Interfaces',
  'WSTG-CONF-06':'Test HTTP Methods',
  'WSTG-CONF-07':'Test HTTP Strict Transport Security (HSTS)',
  'WSTG-CONF-08':'Test RIA Cross Domain Policy',
  'WSTG-CONF-10':'Test for Subdomain Takeover',
  'WSTG-CONF-11':'Test Cloud Storage',
  'WSTG-CONF-12':'Testing for Content Security Policy (CSP)',
  'WSTG-CONF-14':'Test HTTP Security Header Misconfigurations',
  'WSTG-IDNT-01':'Test Role Definitions',
  'WSTG-IDNT-02':'Test User Registration Process',
  'WSTG-IDNT-04':'Testing for Account Enumeration',
  'WSTG-IDNT-05':'Testing for Weak Username Policy',
  'WSTG-ATHN-01':'Testing for Credentials over Encrypted Channel',
  'WSTG-ATHN-02':'Testing for Default Credentials',
  'WSTG-ATHN-03':'Testing for Weak Lock Out Mechanism',
  'WSTG-ATHN-04':'Testing for Bypassing Authentication Schema',
  'WSTG-ATHN-07':'Testing for Weak Password Policy',
  'WSTG-ATHN-09':'Testing for Weak Password Change or Reset',
  'WSTG-ATHN-11':'Testing Multi-Factor Authentication (MFA)',
  'WSTG-ATHZ-01':'Testing Directory Traversal / File Include',
  'WSTG-ATHZ-02':'Testing for Bypassing Authorization Schema',
  'WSTG-ATHZ-04':'Testing for Insecure Direct Object References (IDOR)',
  'WSTG-ATHZ-05':'Testing for OAuth Weaknesses',
  'WSTG-SESS-01':'Testing for Session Management Schema',
  'WSTG-SESS-02':'Testing for Cookie Attributes',
  'WSTG-SESS-05':'Testing for Cross Site Request Forgery (CSRF)',
  'WSTG-SESS-10':'Testing JSON Web Tokens (JWT)',
  'WSTG-INPV-01':'Testing for Reflected XSS',
  'WSTG-INPV-02':'Testing for Stored XSS',
  'WSTG-INPV-05':'Testing for SQL Injection',
  'WSTG-INPV-07':'Testing for XML Injection (XXE)',
  'WSTG-INPV-12':'Testing for Command Injection',
  'WSTG-INPV-18':'Testing for Server-Side Template Injection (SSTI)',
  'WSTG-INPV-19':'Testing for Server-Side Request Forgery (SSRF)',
  'WSTG-INPV-20':'Testing for Mass Assignment',
  'WSTG-CLNT-01':'Testing for DOM-Based XSS',
  'WSTG-CLNT-04':'Testing for Client-Side URL Redirect',
  'WSTG-CLNT-07':'Test Cross Origin Resource Sharing (CORS)',
  'WSTG-CLNT-09':'Testing for Clickjacking',
  'WSTG-CLNT-10':'Testing WebSockets',
  'WSTG-CLNT-12':'Test Browser Storage',
  'WSTG-APIT-01':'API Reconnaissance',
  'WSTG-APIT-02':'API Broken Object Level Authorization (BOLA)',
  'WSTG-APIT-99':'Testing GraphQL',
};

// Prefijo del id de test → nombre de la categoría (mismas categorías que
// WSTG_DATA del frontend; los tests CLNT viven en la categoría "Client-Side").
const WSTG_CATEGORIES = {
  INFO: 'Information Gathering',
  CONF: 'Configuration & Deployment',
  IDNT: 'Identity Management',
  ATHN: 'Authentication Testing',
  ATHZ: 'Authorization Testing',
  SESS: 'Session Management',
  INPV: 'Input Validation',
  CLNT: 'Client-Side Testing',
  APIT: 'API Testing',
};

// Categoría de un test por el prefijo de su id ("WSTG-INPV-05" → INPV).
function wstgCategory(testId) {
  const m = /^WSTG-([A-Z]+)-\d+$/.exec(testId || '');
  return m ? WSTG_CATEGORIES[m[1]] || null : null;
}

module.exports = { WSTG_NAMES, WSTG_CATEGORIES, wstgCategory };
