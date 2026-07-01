# Flowdit — Roadmap

Tres capas: adopción, producto, monetización.

---

## Adopción — lo que hace que la gente lo pruebe

- [x] **Docker Compose todo-en-uno** — `docker compose --profile full up -d --build` levanta backend + PostgreSQL + Nginx (Chromium/Ghostscript incluidos para el export PDF). El `docker compose up` normal (sin profile) sigue siendo solo DB + Nginx para no romper el flujo de dev local con nodemon.
- [ ] **Screenshots y GIF en el README** — la gente decide si instalar o no en 10 segundos mirando capturas. Un GIF del flujo completo (proyecto → vuln → PDF) vale más que cualquier descripción.
- [ ] **Demo en vivo** — instancia pública en `demo.flowdit.space` con datos de ejemplo precargados. Sin demo, la mayoría no llega a instalarlo.

---

## Producto — lo que hace que la gente se quede

- [ ] **Biblioteca de templates de vulnerabilidades** — catálogo de hallazgos comunes (SQLi, XSS, IDOR, SSRF, etc.) que se agregan con un clic, con descripción y remediación pre-escritas. Ahorra 30-40% del tiempo de documentación.
- [ ] **Importación de Nessus** — `.nessus` es el formato del scanner enterprise estándar. Sin esto, Flowdit queda fuera del flujo de trabajo de equipos corporativos.
- [ ] **Workflow de remediación** — el ciclo no termina con el hallazgo. Falta: vuln marcada como "remediated" → retest → "verified closed" con fecha y responsable. Es lo que los clientes realmente necesitan rastrear.
- [ ] **Tests de integración** — sin tests nadie contribuye con confianza. 20-30 tests en endpoints críticos (auth, vulns, export) ya cambian la percepción del proyecto.
- [ ] **Importación de Nmap XML** — complementa Nessus para el inventario de puertos/servicios.
- [ ] **Notificaciones por email** — cuando el cliente responde un ticket o se crea un hallazgo crítico.
- [ ] **CVSS v4.0** — la industria está migrando.

---

## Monetización — lo que hace que pagues las cuentas

- [ ] **Hosting gestionado** — `app.flowdit.space` con plan free (1 proyecto) y plan Pro (~$30/mes ilimitado). El modelo más directo sin cambiar el core open source.
- [ ] **SSO / SAML** — las empresas no usan herramientas que no se integren con Okta, Azure AD o Google Workspace. Es el feature que desbloquea contratos corporativos y el candidato natural para el tier de pago.
- [ ] **White-label** — consultoras medianas quieren el logo y dominio propio. Flowdit ya tiene soporte de logo por proyecto; el salto a white-label completo es relativamente pequeño.

---

## Orden de ataque

| # | Qué | Impacto | Esfuerzo |
|---|-----|---------|----------|
| 1 | Docker Compose todo-en-uno | Adopción masiva | Medio |
| 2 | Screenshots / GIF en README | Conversión inmediata | Bajo |
| 3 | Demo en vivo con seed data | Adopción masiva | Bajo |
| 4 | Templates de vulns | Retención | Medio |
| 5 | Importación Nessus | Mercado enterprise | Medio |
| 6 | Workflow de remediación | Retención | Medio |
| 7 | Tests de integración | Credibilidad open source | Alto |
| 8 | Hosting gestionado | Primera monetización | Alto |
| 9 | SSO / SAML | Contratos enterprise | Alto |
