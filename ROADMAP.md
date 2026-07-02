# Flowdit — Roadmap

Tres capas: adopción, producto, monetización.

---

## Adopción — lo que hace que la gente lo pruebe

- [x] **Docker Compose todo-en-uno** — `docker compose --profile full up -d --build` levanta backend + PostgreSQL + Nginx (Chromium/Ghostscript incluidos para el export PDF). El `docker compose up` normal (sin profile) sigue siendo solo DB + Nginx para no romper el flujo de dev local con nodemon.
- [x] **Screenshots en el README** — capturas reales de dashboard, hallazgos, targets, WSTG, reportes y portal de cliente. Falta el GIF del flujo completo (proyecto → vuln → PDF), que sigue siendo una mejora menor pendiente.
- [x] **Sistema de íconos SVG** — reemplazo de los símbolos Unicode usados como íconos improvisados (✦ ⚙ ✓ etc.) por SVGs reales vendorizados de Lucide, sin CDN. Cubre sidenav, dashboard, hallazgos, targets, members, methodology, WSTG, PortSwigger, portal de cliente, tickets, settings y whiteboard. **Pendiente:** la toolbar de texto enriquecido de `export.html` (el editor de reportes), dejada afuera a propósito por ser la zona más densa/riesgosa de tocar.
- [ ] **Demo en vivo** — instancia pública en `demo.flowdit.space` con datos de ejemplo precargados. Sin demo, la mayoría no llega a instalarlo.

---

## Producto — lo que hace que la gente se quede

- [x] **Biblioteca de templates de vulnerabilidades** — catálogo de hallazgos comunes (SQLi, XSS, IDOR, SSRF, etc.) que se agregan con un clic, con descripción y remediación pre-escritas.
- [x] **Workflow de remediación** — vuln marcada como "remediated" → retest → "verified closed" con fecha, notas y responsable, con auditoría (`remediated_at`/`verified_at`/`verified_by`) separada del status legado de confirmación.
- [x] **IA multi-proveedor** — Groq y Anthropic seleccionables por proyecto (modelo también configurable), con tracking de gasto estimado por proyecto reutilizando los tokens que cada respuesta ya devuelve (sin costo extra de API).
- [x] **Aislamiento de datos entre proyectos** — auditoría de seguridad dedicada; se encontraron y corrigieron varios IDOR reales (acceso cruzado entre proyectos vía `target_id`/`ticket_id` no validados) antes de que esto fuera un problema en producción.
- [ ] **Importación de Nessus** — `.nessus` es el formato del scanner enterprise estándar. Sin esto, Flowdit queda fuera del flujo de trabajo de equipos corporativos.
- [ ] **Tests de integración** — sin tests nadie contribuye con confianza. 20-30 tests en endpoints críticos (auth, vulns, export) ya cambian la percepción del proyecto. Se pospone a propósito hasta tener la versión pública lista.
- [ ] **Importación de Nmap XML** — complementa Nessus para el inventario de puertos/servicios.
- [ ] **Notificaciones por email** — cuando el cliente responde un ticket o se crea un hallazgo crítico.
- [ ] **2FA** — segundo factor de autenticación para todos los usuarios. Expectativa básica de seguridad, independiente de organizations.
- [ ] **CVSS v4.0** — la industria está migrando.

---

## Monetización — lo que hace que pagues las cuentas

- [x] **Organizations — cuentas de empresa** — capa fundacional sobre `projects`: una organización agrupa proyectos con membresía propia (owner/admin/member); owners/admins ven y administran todos los proyectos de la empresa sin invitación manual proyecto por proyecto. Migración con backfill retrocompatible (cero regresión en accesos existentes), panel con resumen de hallazgos críticos/altos por proyecto integrado en `projects.html` filtrable por organización. Es el prerequisito real de SSO y de un panel de admin — ninguno de los dos tenía sentido antes sin este modelo de datos.
- [ ] **Hosting gestionado** — `app.flowdit.space` con plan free (1 proyecto) y plan Pro (~$30/mes ilimitado). El modelo más directo sin cambiar el core open source.
- [ ] **SSO / SAML** — las empresas no usan herramientas que no se integren con Okta, Azure AD o Google Workspace. Con Organizations ya en producción, esto ya es técnicamente viable de construir (se loguea a nivel organización, no a nivel proyecto suelto) — sigue siendo la pieza más grande que queda, pero ya no está bloqueada.
- [ ] **White-label** — consultoras medianas quieren el logo y dominio propio. Flowdit ya tiene soporte de logo por proyecto; el salto a white-label completo es relativamente pequeño.

---

## Orden de ataque

| # | Qué | Estado | Impacto | Esfuerzo |
|---|-----|--------|---------|----------|
| 1 | Docker Compose todo-en-uno | ✅ Hecho | Adopción masiva | Medio |
| 2 | Screenshots en README | ✅ Hecho | Conversión inmediata | Bajo |
| 3 | Templates de vulns | ✅ Hecho | Retención | Medio |
| 4 | Workflow de remediación | ✅ Hecho | Retención | Medio |
| 5 | IA multi-proveedor + tracking de gasto | ✅ Hecho | Retención | Medio |
| 6 | Aislamiento de datos entre proyectos | ✅ Hecho | Credibilidad de seguridad | Medio |
| 7 | Sistema de íconos SVG | ✅ Hecho (falta export.html) | Percepción profesional | Medio |
| 8 | Organizations (cuentas de empresa) | ✅ Hecho | Desbloquea mercado enterprise | Alto |
| 9 | Demo en vivo con seed data | Pendiente | Adopción masiva | Bajo |
| 10 | Importación Nessus | Pendiente | Mercado enterprise | Medio |
| 11 | 2FA | Pendiente | Credibilidad de seguridad | Bajo |
| 12 | Tests de integración | Pendiente (a propósito) | Credibilidad open source | Alto |
| 13 | Hosting gestionado | Pendiente | Primera monetización | Alto |
| 14 | SSO / SAML | Pendiente (ya desbloqueado) | Contratos enterprise | Alto |
