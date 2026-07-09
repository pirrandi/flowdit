# Flowdit — Roadmap

Tres capas: adopción, producto, monetización.

---

## Adopción — lo que hace que la gente lo pruebe

- [x] **Docker Compose todo-en-uno** — `docker compose --profile full up -d --build` levanta backend + PostgreSQL + Nginx (Chromium/Ghostscript incluidos para el export PDF). El `docker compose up` normal (sin profile) sigue siendo solo DB + Nginx para no romper el flujo de dev local con nodemon.
- [x] **Screenshots en el README** — capturas reales de dashboard, hallazgos, targets, WSTG, reportes y portal de cliente. Falta el GIF del flujo completo (proyecto → vuln → PDF), que sigue siendo una mejora menor pendiente.
- [x] **Sistema de íconos SVG** — reemplazo de los símbolos Unicode usados como íconos improvisados (✦ ⚙ ✓ etc.) por SVGs reales vendorizados de Lucide, sin CDN. Cubre sidenav, dashboard, hallazgos, targets, members, methodology, WSTG, PortSwigger, portal de cliente, tickets, settings y whiteboard. **Pendiente:** la toolbar de texto enriquecido de `export.html` (el editor de reportes), dejada afuera a propósito por ser la zona más densa/riesgosa de tocar.
- [ ] **Demo en vivo** — instancia pública en `demo.flowdit.space` con datos de ejemplo precargados. Sin demo, la mayoría no llega a instalarlo. **Listo:** login único compartido (`demo`/`demo`), script de seed/reset (`backend/src/db/seed-demo.js` — proyecto "Acme Corp" con 5 targets, 10 findings de severidad y estado de remediación mixtos, progreso WSTG/PortSwigger y 3 tickets, reusando la biblioteca de templates existente; idempotente, pensado para correr por cron cada ~30 min) y un guard (`DEMO_MODE=true`) que bloquea solo las acciones que dejarían la demo inutilizable para el próximo visitante (borrar el proyecto/org demo, activar 2FA en la cuenta compartida) sin volverla de solo lectura. **Pendiente — despliegue real** (bloqueado por el VPS caído al momento de escribir esto):
  1. Checkout de otro path en el VPS (ej. `/var/www/flowdit-demo`) apuntando a `master`, DB propia (`flowdit_demo`) — no compartir DB con producción.
  2. `.env` del checkout demo con `DEMO_MODE=true` y su propio `DB_NAME`/`JWT_SECRET`.
  3. Nginx: server block para `demo.flowdit.space` (mismo patrón que el de producción) + registro DNS A/CNAME apuntando al VPS.
  4. PM2: proceso propio (ej. `flowdit-demo-backend`) corriendo en un puerto distinto al de producción (prod usa 4000).
  5. `node src/db/migrate.js && node src/db/seed-demo.js` una vez, para el primer poblado.
  6. Crontab en el VPS: `*/30 * * * * cd /var/www/flowdit-demo/backend && node src/db/seed-demo.js >> /var/log/flowdit-demo-seed.log 2>&1`.
  7. Verificar: login `demo`/`demo` en `https://demo.flowdit.space`, y que borrar el proyecto/activar 2FA devuelvan 403.

---

## Producto — lo que hace que la gente se quede

- [x] **Biblioteca de templates de vulnerabilidades** — catálogo de hallazgos comunes (SQLi, XSS, IDOR, SSRF, etc.) que se agregan con un clic, con descripción y remediación pre-escritas.
- [x] **Workflow de remediación** — vuln marcada como "remediated" → retest → "verified closed" con fecha, notas y responsable, con auditoría (`remediated_at`/`verified_at`/`verified_by`) separada del status legado de confirmación.
- [x] **IA multi-proveedor** — Groq y Anthropic seleccionables por proyecto (modelo también configurable), con tracking de gasto estimado por proyecto reutilizando los tokens que cada respuesta ya devuelve (sin costo extra de API).
- [x] **Aislamiento de datos entre proyectos** — auditoría de seguridad dedicada; se encontraron y corrigieron varios IDOR reales (acceso cruzado entre proyectos vía `target_id`/`ticket_id` no validados) antes de que esto fuera un problema en producción.
- [x] **Integración con GitHub Issues (v1 — push de una vía)** — botón "Send to GitHub" por ticket: crea un issue con título/descripción y, si el ticket está vinculado a un hallazgo, su severidad/descripción/remediación. Repo + PAT configurables por proyecto (PAT cifrado en reposo, nunca se devuelve por API). Sin webhooks ni sync bidireccional a propósito — ver [GITHUB_INTEGRATION.md](GITHUB_INTEGRATION.md) para el diseño completo y el camino hacia sync bidireccional (v3) si el uso lo justifica.
- [ ] **Importación de Nessus** — `.nessus` es el formato del scanner enterprise estándar. Sin esto, Flowdit queda fuera del flujo de trabajo de equipos corporativos.
- [x] **Tests de integración** — 25 tests (`node:test` + `supertest`, sin mocks, contra Postgres real) cubriendo auth, aislamiento de datos entre proyectos (regresión directa de los IDOR de `a582e20`) y export (PDF/DOCX). Corren en CI en cada push/PR.
- [ ] **Importación de Nmap XML** — complementa Nessus para el inventario de puertos/servicios.
- [ ] **Notificaciones por email** — cuando el cliente responde un ticket o se crea un hallazgo crítico.
- [x] **2FA** — TOTP opt-in por usuario (compatible con Google Authenticator, Authy, etc.), independiente de organizations. Setup con QR + secreto manual, 10 códigos de respaldo de un solo uso mostrados una única vez al activar, y `/auth/mfa/disable` exige repetir la contraseña de la cuenta (downgrade de seguridad, misma vara que cambiarla). El login por SSO no lo exige — el IdP (Entra ID) ya gestiona su propia política de MFA para ese camino; solo el login por contraseña lo chequea. Secreto cifrado en reposo (AES-256-GCM, reutilizando `SSO_ENCRYPTION_KEY`); códigos de respaldo solo se persisten como hash bcrypt. 11 tests de integración nuevos.
- [ ] **CVSS v4.0** — la industria está migrando.

---

## Monetización — lo que hace que pagues las cuentas

- [x] **Organizations — cuentas de empresa** — capa fundacional sobre `projects`: una organización agrupa proyectos con membresía propia (owner/admin/member); owners/admins ven y administran todos los proyectos de la empresa sin invitación manual proyecto por proyecto. Migración con backfill retrocompatible (cero regresión en accesos existentes), panel con resumen de hallazgos críticos/altos por proyecto integrado en `projects.html` filtrable por organización. Es el prerequisito real de SSO y de un panel de admin — ninguno de los dos tenía sentido antes sin este modelo de datos.
- [ ] **Hosting gestionado** — `app.flowdit.space` con plan free (1 proyecto) y plan Pro (~$30/mes ilimitado). El modelo más directo sin cambiar el core open source.
- [x] **SSO — Microsoft Entra ID (OIDC), por organización** — login vía Entra ID configurable por organización (issuer/client id/secret cifrado, dominio de email vinculado, enforce opcional que bloquea login por contraseña para ese dominio). Aprovisionamiento JIT de usuarios en el primer login SSO. Queda pendiente Okta/Google Workspace y SAML puro, pero el patrón OIDC ya está probado en producción.
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
| 9 | Demo en vivo con seed data | Código listo, falta desplegar | Adopción masiva | Bajo |
| 10 | Importación Nessus | Pendiente | Mercado enterprise | Medio |
| 11 | 2FA | ✅ Hecho | Credibilidad de seguridad | Bajo |
| 12 | Tests de integración | ✅ Hecho | Credibilidad open source | Alto |
| 13 | Hosting gestionado | Pendiente | Primera monetización | Alto |
| 14 | SSO — Entra ID (OIDC) | ✅ Hecho (falta Okta/Google/SAML) | Contratos enterprise | Alto |
