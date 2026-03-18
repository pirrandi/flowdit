# HackList — Guía de Deploy en VPS (DigitalOcean / Hetzner)

## Requisitos mínimos del VPS
- Ubuntu 22.04 LTS
- 1 vCPU, 1GB RAM (suficiente para empezar)
- 20GB disco
- Dominio configurado apuntando a la IP del VPS

---

## 1. Preparar el VPS

```bash
# Conectar al VPS
ssh root@TU_IP_VPS

# Actualizar sistema
apt update && apt upgrade -y

# Instalar Docker y Docker Compose
curl -fsSL https://get.docker.com | sh
apt install docker-compose-plugin -y

# Crear usuario no-root (recomendado)
adduser hacklist
usermod -aG docker hacklist
su - hacklist
```

---

## 2. Subir el proyecto al VPS

```bash
# Desde tu máquina local
scp -r hacklist/ hacklist@TU_IP_VPS:~/

# O usa git (recomendado para producción):
# En tu VPS:
git clone https://github.com/TU_USUARIO/hacklist.git
cd hacklist
```

---

## 3. Configurar variables de entorno

```bash
cd ~/hacklist

# Copiar la plantilla
cp .env.production .env

# Editar con tus valores reales
nano .env
```

**Campos a cambiar obligatoriamente:**
```
FRONTEND_DOMAIN=hacklist.tudominio.com
API_DOMAIN=api.hacklist.tudominio.com
CORS_ORIGIN=https://hacklist.tudominio.com
ACME_EMAIL=tu@email.com
DB_PASSWORD=contraseña_muy_segura_aqui
JWT_SECRET=genera_uno_con_el_comando_de_abajo
```

**Generar JWT_SECRET seguro:**
```bash
openssl rand -hex 64
```

---

## 4. Configurar el frontend para apuntar a la API

Editar `frontend/index.html`, buscar esta línea:
```javascript
window.HACKLIST_API = 'http://localhost:4000/api';
```
Cambiar a:
```javascript
window.HACKLIST_API = 'https://api.hacklist.tudominio.com/api';
```

---

## 5. Configurar DNS

En tu proveedor de DNS, crear dos registros A:
```
hacklist.tudominio.com     A    TU_IP_VPS
api.hacklist.tudominio.com A    TU_IP_VPS
```

Esperar propagación (5-30 minutos).

---

## 6. Desplegar

```bash
cd ~/hacklist

# Construir y arrancar todo
docker compose --env-file .env up -d --build

# Ver logs en tiempo real
docker compose logs -f

# Ver estado de los servicios
docker compose ps
```

Traefik obtendrá los certificados SSL automáticamente en el primer arranque.

---

## 7. Verificar el deploy

```bash
# API health check
curl https://api.hacklist.tudominio.com/health

# Respuesta esperada:
# {"status":"ok","ts":"2025-..."}
```

Abrir en el navegador: `https://hacklist.tudominio.com`

---

## Comandos útiles del día a día

```bash
# Ver logs del API
docker compose logs api -f

# Reiniciar solo el API (tras un cambio)
docker compose restart api

# Rebuild tras cambios en el código
docker compose up -d --build api

# Entrar al contenedor de la DB
docker compose exec db psql -U hacklist_user -d hacklist

# Backup de la base de datos
docker compose exec db pg_dump -U hacklist_user hacklist > backup_$(date +%Y%m%d).sql

# Restaurar backup
cat backup_FECHA.sql | docker compose exec -T db psql -U hacklist_user -d hacklist

# Parar todo
docker compose down

# Parar y borrar datos (¡CUIDADO!)
docker compose down -v
```

---

## Actualizar la aplicación

```bash
# Desde tu máquina local, subir cambios
scp -r frontend/ hacklist@TU_IP_VPS:~/hacklist/
scp -r backend/src/ hacklist@TU_IP_VPS:~/hacklist/backend/

# En el VPS
cd ~/hacklist
docker compose up -d --build
```

---

## Seguridad adicional (recomendado)

### Firewall básico
```bash
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (Traefik redirect)
ufw allow 443/tcp   # HTTPS
ufw enable
```

### Fail2ban para SSH
```bash
apt install fail2ban -y
systemctl enable fail2ban
```

### Backups automáticos de DB
Añadir a crontab (`crontab -e`):
```bash
0 3 * * * cd ~/hacklist && docker compose exec -T db pg_dump -U hacklist_user hacklist > ~/backups/backup_$(date +\%Y\%m\%d).sql
```

---

## Estructura final del proyecto

```
hacklist/
├── backend/
│   ├── src/
│   │   ├── db/
│   │   │   ├── index.js        # Conexión PostgreSQL
│   │   │   └── migrate.js      # Migraciones (auto-run al arrancar)
│   │   ├── middleware/
│   │   │   ├── auth.js         # JWT verification
│   │   │   └── project.js      # Project access control
│   │   ├── routes/
│   │   │   ├── auth.js         # /api/auth/*
│   │   │   ├── projects.js     # /api/projects/*
│   │   │   ├── wstg.js         # /api/projects/:id/wstg/*
│   │   │   ├── ps.js           # /api/projects/:id/ps/*
│   │   │   └── vulns.js        # /api/projects/:id/vulns/*
│   │   └── index.js            # Express app entry point
│   ├── Dockerfile
│   ├── package.json
│   └── .env.example
├── frontend/
│   ├── index.html              # App principal
│   ├── api.js                  # Cliente API
│   └── data.js                 # WSTG + PortSwigger data
├── nginx/
│   └── frontend.conf           # Config Nginx para frontend
├── docker-compose.yml
└── .env.production             # Plantilla de variables
```

---

## API Reference

```
POST   /api/auth/register          Crear cuenta
POST   /api/auth/login             Login
POST   /api/auth/refresh           Renovar token
POST   /api/auth/logout            Logout
GET    /api/auth/me                Perfil del usuario

GET    /api/projects               Listar proyectos del usuario
POST   /api/projects               Crear proyecto
GET    /api/projects/:id           Ver proyecto
PATCH  /api/projects/:id           Editar proyecto
DELETE /api/projects/:id           Borrar proyecto
POST   /api/projects/join          Unirse con token de invitación

GET    /api/projects/:id/members           Listar miembros
PATCH  /api/projects/:id/members/:uid      Cambiar rol
DELETE /api/projects/:id/members/:uid      Expulsar miembro

POST   /api/projects/:id/invites           Crear invitación
GET    /api/projects/:id/invites           Listar invitaciones
DELETE /api/projects/:id/invites/:invId    Cancelar invitación

GET    /api/projects/:id/wstg              Progreso WSTG
PATCH  /api/projects/:id/wstg/:testId/status    Estado test
PATCH  /api/projects/:id/wstg/:testId/note      Notas del test
PATCH  /api/projects/:id/wstg/:testId/items/:i  Check item

GET    /api/projects/:id/ps                     Progreso PortSwigger
PATCH  /api/projects/:id/ps/:catId/:labIdx      Toggle lab

GET    /api/projects/:id/vulns             Custom vulns
POST   /api/projects/:id/vulns             Crear vuln
PATCH  /api/projects/:id/vulns/:vulnId     Editar vuln
DELETE /api/projects/:id/vulns/:vulnId     Borrar vuln
```

---

## Roadmap para monetización

### Tier Free
- 1 proyecto
- Acceso completo WSTG + PortSwigger
- 3 custom vulns

### Tier Pro ($8/mes)
- Proyectos ilimitados
- Custom vulns ilimitadas
- Exportar reporte PDF
- Historial de cambios

### Tier Teams ($20/mes por equipo)
- Todo lo de Pro
- Colaboración en equipo
- Roles (owner/editor/viewer)
- Dashboard compartido

**Para implementar pagos:** Stripe + webhook que actualiza un campo `plan` en la tabla `users`.
