# Flowdit Self-hosting Guide

This guide covers a full production deployment on Ubuntu 22.04 LTS using Node.js, PostgreSQL, Nginx, PM2, and Let's Encrypt.

## Requirements

- Ubuntu 22.04 LTS (or similar Debian-based)
- 1 vCPU, 1 GB RAM minimum
- A domain with an A record pointing to your server IP
- Ports 80 and 443 open

---

## 1. Install dependencies

```bash
# System update
apt update && apt upgrade -y

# Node.js 20 (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# PostgreSQL 15
apt install -y postgresql postgresql-contrib

# Nginx
apt install -y nginx

# PM2 (process manager)
npm install -g pm2

# Certbot (SSL)
apt install -y certbot python3-certbot-nginx

# Chromium (for PDF export)
apt install -y chromium-browser
# or on some systems:
# apt install -y chromium
```

---

## 2. Set up PostgreSQL

```bash
# Switch to postgres user
sudo -u postgres psql

-- Inside psql:
CREATE USER flowdit_user WITH PASSWORD 'your_strong_password';
CREATE DATABASE flowdit OWNER flowdit_user;
GRANT ALL PRIVILEGES ON DATABASE flowdit TO flowdit_user;
\q
```

---

## 3. Clone and configure

```bash
# Clone the repo
git clone https://github.com/pirrandi/flowdit.git /var/www/flowdit
cd /var/www/flowdit

# Configure environment
cp .env.example .env
nano .env
```

Fill in all required values in `.env`:

```env
NODE_ENV=production
PORT=4000

DB_HOST=localhost
DB_PORT=5432
DB_NAME=flowdit
DB_USER=flowdit_user
DB_PASSWORD=your_strong_password

# Generate with: openssl rand -hex 64
JWT_SECRET=your_64_char_random_string
JWT_EXPIRES_IN=7d
JWT_REFRESH_EXPIRES_IN=30d

CORS_ORIGIN=https://yourdomain.com
FRONTEND_URL=https://yourdomain.com
RATE_LIMIT_MAX=200

# Optional SMTP for email notifications
SMTP_HOST=
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
SMTP_FROM=Flowdit <no-reply@yourdomain.com>
```

---

## 4. Install backend dependencies and run migrations

```bash
cd /var/www/flowdit/backend
npm install
node src/db/migrate.js

# Create the first account: public registration is off by default.
# Omit --password to get a strong generated one, printed once.
npm run user:create -- --username admin --email you@example.com
```

---

## 5. Start with PM2

```bash
cd /var/www/flowdit/backend
pm2 start src/index.js --name flowdit-backend
pm2 save
pm2 startup   # follow the printed command to enable auto-start on reboot
```

Verify it's running:

```bash
pm2 status
curl http://localhost:4000/health
# Expected: {"status":"ok"}
```

---

## 6. Configure Nginx

Create `/etc/nginx/sites-available/flowdit`:

```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

    # Serve frontend
    root /var/www/flowdit/frontend;
    index index.html;

    # Security headers. Note that nginx does not merge add_header across levels:
    # any block declaring its own add_header loses every inherited one, so a
    # location that sets Cache-Control must restate these.
    #
    # connect-src is 'self' here because this vhost proxies /api and /ws on the
    # same origin. 'unsafe-inline' is still required by the current frontend
    # (inline <script> blocks and inline style attributes).
    add_header X-Frame-Options        "SAMEORIGIN"                       always;
    add_header X-Content-Type-Options "nosniff"                          always;
    add_header Referrer-Policy        "strict-origin-when-cross-origin"  always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'" always;

    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy API
    location /api {
        proxy_pass         http://localhost:4000;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Allow large request bodies (evidence images)
        client_max_body_size 50M;
        proxy_read_timeout   120s;
    }

    # Proxy WebSocket
    location /ws {
        proxy_pass         http://localhost:4000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_read_timeout 3600s;
    }
}
```

Enable and test:

```bash
ln -s /etc/nginx/sites-available/flowdit /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

---

## 7. Get SSL certificate

```bash
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Certbot will automatically configure the SSL directives and set up auto-renewal.

---

## 8. Verify

```bash
# Backend health
curl https://yourdomain.com/api/health

# Open in browser
# https://yourdomain.com → should show the Flowdit login page
```

---

## Day-to-day operations

```bash
# View backend logs
pm2 logs flowdit-backend

# Restart backend
pm2 restart flowdit-backend

# Update to latest version
cd /var/www/flowdit
git pull
cd backend && npm install
node src/db/migrate.js   # always safe to run (idempotent)
pm2 restart flowdit-backend
```

---

## Database backup

```bash
# Manual backup
pg_dump -U flowdit_user -h localhost flowdit > backup_$(date +%Y%m%d).sql

# Restore
psql -U flowdit_user -h localhost flowdit < backup_YYYYMMDD.sql
```

Automate with cron (`crontab -e`):

```bash
0 3 * * * pg_dump -U flowdit_user -h localhost flowdit > /var/backups/flowdit_$(date +\%Y\%m\%d).sql
```

---

## Security hardening (recommended)

```bash
# Firewall
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# Fail2ban for SSH brute force protection
apt install -y fail2ban
systemctl enable --now fail2ban
```
