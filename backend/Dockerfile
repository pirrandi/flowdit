FROM node:20-alpine

# Chromium (PDF export via Puppeteer) + Ghostscript (PDF password encryption)
RUN apk add --no-cache chromium ghostscript ca-certificates

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src

EXPOSE 4000

CMD ["sh", "-c", "node src/db/migrate.js && node src/index.js"]
