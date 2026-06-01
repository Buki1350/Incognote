#!/bin/sh
set -e

# Platform typically sets PORT=3000 — unset so services use AUTH_PORT/NOTES_PORT
unset PORT

AUTH_PORT=${AUTH_PORT:-3001}
NOTES_PORT=${NOTES_PORT:-3002}

export AUTH_SERVICE_URL=http://127.0.0.1:${AUTH_PORT}

cat > /etc/nginx/conf.d/default.conf <<EOF
server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;

    location /api/auth/ {
        proxy_pass http://127.0.0.1:${AUTH_PORT}/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /api/notes/ {
        proxy_pass http://127.0.0.1:${NOTES_PORT}/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

echo "Starting auth-service on 0.0.0.0:${AUTH_PORT}..."
AUTH_PORT=${AUTH_PORT} /usr/local/bin/auth-service &
AUTH_PID=$!

echo "Starting notes-service on 0.0.0.0:${NOTES_PORT}..."
NOTES_PORT=${NOTES_PORT} /usr/local/bin/notes-service &
NOTES_PID=$!

sleep 2

echo "Starting nginx on port 80..."
nginx -g "daemon off;"
