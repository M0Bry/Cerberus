#!/bin/bash
# Generate self-signed certificates for development
# For production, use Let's Encrypt: certbot certonly --standalone -d yourdomain.com

CERT_DIR="./infrastructure/nginx/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
    echo "Certificates already exist. Skipping."
    exit 0
fi

echo "Generating self-signed certificates for development..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/privkey.pem" \
    -out "$CERT_DIR/fullchain.pem" \
    -subj "/C=US/ST=State/L=City/O=CerberusAI/CN=localhost" \
    2>/dev/null

echo "✅ Certificates generated:"
echo "   $CERT_DIR/fullchain.pem"
echo "   $CERT_DIR/privkey.pem"
echo ""
echo "⚠️  For production, replace with real certificates from Let's Encrypt."
