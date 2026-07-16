# Running JWTS as a Systemd Service on Ubuntu 24.04

This guide covers how to deploy and run the JWTS application as a systemd service on Ubuntu 24.04.3 LTS (x86_64).

## Prerequisites

- Ubuntu 24.04.3 LTS (x86_64)
- Root or sudo access
- The compiled `jwts` binary

## 1. Create a Dedicated User

Create a non-privileged user to run the service:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin jwts
```

## 2. Create Directory Structure

```bash
# Create application directories
sudo mkdir -p /opt/jwts/{bin,pem,config}

# Set ownership
sudo chown -R jwts:jwts /opt/jwts
```

## 3. Deploy the Binary

### Option A: Copy Pre-built Binary

```bash
# Copy the binary
sudo cp ./target/release/jwts /opt/jwts/bin/

# Make it executable
sudo chmod +x /opt/jwts/bin/jwts

# Set ownership
sudo chown jwts:jwts /opt/jwts/bin/jwts
```

### Option B: Build on Server

```bash
# Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone <your-repo-url> /tmp/jwts
cd /tmp/jwts
cargo build --release

# Copy binary
sudo cp target/release/jwts /opt/jwts/bin/
sudo chown jwts:jwts /opt/jwts/bin/jwts
sudo chmod +x /opt/jwts/bin/jwts
```

## 4. Generate Keys

Run the key generation script or generate manually:

```bash
# Copy the script
sudo cp scripts/generate-keys.sh /opt/jwts/

# Run as root (will create keys in /opt/jwts/pem)
cd /opt/jwts
sudo ./generate-keys.sh

# Or generate manually with OpenSSL:
cd /opt/jwts/pem

# RSA keys (RS256/384/512)
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa-private.pem
sudo openssl pkey -in rsa-private.pem -pubout -out rsa-public.pem

# PSS keys (PS256/384/512)
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out pss-private.pem
sudo openssl pkey -in pss-private.pem -pubout -out pss-public.pem

# EC P-256 keys (ES256)
sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ec-private.pem
sudo openssl pkey -in ec-private.pem -pubout -out ec-public.pem

# EC P-384 keys (ES384)
sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out ec384-private.pem
sudo openssl pkey -in ec384-private.pem -pubout -out ec384-public.pem

# HMAC secret (HS256/384/512)
sudo openssl rand -base64 64 | tr -d '\n' > hmac-secret.txt
```

Set secure permissions:

```bash
sudo chown -R jwts:jwts /opt/jwts/pem
sudo chmod 600 /opt/jwts/pem/*-private.pem
sudo chmod 600 /opt/jwts/pem/hmac-secret.txt
sudo chmod 644 /opt/jwts/pem/*-public.pem
```

## 5. Create Environment File

Create the environment configuration:

```bash
sudo tee /opt/jwts/config/jwts.env << 'EOF'
# Server configuration
HOST=0.0.0.0
PORT=5000

# Logging
RUST_LOG=info

# API Key (optional - leave empty to disable authentication)
API_KEY=your-secure-api-key-here

# HMAC secret for HS256/HS384/HS512
JWT_SECRET=your-hmac-secret-here

# RSA keys for RS256/RS384/RS512
JWT_PRIVATE_KEY=/opt/jwts/pem/rsa-private.pem
JWT_PUBLIC_KEY=/opt/jwts/pem/rsa-public.pem

# EC P-256 keys for ES256
JWT_EC_PRIVATE_KEY=/opt/jwts/pem/ec-private.pem
JWT_EC_PUBLIC_KEY=/opt/jwts/pem/ec-public.pem

# EC P-384 keys for ES384
JWT_EC384_PRIVATE_KEY=/opt/jwts/pem/ec384-private.pem
JWT_EC384_PUBLIC_KEY=/opt/jwts/pem/ec384-public.pem

# PSS keys for PS256/PS384/PS512
JWT_PSS_PRIVATE_KEY=/opt/jwts/pem/pss-private.pem
JWT_PSS_PUBLIC_KEY=/opt/jwts/pem/pss-public.pem

# Token verification settings (optional)
AUDIENCE=

# Rate limiting
RATE_LIMIT_PER_SECOND=100
RATE_LIMIT_BURST=50
EOF
```

Set the HMAC secret from the generated file:

```bash
# Read the generated secret
HMAC_SECRET=$(sudo cat /opt/jwts/pem/hmac-secret.txt)

# Update the env file
sudo sed -i "s|JWT_SECRET=your-hmac-secret-here|JWT_SECRET=${HMAC_SECRET}|" /opt/jwts/config/jwts.env
```

Secure the environment file:

```bash
sudo chown jwts:jwts /opt/jwts/config/jwts.env
sudo chmod 600 /opt/jwts/config/jwts.env
```

## 6. Create Systemd Service File

```bash
sudo tee /etc/systemd/system/jwts.service << 'EOF'
[Unit]
Description=JWTS - JWT Signing and Verification Service
Documentation=https://github.com/phtn/jwts
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=jwts
Group=jwts

# Working directory
WorkingDirectory=/opt/jwts

# Environment file
EnvironmentFile=/opt/jwts/config/jwts.env

# Start command
ExecStart=/opt/jwts/bin/jwts

# Restart policy
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

# Allow reading from /opt/jwts
ReadOnlyPaths=/opt/jwts
ReadWritePaths=

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=jwts

[Install]
WantedBy=multi-user.target
EOF
```

## 7. Enable and Start the Service

```bash
# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable the service to start on boot
sudo systemctl enable jwts

# Start the service
sudo systemctl start jwts

# Check status
sudo systemctl status jwts
```

## 8. Verify the Service

```bash
# Check if the service is running
sudo systemctl status jwts

# View logs
sudo journalctl -u jwts -f

# Test the health endpoint
curl http://localhost:5000/health

# Test the JWKS endpoint
curl http://localhost:5000/.well-known/jwks.json
```

## Service Management Commands

```bash
# Start the service
sudo systemctl start jwts

# Stop the service
sudo systemctl stop jwts

# Restart the service
sudo systemctl restart jwts

# Reload configuration (after changing env file)
sudo systemctl reload jwts

# Check status
sudo systemctl status jwts

# View logs (last 100 lines)
sudo journalctl -u jwts -n 100

# View logs (follow mode)
sudo journalctl -u jwts -f

# View logs since last boot
sudo journalctl -u jwts -b

# Disable service from starting on boot
sudo systemctl disable jwts
```

## Firewall Configuration (Optional)

If using UFW:

```bash
# Allow port 5000
sudo ufw allow 5000/tcp

# Or allow from specific IP only
sudo ufw allow from 10.0.0.0/8 to any port 5000

# Check status
sudo ufw status
```

## Reverse Proxy with Nginx (Recommended)

For production, use Nginx as a reverse proxy:

```bash
# Install Nginx
sudo apt update
sudo apt install -y nginx

# Create Nginx configuration
sudo tee /etc/nginx/sites-available/jwts << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/jwts /etc/nginx/sites-enabled/

# Test Nginx configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

For HTTPS with Let's Encrypt:

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal is configured automatically
```

## Troubleshooting

### Service won't start

```bash
# Check detailed status
sudo systemctl status jwts -l

# Check logs for errors
sudo journalctl -u jwts --no-pager -n 50

# Verify binary permissions
ls -la /opt/jwts/bin/jwts

# Verify key permissions
ls -la /opt/jwts/pem/

# Test binary manually
sudo -u jwts /opt/jwts/bin/jwts
```

### Permission denied errors

```bash
# Fix ownership
sudo chown -R jwts:jwts /opt/jwts

# Fix key permissions
sudo chmod 600 /opt/jwts/pem/*-private.pem
sudo chmod 600 /opt/jwts/pem/hmac-secret.txt
sudo chmod 644 /opt/jwts/pem/*-public.pem
```

### Port already in use

```bash
# Check what's using the port
sudo ss -tlnp | grep 5000

# Kill the process or change PORT in jwts.env
```

### SELinux issues (if enabled)

```bash
# Check SELinux status
getenforce

# If enforcing, create policy or set to permissive
sudo setenforce 0  # Temporary
```

## Directory Structure

After setup, your directory structure should look like:

```
/opt/jwts/
├── bin/
│   └── jwts                    # The binary
├── config/
│   └── jwts.env                # Environment configuration
├── pem/
│   ├── rsa-private.pem         # RSA private key (RS256/384/512)
│   ├── rsa-public.pem          # RSA public key
│   ├── pss-private.pem         # PSS private key (PS256/384/512)
│   ├── pss-public.pem          # PSS public key
│   ├── ec-private.pem          # EC P-256 private key (ES256)
│   ├── ec-public.pem           # EC P-256 public key
│   ├── ec384-private.pem       # EC P-384 private key (ES384)
│   ├── ec384-public.pem        # EC P-384 public key
│   └── hmac-secret.txt         # HMAC secret (HS256/384/512)
└── generate-keys.sh            # Key generation script (optional)

/etc/systemd/system/
└── jwts.service                # Systemd service file
```

## Security Checklist

- [ ] Non-root user running the service
- [ ] Private keys have 600 permissions
- [ ] Environment file has 600 permissions
- [ ] Systemd security hardening enabled
- [ ] Firewall configured
- [ ] API_KEY set for authentication (if needed)
- [ ] HTTPS enabled via reverse proxy (for production)
- [ ] Rate limiting configured
- [ ] Logs monitored
