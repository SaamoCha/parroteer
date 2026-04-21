# Parroteer Reflector

Self-hosted [clienthellod](https://github.com/refraction-networking/clienthellod)
reflector for TLS and QUIC fingerprint capture. Deployed on Fly.io.

## Setup

### 1. Get a domain

Point a domain (e.g., `reflect.matseoi.com`) to the Fly.io app.
You'll set this after the first deploy when you know the IP.

### 2. Deploy

```bash
cd reflector

# Install flyctl if needed
# curl -L https://fly.io/install.sh | sh

# Create app (first time only)
fly launch --no-deploy

# Set your domain
fly secrets set REFLECTOR_DOMAIN=reflect.matseoi.com

# Deploy
fly deploy

# Get the app's IP
fly ips list
```

### 3. DNS

Point your domain to the Fly.io IPs:
```
reflect.matseoi.com  A     <ipv4 from fly ips list>
reflect.matseoi.com  AAAA  <ipv6 from fly ips list>
```

Caddy will automatically get a Let's Encrypt certificate on first request.

### 4. Test

```bash
# TLS fingerprint
curl https://reflect.matseoi.com/

# Should return JSON with tls object including cipher_suites, extensions, etc.
```

## How it works

- **Port 80**: ACME HTTP-01 challenge + redirect to HTTPS
- **Port 443 TCP**: Caddy terminates TLS; clienthellod listener wrapper
  captures the raw ClientHello before Caddy processes it; handler returns
  the fingerprint as JSON
- **Port 443 UDP**: Same for QUIC Initial Packets

All ports use Fly.io TCP/UDP passthrough (no Fly TLS termination).

## Updating parroteer to use this reflector

Set `REFLECTOR_URL` environment variable in the CI workflow:

```yaml
env:
  REFLECTOR_URL: "https://reflect.matseoi.com/"
```
