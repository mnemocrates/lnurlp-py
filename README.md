# LNURL-pay Server

A lightweight, self-hosted LNURL-pay server implementation in Python that connects to your Lightning Network (LND) node via Tor.

## Features

- ✅ **LNURL-pay Protocol Compliant** - Full implementation of LUD-06 and LUD-12
- ✅ **Tor Support** - Securely connects to LND nodes via onion services
- ✅ **Input Validation** - Validates amounts, comments, and usernames
- ✅ **Error Handling** - Comprehensive error handling for LND connection failures
- ✅ **Logging** - File and console logging for monitoring and debugging
- ✅ **Configurable** - JSON-based configuration for easy customization
- ✅ **Comment Support** - Allows payers to attach messages (up to 200 chars)
- ✅ **Rate Limiting** - Built-in rate limiting with persistent storage
- ✅ **Statistics Tracking** - Persistent statistics across restarts
- ✅ **SSL/TLS Options** - Configurable certificate verification

## Requirements

- Python 3.7+
- LND node with REST API access
- Tor proxy (for connecting to LND over Tor)
- nginx (for reverse proxy)
- xxd utility (usually pre-installed on Linux)

## Installation

### 1. Clone or Download

```bash
cd /opt
git clone <your-repo-url> lnurlp-py
cd lnurlp-py
```

### 2. Install Python Dependencies

```bash
pip install requests
```

### 3. Configure the Server

Copy the example configuration and edit it:

```bash
cp config.json.example config.json
nano config.json
```

### 4. Set Permissions

Ensure the macaroon file is readable:

```bash
chmod 644 /path/to/your/invoice.macaroon
```

## Configuration (config.json)

The server uses a JSON configuration file with the following structure:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 5001,
    "rate_limit_file": "rate_limits.json",
    "stats_file": "stats.json",
    "stats_save_interval": 300
  },
  "lnd": {
    "onion_address": "abcdefg1234567890.onion",
    "port": 8080,
    "macaroon_path": "/var/lib/lnurlp/invoice.macaroon",
    "invoice_expiry": 3600,
    "verify_ssl": false
  },
  "tor": {
    "proxy": "socks5h://127.0.0.1:9050"
  },
  "lnurlp": {
    "domain": "0kb.io",
    "min_sendable": 1000,
    "max_sendable": 100000000,
    "comment_allowed": 200,
    "allows_nostr": false,
    "allowed_usernames": [],
    "require_valid_username": false
  }
}
```

### Configuration Parameters

#### Server Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `host` | string | IP address to bind the server (use `127.0.0.1` for local-only) |
| `port` | integer | Port number for the HTTP server (default: 5001) |
| `rate_limit_file` | string | File to persist rate limiting data (default: `rate_limits.json`) |
| `stats_file` | string | File to persist server statistics (default: `stats.json`) |
| `stats_save_interval` | integer | How often to save stats in seconds (default: 300 = 5 minutes) |

#### LND Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `onion_address` | string | Your LND node's onion address (without `https://` or port) |
| `port` | integer | LND REST API port (default: 8080) |
| `macaroon_path` | string | Absolute path to invoice.macaroon file |
| `invoice_expiry` | integer | Invoice expiry time in seconds (default: 3600 = 1 hour) |
| `verify_ssl` | boolean | Enable SSL certificate verification (default: false, recommended for .onion addresses) |

**SSL Certificate Verification:**

- For `.onion` addresses: Set `verify_ssl: false` (Tor provides encryption)
- For clearnet addresses: Set `verify_ssl: true` and ensure proper certificates
- **Warning**: Disabling SSL verification increases MITM risk on clearnet connections

**Finding your LND onion address:**
```bash
lncli getinfo | grep "uris"
```

#### Tor Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `proxy` | string | SOCKS5 proxy address for Tor (default: `socks5h://127.0.0.1:9050`) |

#### LNURL-pay Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Your public domain name (e.g., `yourdomain.com`) |
| `min_sendable` | integer | Minimum payment amount in millisatoshis (1000 = 1 sat) |
| `max_sendable` | integer | Maximum payment amount in millisatoshis (100000000 = 100,000 sats) |
| `comment_allowed` | integer | Maximum comment length in characters (0-280, default: 200) |
| `allows_nostr` | boolean | Enable Nostr NIP-57 support (currently not implemented) |
| `allowed_usernames` | array | Optional list of permitted usernames (empty = allow all) |
| `require_valid_username` | boolean | Enforce username whitelist (requires `allowed_usernames` to be set) |

**Important**: `max_sendable` values above 10 million sats (10,000,000,000 millisats) will trigger a warning during startup as they may expose your node to liquidity issues. Ensure your channels can handle the maximum amounts you configure.

**Username Whitelist Examples:**

**Allow any username** (default behavior):
```json
"allowed_usernames": [],
"require_valid_username": false
```

**Restrict to specific usernames only:**
```json
"allowed_usernames": ["alice", "bob", "tips", "donations"],
"require_valid_username": true
```

When enabled, only usernames in the `allowed_usernames` list will be accepted. Matching is case-insensitive (e.g., `Alice` = `alice`). All payments still go to your single LND wallet regardless of username.

## systemd Service Setup

Create a systemd service file to run the server automatically. A template file `lnurlp.service` is included in the repository.

### 1. Install Service File

Copy the service file to systemd:

```bash
sudo cp lnurlp.service /etc/systemd/system/
```

Or create `/etc/systemd/system/lnurlp.service` manually with the included template.
Restart=always
RestartSec=10

#### Security hardening
```
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/lnurlp-py
```

#### Logging
```
StandardOutput=journal
StandardError=journal
SyslogIdentifier=lnurlp

[Install]
WantedBy=multi-user.target
```

### 2. Create Service User

```bash
sudo useradd -r -s /bin/false lnurlp
sudo chown -R lnurlp:lnurlp /opt/lnurlp-py
```

### 3. Enable and Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable lnurlp
sudo systemctl start lnurlp
```

### 4. Check Status

```bash
sudo systemctl status lnurlp
sudo journalctl -u lnurlp -f
```

## nginx Configuration

Configure nginx as a reverse proxy to handle HTTPS and route requests to the Python server.

### 1. Install Certbot (for SSL)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

### 2. nginx Server Block

Create `/etc/nginx/sites-available/lnurlp`:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name yourdomain.com;

    # SSL certificates (managed by certbot)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # LNURL-pay metadata endpoint
    location /.well-known/lnurlp/ {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # CORS headers (optional, for web wallets)
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type";
    }

    # LNURL-pay callback endpoint
    location /lnurlp/callback {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # CORS headers (optional, for web wallets)
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS";
        add_header Access-Control-Allow-Headers "Content-Type";
    }

    # Block all other paths
    location / {
        return 404;
    }
}
```

### 3. Enable Site and Reload nginx

```bash
sudo ln -s /etc/nginx/sites-available/lnurlp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## Usage

### Lightning Address Format

Once configured, users can send payments to:

```
username@yourdomain.com
```

**Important:** By default, ANY username will work and all payments go to your single LND wallet. The username only appears in the invoice memo field. 

If you want to restrict which usernames are accepted, enable the username whitelist in your `config.json`:

```json
"allowed_usernames": ["alice", "bob", "tips"],
"require_valid_username": true
```

With the whitelist enabled, only `alice@yourdomain.com`, `bob@yourdomain.com`, and `tips@yourdomain.com` will be accepted. Other usernames will return an error.

For example, if your domain is `example.com` and a user wants to pay `alice`, they would use:

```
alice@example.com
```

### Testing the Endpoints

**Test metadata endpoint:**
```bash
curl https://yourdomain.com/.well-known/lnurlp/alice
```

Expected response:
```json
{
  "status": "OK",
  "tag": "payRequest",
  "callback": "https://yourdomain.com/lnurlp/callback",
  "metadata": "[[\"text/plain\",\"Payment to alice@yourdomain.com\"]]",
  "minSendable": 1000,
  "maxSendable": 100000000,
  "allowsNostr": false,
  "commentAllowed": 200
}
```

**Test callback endpoint:**
```bash
curl "https://yourdomain.com/lnurlp/callback?amount=5000&comment=Test+payment"
```

Expected response:
```json
{
  "pr": "lnbc50n1...",
  "routes": []
}
```

### Wallet Support

Compatible with any LNURL-pay supporting wallet:
- Phoenix
- Wallet of Satoshi
- Blue Wallet
- Zeus
- Muun
- Breez
- And many more...

## Monitoring

### View Live Logs

```bash
# systemd logs
sudo journalctl -u lnurlp -f

# Application logs
tail -f /opt/lnurlp-py/lnurlp-server.log
```

### Log Rotation

Configure logrotate for the application log:

Create `/etc/logrotate.d/lnurlp`:

```
/opt/lnurlp-py/lnurlp-server.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 lnurlp lnurlp
    postrotate
        systemctl reload lnurlp > /dev/null 2>&1 || true
    endscript
}
```

## Troubleshooting

### Server won't start

**Check configuration:**
```bash
python3 verify_install.py  # Run installation verification first
python3 server.py
```

**Verify config.json exists:**
```bash
ls -la config.json
```

### LND connection fails

**Test Tor connection:**
```bash
curl --socks5-hostname 127.0.0.1:9050 https://your-onion-address.onion:8080/v1/getinfo
```

**Check macaroon permissions:**
```bash
ls -la /path/to/invoice.macaroon
```

### Invoice creation fails

**Check LND logs:**
```bash
tail -f ~/.lnd/logs/bitcoin/mainnet/lnd.log
```

**Verify macaroon has invoice permissions:**
```bash
lncli bakemacaroon invoices:write invoices:read
```

### nginx 502 Bad Gateway

**Verify Python server is running:**
```bash
sudo systemctl status lnurlp
curl http://127.0.0.1:5001/.well-known/lnurlp/test
```

## SSL/TLS and Security Considerations

### Tor Connection Security

The server connects to LND via Tor onion service with `verify=False` for SSL certificate verification. This is **acceptable for .onion addresses** because:

- Tor provides end-to-end encryption through the network itself
- .onion addresses cannot get valid SSL certificates from public CAs
- The onion address acts as a cryptographic identifier

**Important:** If you modify the code to connect to LND without Tor (direct IP), you MUST enable SSL verification or use a secure connection method.

### Network Security

1. **Firewall Configuration**
   - Block direct access to port 5001 from external networks
   - Only nginx should be able to connect to the Python server
   - Example iptables rule:
     ```bash
     iptables -A INPUT -p tcp --dport 5001 ! -s 127.0.0.1 -j DROP
     ```

2. **HTTPS is Mandatory**
   - LNURL-pay spec requires HTTPS
   - Use Let's Encrypt for free SSL certificates
   - Never expose HTTP endpoints publicly

3. **Macaroon Security**
   - Use invoice-only macaroon (minimal permissions)
   - Never commit macaroon to version control
   - Restrict file permissions: `chmod 600 invoice.macaroon`
   - Rotate macaroons periodically

### Rate Limiting

The server implements built-in rate limiting (100 requests per 60 seconds per IP) with persistent storage to `rate_limits.json`. This provides basic protection against DoS attacks and invoice spam.

**For additional protection**, configure rate limiting in nginx as well:

```nginx
# Add to nginx server block for defense-in-depth
limit_req_zone $binary_remote_addr zone=lnurlp_meta:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=lnurlp_callback:10m rate=10r/s;

location /.well-known/lnurlp/ {
    limit_req zone=lnurlp_meta burst=50 nodelay;
    limit_req_status 429;
    # ... rest of config
}

location /lnurlp/callback {
    limit_req zone=lnurlp_callback burst=20 nodelay;
    limit_req_status 429;
    # ... rest of config
}
```

The combination of application-level and nginx-level rate limiting provides defense-in-depth protection.

### fail2ban for Automatic IP Banning

While the server has built-in rate limiting, **fail2ban** provides an additional layer of protection by automatically banning IP addresses that exhibit abusive behavior. Unlike rate limiting which throttles requests, fail2ban uses iptables to completely block repeat offenders at the firewall level.

**Why use fail2ban?**
- **Persistent bans**: Blocks abusive IPs for extended periods (hours/days)
- **System-wide protection**: Banned IPs are blocked from all services, not just the LNURL server
- **Pattern detection**: Can identify attack patterns across multiple attempts
- **Automatic response**: No manual intervention needed to block bad actors

**How it works:**
1. fail2ban monitors `lnurlp-server.log` for warning patterns
2. Counts violations per IP address (rate limits, invalid requests, prohibited content)
3. After threshold is reached (default: 5 violations in 10 minutes), bans the IP using iptables
4. Ban duration is configurable (default: 1 hour)

**When to use it:**
- Production deployments exposed to the public internet
- If you notice repeated abuse in your logs
- When running on a server with other services (fail2ban can protect them too)
- As part of a comprehensive security strategy

The server works perfectly fine without fail2ban, but it's recommended for internet-facing deployments where automated attack mitigation is valuable.

## Backup and Recovery

### What to Backup

**Critical files:**
- `config.json` - Your server configuration
- `invoice.macaroon` - Authentication for LND (if you generated it specifically for this server)

**Optional:**
- `lnurlp-server.log` - Server logs for audit trail

### Backup Script Example

```bash
#!/bin/bash
# backup-lnurlp.sh

BACKUP_DIR="/var/backups/lnurlp"
DATE=$(date +%Y%m%d-%H%M%S)
SERVER_DIR="/opt/lnurlp-py"

mkdir -p "$BACKUP_DIR"

# Backup config
cp "$SERVER_DIR/config.json" "$BACKUP_DIR/config-$DATE.json"

# Backup logs (last 30 days)
find "$SERVER_DIR" -name "lnurlp-server.log*" -mtime -30 \
    -exec cp {} "$BACKUP_DIR/" \;

# Keep only 90 days of backups
find "$BACKUP_DIR" -type f -mtime +90 -delete

echo "Backup completed: $BACKUP_DIR"
```

### Recovery Procedure

1. **Restore configuration**
   ```bash
   cp /var/backups/lnurlp/config-YYYYMMDD-HHMMSS.json /opt/lnurlp-py/config.json
   ```

2. **Verify configuration**
   ```bash
   cd /opt/lnurlp-py
   python3 verify_install.py
   ```

3. **Restart server**
   ```bash
   sudo systemctl restart lnurlp
   sudo systemctl status lnurlp
   ```

4. **Test endpoints**
   ```bash
   curl https://yourdomain.com/.well-known/lnurlp/test
   ```

### Disaster Recovery

If LND node is lost/corrupted:
- LNURL-pay server configuration survives independently
- You'll need to update `macaroon_path` in config.json to point to new LND instance
- Username history is not stored (server is stateless)
- Invoice history is in LND's database only

## Security Considerations

1. **Keep macaroon secure** - Use an invoice-only macaroon with minimal permissions
2. **Use HTTPS** - Always serve LNURL endpoints over HTTPS
3. **Firewall** - Block direct access to port 5001, only allow nginx
4. **Rate limiting** - Built-in at 100 req/60s per IP; add nginx rate limiting for defense-in-depth
5. **fail2ban** - Optional fail2ban jail included to automatically ban abusive IPs
6. **Monitor logs** - Regularly check logs for suspicious activity
7. **Update regularly** - Keep dependencies and system packages updated

### fail2ban Integration (Optional)

Automatically ban IPs that repeatedly trigger rate limits or validation errors:

1. Copy jail configuration:
```bash
sudo cp fail2ban-jail.conf /etc/fail2ban/jail.d/lnurlp.conf
sudo cp fail2ban-filter.conf /etc/fail2ban/filter.d/lnurlp.conf
```

2. Update log path in `/etc/fail2ban/jail.d/lnurlp.conf` to match your installation

3. Restart fail2ban:
```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status lnurlp
```

**Settings**:
- `maxretry: 5` - Ban after 5 violations
- `findtime: 600` - Within 10 minutes
- `bantime: 3600` - Ban for 1 hour

The filter catches rate limit violations, invalid usernames, prohibited content, and repeated errors.

## License

MIT License - Feel free to use and modify

## Support

For issues, questions, or contributions, please open an issue on the project repository.

## Acknowledgments

- [LNURL Protocol](https://github.com/lnurl/luds)
- [LND](https://github.com/lightningnetwork/lnd)
- Lightning Network community
