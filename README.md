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

### Step 1: Install System Dependencies

```bash
# Update package list
sudo apt update

# Install Python 3 and pip
sudo apt install python3 python3-pip

# Install Tor (if not already installed)
sudo apt install tor

# Install nginx (for reverse proxy)
sudo apt install nginx

# Install certbot (for SSL certificates)
sudo apt install certbot python3-certbot-nginx
```

### Step 2: Create System User and Directories

Create a dedicated user and directory structure following Linux FHS standards:

```bash
# Create lnurlp user (no login shell, system user)
sudo useradd -r -s /bin/false lnurlp

# Create application directory (root owns the code)
sudo mkdir -p /opt/lnurlp-py

# Create runtime data directory (lnurlp user owns runtime data)
sudo mkdir -p /var/lib/lnurlp

# Create log directory (lnurlp user owns logs)
sudo mkdir -p /var/log/lnurlp
```

### Step 3: Install Application Files

```bash
# Clone repository to application directory
cd /opt
sudo git clone <your-repo-url> lnurlp-py
cd lnurlp-py

# Set ownership - root owns application code (read-only for security)
sudo chown -R root:root /opt/lnurlp-py

# Make server.py executable
sudo chmod 755 /opt/lnurlp-py/server.py
```

### Step 4: Install Python Dependencies

```bash
# Install required Python packages
sudo pip3 install requests

# Or use requirements.txt if available:
# sudo pip3 install -r requirements.txt
```

### Step 5: Configure the Server

```bash
# Copy configuration template
cd /opt/lnurlp-py
sudo cp config.json.example config.json

# Edit configuration (see Configuration section below for details)
sudo nano config.json

# IMPORTANT: Update these values in config.json:
#   - lnd.onion_address: Your LND node's onion address
#   - lnurlp.domain: Your public domain name
#   - lnd.macaroon_path: /var/lib/lnurlp/invoice.macaroon
#   - server.rate_limit_file: /var/lib/lnurlp/rate_limits.json
#   - server.stats_file: /var/lib/lnurlp/stats.json
#   - server.log_file: /var/log/lnurlp/lnurlp-server.log

# Set config permissions (readable by lnurlp user)
sudo chown root:lnurlp /opt/lnurlp-py/config.json
sudo chmod 640 /opt/lnurlp-py/config.json
```

### Step 6: Install Macaroon

```bash
# Copy invoice macaroon from your LND node
# Example: If LND is local
sudo cp ~/.lnd/data/chain/bitcoin/mainnet/invoice.macaroon /var/lib/lnurlp/

# Example: If copying from remote server
# scp user@lnd-server:~/.lnd/data/chain/bitcoin/mainnet/invoice.macaroon .
# sudo mv invoice.macaroon /var/lib/lnurlp/

# Set restrictive permissions (CRITICAL for security)
sudo chown lnurlp:lnurlp /var/lib/lnurlp/invoice.macaroon
sudo chmod 600 /var/lib/lnurlp/invoice.macaroon
```

### Step 7: Set Directory Permissions

This is **critical** - incorrect permissions will cause the server fail:

```bash
# lnurlp user must own runtime data and log directories
sudo chown lnurlp:lnurlp /var/lib/lnurlp
sudo chown lnurlp:lnurlp /var/log/lnurlp

# Set directory permissions (755 allows lnurlp user to write files)
sudo chmod 755 /var/lib/lnurlp
sudo chmod 755 /var/log/lnurlp

# Verify permissions are correct
ls -ld /opt/lnurlp-py /var/lib/lnurlp /var/log/lnurlp
# Should show:
#   drwxr-xr-x ... root   root   ... /opt/lnurlp-py
#   drwxr-xr-x ... lnurlp lnurlp ... /var/lib/lnurlp
#   drwxr-xr-x ... lnurlp lnurlp ... /var/log/lnurlp
```

**Why these permissions matter:**
- `/opt/lnurlp-py` - Root owns code (prevents server from modifying itself)
- `/var/lib/lnurlp` - lnurlp user owns data (server can write rate_limits.json, stats.json)
- `/var/log/lnurlp` - lnurlp user owns logs (server can write log files)
- Wrong permissions = server unable to write data/logs.

### Step 8: Test the Installation

```bash
# Test configuration validity
cd /opt/lnurlp-py
python3 verify_install.py

# Test server manually (press Ctrl+C to stop)
sudo -u lnurlp python3 /opt/lnurlp-py/server.py

# In another terminal, test the endpoint
curl http://127.0.0.1:5001/.well-known/lnurlp/test
```

If you see:
- "Server started successfully" in the first terminal
- JSON response from curl (not hanging)
- No permission errors in logs

...then installation is correct! Press Ctrl+C to stop the test server.

### Directory Structure Summary

After installation, your directory structure should look like this:

```
/opt/lnurlp-py/              # Application code (root:root, read-only)
├── server.py                # Main server (root:root, 755)
├── config.json              # Configuration (root:lnurlp, 640)
├── config.json.example      # Template (root:root, 644)
├── test_server.py           # Unit tests
├── verify_install.py        # Installation verification
├── lnurlp.service           # systemd service template
└── README.md

/var/lib/lnurlp/             # Runtime data (lnurlp:lnurlp, 755)
├── invoice.macaroon         # LND auth (lnurlp:lnurlp, 600) - YOU MUST COPY THIS
├── rate_limits.json         # Auto-created by server (lnurlp:lnurlp, 644)
└── stats.json               # Auto-created by server (lnurlp:lnurlp, 644)

/var/log/lnurlp/             # Logs (lnurlp:lnurlp, 755)
└── lnurlp-server.log        # Auto-created by server (lnurlp:lnurlp, 644)
```

**Ownership model:**
- **root owns code** (`/opt/lnurlp-py`) - prevents the server from modifying its own code
- **lnurlp owns data** (`/var/lib/lnurlp`) - allows the server to write persistent data
- **lnurlp owns logs** (`/var/log/lnurlp`) - allows the server to write log files

## systemd Service Setup

After successful manual testing, set up the server to run automatically as a systemd service.

### Step 1: Install Service File

```bash
# Copy the included service template
sudo cp /opt/lnurlp-py/lnurlp.service /etc/systemd/system/

# Reload systemd to recognize the new service
sudo systemctl daemon-reload
```

The included `lnurlp.service` file has security hardening features:
- Runs as non-root `lnurlp` user
- Restricted filesystem access
- Automatic restart on failure
- Proper dependency ordering

### Step 2: Enable and Start Service

```bash
# Enable service to start on boot
sudo systemctl enable lnurlp

# Start the service now
sudo systemctl start lnurlp

# Check service status
sudo systemctl status lnurlp
```

### Step 3: Verify Service is Running

```bash
# View real-time logs
sudo journalctl -u lnurlp -f

# Test the endpoint
curl http://127.0.0.1:5001/.well-known/lnurlp/test
```

### Step 4: Common Service Commands

```bash
# Stop the service
sudo systemctl stop lnurlp

# Restart the service (after config changes)
sudo systemctl restart lnurlp

# View service status
sudo systemctl status lnurlp

# View logs (last 50 lines)
sudo journalctl -u lnurlp -n 50

# View logs (follow in real-time)
sudo journalctl -u lnurlp -f

# Disable service (prevent auto-start on boot)
sudo systemctl disable lnurlp
```

## nginx Configuration

Configure nginx as a reverse proxy to handle HTTPS and route public traffic to your Python server.

### Step 1: Obtain SSL Certificate

```bash
# Make sure your domain's DNS points to your server's IP address first!
# Then obtain a free SSL certificate from Let's Encrypt:

sudo certbot --nginx -d yourdomain.com

# Follow the prompts to set up automatic certificate renewal
```

### Step 2: Create nginx Configuration

Create `/etc/nginx/sites-available/lnurlp`:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name yourdomain.com;

    root /var/www/lnurlp;
    index index.html;

    # No logs (or near-zero logs)
    access_log off;
    error_log /var/log/nginx/error.log crit;

    # Security headers (minimal but useful)
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";

    # No directory listing
    autoindex off;
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem; # managed by Certbot

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
```

#### LND Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `onion_address` | string | Your LND node's onion address (without `https://` or port) |
| `port` | integer | LND REST API port (default: 8080) |
| `macaroon_path` | string | Absolute path to invoice.macaroon file |
| `invoice_expiry` | integer | Invoice expiry time in seconds (default: 3600 = 1 hour) |
| `verify_ssl` | boolean | Enable SSL certificate verification (default: false, recommended for .onion addresses) |

**SSL Certificate Verification:**

- For `.onion` addresses: `verify_ssl: false` is **safe** - Tor provides end-to-end encryption
- For clearnet addresses: `verify_ssl: true` is **required** - HTTPS prevents MITM attacks
- The server will log appropriate warnings based on your configuration

**Important Notes:**
- Disabling SSL verification on .onion is safe because Tor's architecture provides cryptographic authentication
- The .onion address itself is derived from the service's public key, making MITM attacks cryptographically impossible
- For clearnet LND nodes, always enable SSL verification with valid certificates

**Finding your LND onion address:**
```bash
lncli getinfo | grep "uris"
```

#### Tor Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `proxy` | string | SOCKS5 proxy address for Tor (default: `socks5h://127.0.0.1:9050`) |

## Configuration Reference (config.json)

The server uses a JSON configuration file with the following structure:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 5001,
    "rate_limit_file": "/var/lib/lnurlp/rate_limits.json",
    "stats_file": "/var/lib/lnurlp/stats.json",
    "stats_save_interval": 300,
    "log_file": "/var/log/lnurlp/lnurlp-server.log"
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
| `rate_limit_file` | string | Absolute path to rate limiting data file |
| `stats_file` | string | Absolute path to server statistics file |
| `stats_save_interval` | integer | How often to save stats in seconds (default: 300 = 5 minutes) |
| `log_file` | string | Absolute path to log file |

#### LND Settings

| Parameter | Type | Description |
|-----------|------|-------------|
| `onion_address` | string | Your LND node's onion address (without `https://` or port) |
| `port` | integer | LND REST API port (default: 8080) |
| `macaroon_path` | string | Absolute path to invoice.macaroon file |
| `invoice_expiry` | integer | Invoice expiry time in seconds (default: 3600 = 1 hour) |
| `verify_ssl` | boolean | Enable SSL certificate verification (see below) |

**SSL Certificate Verification:**

- For `.onion` addresses: `verify_ssl: false` is **safe** - Tor provides end-to-end encryption
- For clearnet addresses: `verify_ssl: true` is **required** - HTTPS prevents MITM attacks

**Important Notes:**
- Disabling SSL verification on .onion is safe because Tor's architecture provides cryptographic authentication
- The .onion address itself is derived from the service's public key, making MITM attacks cryptographically impossible
- For clearnet LND nodes, always enable SSL verification with valid certificates

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

## Usage

### Lightning Address Format

Once configured, users can send payments to:

```
username@yourdomain.com
```

**Important:** By default, ANY username will work and all payments go to your single LND wallet. The username only appears in the invoice memo field. 

To restrict accepted usernames, enable the whitelist in your `config.json` (see Configuration Reference above).

### Testing Your Server

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

The `pr` field contains a Lightning invoice that can be paid by any Lightning wallet.

### Wallet Support

Compatible with any LNURL-pay supporting wallet:
- Phoenix
- Wallet of Satoshi
- Blue Wallet
- Zeus
- Muun
- Breez
- And many more...

Simply enter `username@yourdomain.com` in the wallet and it will handle the rest.

## Monitoring and Maintenance

### View Live Logs

```bash
# View systemd service logs (recommended)
sudo journalctl -u lnurlp -f

# View application log file
tail -f /var/log/lnurlp/lnurlp-server.log
```

### Check Server Statistics

The server tracks statistics and saves them to `/var/lib/lnurlp/stats.json`:

```bash
# View current stats
cat /var/lib/lnurlp/stats.json

# Access health check endpoint
curl http://127.0.0.1:5001/health
```

Statistics include:
- Total requests
- Metadata requests
- Callback requests
- Invoices created
- Errors
- Rate limit violations

### Log Rotation

Configure logrotate to prevent log files from growing too large.

Create `/etc/logrotate.d/lnurlp`:

```
/var/log/lnurlp/lnurlp-server.log {
    daily
    rotate 14
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

This will:
- Rotate logs daily
- Keep 14 days of logs
- Compress old logs
- Create new log files with correct ownership

## Troubleshooting

### Server Won't Start

### Server Won't Start

**Check systemd status:**
```bash
sudo systemctl status lnurlp
sudo journalctl -u lnurlp -n 50
```

**Verify configuration:**
```bash
cd /opt/lnurlp-py
python3 verify_install.py
```

**Check file permissions:**
```bash
# Verify directories have correct ownership
ls -ld /opt/lnurlp-py /var/lib/lnurlp /var/log/lnurlp

# Verify macaroon permissions
ls -l /var/lib/lnurlp/invoice.macaroon
```

Common issues:
- Missing `config.json` - copy from `config.json.example`
- Wrong permissions on `/var/lib/lnurlp` or `/var/log/lnurlp`
- Missing or wrong permissions on macaroon file

### Server Hangs on Requests

If `curl` connects but never returns a response:

**Check permissions on data directories:**
```bash
# These must be owned by lnurlp user
sudo chown lnurlp:lnurlp /var/lib/lnurlp
sudo chown lnurlp:lnurlp /var/log/lnurlp

# Restart after fixing permissions
sudo systemctl restart lnurlp
```

**Check for permission errors in logs:**
```bash
sudo journalctl -u lnurlp | grep -i permission
```

The server will hang if it cannot write to:
- `/var/log/lnurlp/lnurlp-server.log` (log file)
- `/var/lib/lnurlp/rate_limits.json` (rate limiting data)
- `/var/lib/lnurlp/stats.json` (statistics)

### LND Connection Fails

**Test Tor connectivity:**
```bash
# Test if you can reach your LND node via Tor
curl --socks5-hostname 127.0.0.1:9050 \
     https://your-onion-address.onion:8080/v1/getinfo \
     --insecure
```

**Verify Tor is running:**
```bash
sudo systemctl status tor
```

**Check macaroon permissions and path:**
```bash
# Verify file exists and is readable by lnurlp user
sudo -u lnurlp cat /var/lib/lnurlp/invoice.macaroon > /dev/null
echo $?  # Should print 0 if successful
```

**Test macaroon manually:**
```bash
# Extract hex from macaroon
MACAROON_HEX=$(xxd -p -c 1000 /var/lib/lnurlp/invoice.macaroon)

# Test LND connection
curl --socks5-hostname 127.0.0.1:9050 \
     -H "Grpc-Metadata-macaroon: $MACAROON_HEX" \
     https://your-onion.onion:8080/v1/getinfo \
     --insecure
```

### Invoice Creation Fails

**Check LND logs:**
```bash
# For default LND installation
tail -f ~/.lnd/logs/bitcoin/mainnet/lnd.log
```

**Verify macaroon permissions:**
The macaroon must have `invoices:write` and `invoices:read` permissions.

**Create a new invoice macaroon if needed:**
```bash
lncli bakemacaroon invoices:write invoices:read --save_to=invoice.macaroon
```

### nginx 502 Bad Gateway

**Verify Python server is running:**
```bash
sudo systemctl status lnurlp
curl http://127.0.0.1:5001/.well-known/lnurlp/test
```

**Check nginx error logs:**
```bash
sudo tail -f /var/log/nginx/error.log
```

**Verify nginx can connect to port 5001:**
```bash
sudo netstat -tlnp | grep 5001
```

### Rate Limiting Issues

**Check current rate limit data:**
```bash
cat /var/lib/lnurlp/rate_limits.json
```

**Clear rate limits (if needed):**
```bash
sudo systemctl stop lnurlp
sudo rm /var/lib/lnurlp/rate_limits.json
sudo systemctl start lnurlp
```

Rate limits reset automatically after 60 seconds per IP address.

## Security Considerations

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

## fail2ban Integration (Optional)

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
