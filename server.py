#!/usr/bin/env python3
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import urllib3
import subprocess
import os
import logging
import re
import signal
import sys
import uuid
from threading import Lock
from datetime import datetime
import time

# Configure logging (will be reconfigured after loading config)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Error message constants
ERROR_INVALID_USERNAME = "Invalid username"
ERROR_MISSING_AMOUNT = "Missing amount parameter"
ERROR_INVALID_AMOUNT_FORMAT = "Invalid amount format"
ERROR_AMOUNT_OUT_OF_RANGE = "Amount must be between {min} and {max} millisats"
ERROR_COMMENT_TOO_LONG = "Comment must be {max} characters or less"
ERROR_COMMENT_INVALID_CONTENT = "Comment contains prohibited content"
ERROR_INVOICE_CREATION_FAILED = "Failed to create invoice"
ERROR_INVALID_INVOICE_RESPONSE = "Invalid invoice response"
ERROR_TIMEOUT = "Request timed out"
ERROR_SERVICE_UNAVAILABLE = "Service temporarily unavailable"
ERROR_INTERNAL_ERROR = "Internal server error"
ERROR_UNKNOWN_ENDPOINT = "Unknown endpoint"

# Prohibited words/patterns in comments (basic filtering)
COMMENT_BLACKLIST = [
    r'https?://',  # URLs
    r'www\.',      # URLs without protocol
    r'@.*\.',      # Email addresses
]

# Username validation pattern (alphanumeric, underscore, hyphen, period)
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')

# Simple rate limiting - tracks request counts per IP
# Format: {ip_address: {'count': N, 'reset_time': timestamp}}
rate_limit_store = {}
rate_limit_lock = Lock()
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100  # requests per window

# Global statistics
stats = {
    'requests_total': 0,
    'requests_metadata': 0,
    'requests_callback': 0,
    'invoices_created': 0,
    'errors_total': 0,
    'rate_limited': 0,
    'start_time': None
}
stats_lock = Lock()

# Load configuration
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
    logger.info("Configuration loaded successfully")
except FileNotFoundError:
    logger.error(f"Config file not found: {CONFIG_PATH}")
    logger.info("Please copy config.json.example to config.json and configure it")
    sys.exit(1)
except json.JSONDecodeError as e:
    logger.error(f"Invalid JSON in config file: {e}")
    sys.exit(1)

# Validate configuration
def validate_config(cfg):
    """Validate configuration values"""
    errors = []
    
    # Validate server config
    server_port = cfg.get("server", {}).get("port")
    if not isinstance(server_port, int) or not (1 <= server_port <= 65535):
        errors.append("server.port must be an integer between 1 and 65535")
    
    # Validate LND config
    lnd_port = cfg.get("lnd", {}).get("port")
    if not isinstance(lnd_port, int) or not (1 <= lnd_port <= 65535):
        errors.append("lnd.port must be an integer between 1 and 65535")
    
    if not cfg.get("lnd", {}).get("onion_address"):
        errors.append("lnd.onion_address is required")
    
    macaroon_path = cfg.get("lnd", {}).get("macaroon_path", "")
    if macaroon_path and not os.path.exists(macaroon_path):
        errors.append(f"Macaroon file not found: {macaroon_path}")
    
    # Validate LNURL config
    min_sendable = cfg.get("lnurlp", {}).get("min_sendable")
    if not isinstance(min_sendable, int) or (isinstance(min_sendable, int) and min_sendable < 1):
        errors.append("lnurlp.min_sendable must be a positive integer")
    
    max_sendable = cfg.get("lnurlp", {}).get("max_sendable")
    if not isinstance(max_sendable, int) or (isinstance(max_sendable, int) and max_sendable < 1):
        errors.append("lnurlp.max_sendable must be a positive integer")
    
    # Only check min/max relationship if both are valid integers
    if isinstance(min_sendable, int) and isinstance(max_sendable, int):
        if min_sendable > max_sendable:
            errors.append("lnurlp.min_sendable cannot be greater than max_sendable")
    
    # Sanity check: warn about unusually high maximum amounts
    # 10 million sats = 10,000,000,000 millisats
    MAX_REASONABLE_AMOUNT = 10_000_000_000  # 10M sats in millisats
    if isinstance(max_sendable, int) and max_sendable > MAX_REASONABLE_AMOUNT:
        # This is a warning, not an error - log it but don't fail validation
        import warnings
        warnings.warn(
            f"max_sendable ({max_sendable} msat = {max_sendable//1000} sats) "
            f"is very high. Recommended maximum: {MAX_REASONABLE_AMOUNT//1000} sats. "
            "This could expose your node to liquidity issues.",
            UserWarning
        )
    
    comment_allowed = cfg.get("lnurlp", {}).get("comment_allowed")
    if not isinstance(comment_allowed, int) or not (0 <= comment_allowed <= 2000):
        errors.append("lnurlp.comment_allowed must be an integer between 0 and 2000")
    
    if not cfg.get("lnurlp", {}).get("domain"):
        errors.append("lnurlp.domain is required")
    
    return errors

validation_errors = validate_config(config)
if validation_errors:
    logger.error("Configuration validation failed:")
    for error in validation_errors:
        logger.error(f"  - {error}")
    sys.exit(1)

# Configure file logging now that we have the config
LOG_FILE = config["server"].get("log_file", "/var/log/lnurlp/lnurlp-server.log")
try:
    # Add file handler to existing logger
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    logger.info(f"Logging to {LOG_FILE}")
except PermissionError:
    logger.warning(f"Cannot write to {LOG_FILE}, using console logging only")
except Exception as e:
    logger.warning(f"Failed to configure file logging: {e}, using console logging only")

# Initialize configuration variables
LND_ONION = config["lnd"]["onion_address"]
LND_PORT = config["lnd"]["port"]
MACAROON_PATH = config["lnd"]["macaroon_path"]
INVOICE_EXPIRY = config["lnd"].get("invoice_expiry", 3600)
TOR_PROXY = config["tor"]["proxy"]
SERVER_HOST = config["server"]["host"]
SERVER_PORT = config["server"]["port"]
DOMAIN = config["lnurlp"]["domain"]
MIN_SENDABLE = config["lnurlp"]["min_sendable"]
MAX_SENDABLE = config["lnurlp"]["max_sendable"]
COMMENT_ALLOWED = config["lnurlp"]["comment_allowed"]
ALLOWS_NOSTR = config["lnurlp"]["allows_nostr"]
ALLOWED_USERNAMES = config["lnurlp"].get("allowed_usernames", [])
REQUIRE_VALID_USERNAME = config["lnurlp"].get("require_valid_username", False)
VERIFY_SSL = config["lnd"].get("verify_ssl", False)
RATE_LIMIT_FILE = config["server"].get("rate_limit_file", "rate_limits.json")
STATS_FILE = config["server"].get("stats_file", "stats.json")
STATS_SAVE_INTERVAL = config["server"].get("stats_save_interval", 300)
# Cache macaroon at startup
MACAROON_HEX = None

def load_macaroon():
    """Load and cache macaroon at startup (cross-platform)"""
    global MACAROON_HEX
    try:
        # Try to read macaroon file directly as binary and convert to hex
        with open(MACAROON_PATH, 'rb') as f:
            macaroon_bytes = f.read()
            MACAROON_HEX = macaroon_bytes.hex().upper()
        logger.info("Macaroon loaded and cached successfully")
        return True
    except FileNotFoundError:
        logger.error(f"Macaroon file not found: {MACAROON_PATH}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error loading macaroon: {e}")
        return False

def load_rate_limits():
    """Load rate limit data from file if it exists"""
    global rate_limit_store
    try:
        if os.path.exists(RATE_LIMIT_FILE):
            with open(RATE_LIMIT_FILE, 'r') as f:
                rate_limit_store = json.load(f)
            logger.info(f"Loaded rate limit data for {len(rate_limit_store)} IPs")
        else:
            logger.info("No existing rate limit file found, starting fresh")
    except Exception as e:
        logger.warning(f"Failed to load rate limits: {e}. Starting with empty rate limit store.")
        rate_limit_store = {}

def save_rate_limits():
    """Save rate limit data to file"""
    try:
        with rate_limit_lock:
            # Clean up expired entries before saving
            current_time = time.time()
            cleaned_store = {ip: data for ip, data in rate_limit_store.items() 
                           if current_time <= data['reset_time']}
            
            with open(RATE_LIMIT_FILE, 'w') as f:
                json.dump(cleaned_store, f, indent=2)
            logger.debug(f"Saved rate limit data for {len(cleaned_store)} IPs")
    except Exception as e:
        logger.error(f"Failed to save rate limits: {e}")

def load_stats():
    """Load statistics from file if it exists"""
    global stats
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                saved_stats = json.load(f)
            # Restore persisted stats but keep current start_time
            for key in ['requests_total', 'requests_metadata', 'requests_callback', 
                       'invoices_created', 'errors_total', 'rate_limited']:
                if key in saved_stats:
                    stats[key] = saved_stats[key]
            logger.info(f"Loaded statistics: {stats['invoices_created']} total invoices created")
        else:
            logger.info("No existing stats file found, starting fresh")
    except Exception as e:
        logger.warning(f"Failed to load stats: {e}. Starting with empty statistics.")

def save_stats():
    """Save statistics to file"""
    try:
        with stats_lock:
            # Don't save start_time as it should be fresh each startup
            stats_to_save = {k: v for k, v in stats.items() if k != 'start_time'}
            
            with open(STATS_FILE, 'w') as f:
                json.dump(stats_to_save, f, indent=2)
            logger.debug(f"Saved statistics: {stats['invoices_created']} total invoices")
    except Exception as e:
        logger.error(f"Failed to save stats: {e}")

def sanitize_username(username):
    """Validate and sanitize username"""
    if not username:
        return None
    
    # Trim whitespace
    username = username.strip()
    
    # Check length
    if len(username) > 100 or len(username) < 1:
        return None
    
    # Check against pattern
    if not USERNAME_PATTERN.match(username):
        return None
    
    # Check whitelist if enabled
    if REQUIRE_VALID_USERNAME and ALLOWED_USERNAMES:
        if username.lower() not in [u.lower() for u in ALLOWED_USERNAMES]:
            return None
    
    return username

def sanitize_comment(comment):
    """Validate and sanitize comment"""
    if not comment:
        return ""
    
    # Trim whitespace
    comment = comment.strip()
    
    # Check for prohibited patterns
    for pattern in COMMENT_BLACKLIST:
        if re.search(pattern, comment, re.IGNORECASE):
            return None
    
    return comment

def check_rate_limit(ip_address):
    """Check if IP address has exceeded rate limit"""
    current_time = time.time()
    
    with rate_limit_lock:
        # Clean up old entries
        expired_ips = [ip for ip, data in rate_limit_store.items() 
                      if current_time > data['reset_time']]
        for ip in expired_ips:
            del rate_limit_store[ip]
        
        # Check current IP
        if ip_address not in rate_limit_store:
            rate_limit_store[ip_address] = {
                'count': 1,
                'reset_time': current_time + RATE_LIMIT_WINDOW
            }
            return True
        
        ip_data = rate_limit_store[ip_address]
        
        # Reset window if expired
        if current_time > ip_data['reset_time']:
            rate_limit_store[ip_address] = {
                'count': 1,
                'reset_time': current_time + RATE_LIMIT_WINDOW
            }
            return True
        
        # Check limit
        if ip_data['count'] >= RATE_LIMIT_MAX_REQUESTS:
            return False
        
        # Increment counter
        ip_data['count'] += 1
        return True

def increment_stat(stat_name):
    """Thread-safe statistics increment"""
    with stats_lock:
        stats[stat_name] = stats.get(stat_name, 0) + 1

def check_directory_permissions():
    """Verify that the server can write to required directories and files"""
    errors = []
    
    # Check directories that need write access
    directories_to_check = []
    files_to_check = []
    
    # Add log file directory if configured
    if LOG_FILE:
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir:
            directories_to_check.append(("log directory", log_dir))
            files_to_check.append(("log file", LOG_FILE))
    
    # Add stats file directory
    if STATS_FILE:
        stats_dir = os.path.dirname(STATS_FILE)
        if stats_dir:
            directories_to_check.append(("stats directory", stats_dir))
            files_to_check.append(("stats file", STATS_FILE))
    
    # Add rate limit file directory
    if RATE_LIMIT_FILE:
        rate_limit_dir = os.path.dirname(RATE_LIMIT_FILE)
        if rate_limit_dir:
            directories_to_check.append(("rate limit directory", rate_limit_dir))
            files_to_check.append(("rate limit file", RATE_LIMIT_FILE))
    
    # Check if directories exist and are writable
    for name, directory in directories_to_check:
        if not directory:
            continue
            
        if not os.path.exists(directory):
            errors.append(f"{name} does not exist: {directory}")
            continue
            
        if not os.path.isdir(directory):
            errors.append(f"{name} is not a directory: {directory}")
            continue
            
        if not os.access(directory, os.W_OK):
            errors.append(f"No write permission for {name}: {directory}")
    
    # Try to write test files to verify actual write capability
    for name, filepath in files_to_check:
        if not filepath or errors:  # Skip if we already found directory errors
            continue
            
        # Try to create/update the file
        try:
            # If file exists, try to open it in append mode
            # If it doesn't exist, try to create it
            test_mode = 'a' if os.path.exists(filepath) else 'w'
            with open(filepath, test_mode) as f:
                pass  # Just test that we can open it
            
            # If we created a new file during the test, ensure proper permissions
            if test_mode == 'w' and os.path.exists(filepath):
                # Set readable by owner and group
                os.chmod(filepath, 0o644)
                
        except PermissionError as e:
            errors.append(f"Cannot write to {name}: {filepath} - {e}")
        except OSError as e:
            errors.append(f"Cannot access {name}: {filepath} - {e}")
        except Exception as e:
            errors.append(f"Error testing {name}: {filepath} - {e}")
    
    return errors

class Handler(BaseHTTPRequestHandler):

    protocol_version = "HTTP/1.1"

    def __init__(self, *args, **kwargs):
        self.request_id = str(uuid.uuid4())[:8]
        super().__init__(*args, **kwargs)

    def log_message(self, format, *args):
        """Override to use custom logger instead of stderr"""
        logger.info(f"[{self.request_id}] {self.address_string()} - {format % args}")

    def do_HEAD(self):
        # Respond with the same headers as GET, but no body
        if self.path.startswith("/.well-known/lnurlp/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
        else:
            self.send_error(404)

    def do_GET(self):
        increment_stat('requests_total')
        
        # Check rate limit
        client_ip = self.client_address[0]
        if not check_rate_limit(client_ip):
            logger.warning(f"[{self.request_id}] Rate limit exceeded for {client_ip}")
            increment_stat('rate_limited')
            self.respond_error("Rate limit exceeded. Please try again later.")
            return
        
        try:
            parsed = urllib.parse.urlparse(self.path)

            # Health check endpoint
            if parsed.path == "/health":
                uptime = 0
                if stats['start_time']:
                    uptime = (datetime.now() - stats['start_time']).total_seconds()
                
                # Create a copy of stats with datetime converted to timestamp
                stats_copy = stats.copy()
                if 'start_time' in stats_copy and stats_copy['start_time']:
                    stats_copy['start_time'] = stats_copy['start_time'].isoformat()
                
                health_data = {
                    "status": "healthy",
                    "uptime_seconds": uptime,
                    "stats": stats_copy
                }
                logger.debug(f"[{self.request_id}] Health check requested")
                self.respond(health_data)
                return

            # LNURLp metadata endpoint
            if parsed.path.startswith("/.well-known/lnurlp/"):
                increment_stat('requests_metadata')
                username = parsed.path.split("/")[-1]
                
                # Sanitize and validate username
                username = sanitize_username(username)
                if not username:
                    logger.warning(f"[{self.request_id}] Invalid username request")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_INVALID_USERNAME)
                    return
                
                callback = f"https://{DOMAIN}/lnurlp/callback"

                body = {
                    "status": "OK",
                    "tag": "payRequest",
                    "callback": callback,
                    "metadata": json.dumps([["text/plain", f"Payment to {username}@{DOMAIN}"]]),
                    "minSendable": MIN_SENDABLE,
                    "maxSendable": MAX_SENDABLE,
                    "allowsNostr": ALLOWS_NOSTR,
                    "commentAllowed": COMMENT_ALLOWED
                }

                logger.info(f"[{self.request_id}] LNURL metadata requested for user: {username}")
                self.respond(body)
                return

            # Invoice callback
            if parsed.path == "/lnurlp/callback":
                increment_stat('requests_callback')
                qs = urllib.parse.parse_qs(parsed.query)
                
                # Validate amount parameter
                if "amount" not in qs:
                    logger.warning(f"[{self.request_id}] Missing amount parameter in callback")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_MISSING_AMOUNT)
                    return
                
                try:
                    amount_msat = int(qs.get("amount", [0])[0])
                except (ValueError, IndexError):
                    logger.warning(f"[{self.request_id}] Invalid amount format: {qs.get('amount', [''])[0]}")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_INVALID_AMOUNT_FORMAT)
                    return
                
                # Validate amount range
                if amount_msat < MIN_SENDABLE or amount_msat > MAX_SENDABLE:
                    logger.warning(f"[{self.request_id}] Amount out of range: {amount_msat} msat")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_AMOUNT_OUT_OF_RANGE.format(min=MIN_SENDABLE, max=MAX_SENDABLE))
                    return
                
                amount_sat = amount_msat // 1000
                
                # Validate and sanitize comment
                comment = qs.get("comment", [""])[0]
                if len(comment) > COMMENT_ALLOWED:
                    logger.warning(f"[{self.request_id}] Comment too long: {len(comment)} chars")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_COMMENT_TOO_LONG.format(max=COMMENT_ALLOWED))
                    return
                
                # Sanitize comment content
                if comment:
                    sanitized_comment = sanitize_comment(comment)
                    if sanitized_comment is None:
                        logger.warning(f"[{self.request_id}] Comment contains prohibited content")
                        increment_stat('errors_total')
                        self.respond_error(ERROR_COMMENT_INVALID_CONTENT)
                        return
                    comment = sanitized_comment

                # Create invoice via LND
                try:
                    logger.info(f"[{self.request_id}] Creating invoice for {amount_sat} sats")
                    
                    # Warn if SSL verification is disabled
                    if not VERIFY_SSL:
                        logger.debug(f"[{self.request_id}] SSL verification disabled for LND connection")
                    
                    response = requests.post(
                        f"https://{LND_ONION}:{LND_PORT}/v1/invoices",
                        headers={"Grpc-Metadata-macaroon": MACAROON_HEX},
                        json={
                            "value": amount_sat,
                            "memo": comment,
                            "expiry": INVOICE_EXPIRY
                        },
                        proxies={"https": TOR_PROXY},
                        verify=VERIFY_SSL,
                        timeout=30
                    )
                    
                    if response.status_code != 200:
                        logger.error(f"[{self.request_id}] LND returned error: {response.status_code} - {response.text}")
                        increment_stat('errors_total')
                        self.respond_error(ERROR_INVOICE_CREATION_FAILED)
                        return
                    
                    invoice = response.json()
                    
                    if "payment_request" not in invoice:
                        logger.error(f"[{self.request_id}] Invalid LND response: {invoice}")
                        increment_stat('errors_total')
                        self.respond_error(ERROR_INVALID_INVOICE_RESPONSE)
                        return
                    
                    increment_stat('invoices_created')
                    logger.info(f"[{self.request_id}] Invoice created successfully for {amount_sat} sats")
                    self.respond({"pr": invoice["payment_request"], "routes": []})
                    
                except requests.exceptions.Timeout:
                    logger.error(f"[{self.request_id}] LND request timed out")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_TIMEOUT)
                    
                except requests.exceptions.ConnectionError as e:
                    logger.error(f"[{self.request_id}] Failed to connect to LND: {e}")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_SERVICE_UNAVAILABLE)
                    
                except requests.exceptions.RequestException as e:
                    logger.error(f"[{self.request_id}] LND request failed: {e}")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_INVOICE_CREATION_FAILED)
                    
                except Exception as e:
                    logger.error(f"[{self.request_id}] Unexpected error creating invoice: {e}")
                    increment_stat('errors_total')
                    self.respond_error(ERROR_INTERNAL_ERROR)
                
                return

            logger.warning(f"[{self.request_id}] Unknown endpoint requested: {parsed.path}")
            increment_stat('errors_total')
            self.respond_error(ERROR_UNKNOWN_ENDPOINT)
            
        except Exception as e:
            logger.error(f"[{self.request_id}] Unhandled error in do_GET: {e}", exc_info=True)
            increment_stat('errors_total')
            try:
                self.respond_error(ERROR_INTERNAL_ERROR)
            except:
                pass  # Already in error state, can't do much more

    def respond(self, body):
        """Send successful JSON response"""
        try:
            response_body = json.dumps(body).encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(response_body)
        except Exception as e:
            logger.error(f"[{self.request_id}] Error writing response: {e}")
    
    def respond_error(self, reason):
        """Respond with LNURL error format"""
        try:
            body = {"status": "ERROR", "reason": reason}
            response_body = json.dumps(body).encode('utf-8')
            self.send_response(200)  # LNURL errors still use 200 status
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self.wfile.write(response_body)
        except Exception as e:
            logger.error(f"[{self.request_id}] Error writing error response: {e}")

# Global server instance
server = None

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    logger.info(f"Received signal {sig}, shutting down gracefully...")
    # Save final state before shutdown
    save_stats()
    save_rate_limits()
    # Call shutdown from a different thread to avoid deadlock
    import threading
    def shutdown_server():
        if server:
            server.shutdown()
    shutdown_thread = threading.Thread(target=shutdown_server)
    shutdown_thread.start()
    shutdown_thread.join(timeout=5)
    logger.info("Server shutdown complete")
    sys.exit(0)

if __name__ == "__main__":
    # Load macaroon at startup
    if not load_macaroon():
        logger.error("Failed to load macaroon, exiting")
        sys.exit(1)
    
    # Check directory permissions before starting server
    permission_errors = check_directory_permissions()
    if permission_errors:
        logger.error("Directory permission check failed:")
        for error in permission_errors:
            logger.error(f"  - {error}")
        logger.error("")
        logger.error("Fix permissions with these commands:")
        if STATS_FILE or RATE_LIMIT_FILE:
            data_dir = os.path.dirname(STATS_FILE or RATE_LIMIT_FILE)
            if data_dir:
                logger.error(f"  sudo chown $(whoami):$(whoami) {data_dir}")
                logger.error(f"  sudo chmod 755 {data_dir}")
        if LOG_FILE:
            log_dir = os.path.dirname(LOG_FILE)
            if log_dir:
                logger.error(f"  sudo chown $(whoami):$(whoami) {log_dir}")
                logger.error(f"  sudo chmod 755 {log_dir}")
        sys.exit(1)
    
    logger.info("Directory permissions verified successfully")
    
    # Load persisted data
    load_rate_limits()
    load_stats()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Record start time
    stats['start_time'] = datetime.now()
    
    # Log SSL verification warning if disabled
    if not VERIFY_SSL:
        if '.onion' in LND_ONION:
            logger.info("SSL certificate verification disabled for .onion address")
            logger.info("This is safe - Tor provides end-to-end encryption and authentication")
            # Suppress urllib3 InsecureRequestWarning for .onion addresses
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            logger.warning("SSL certificate verification is DISABLED for clearnet LND connection!")
            logger.warning("This is UNSAFE and exposes you to MITM attacks!")
            logger.warning("Enable 'verify_ssl: true' in config.json immediately")
    
    logger.info(f"Starting LNURL-pay server on {SERVER_HOST}:{SERVER_PORT}")
    logger.info(f"Domain: {DOMAIN}")
    logger.info(f"Amount range: {MIN_SENDABLE}-{MAX_SENDABLE} msat ({MIN_SENDABLE//1000}-{MAX_SENDABLE//1000} sats)")
    logger.info(f"Comment max length: {COMMENT_ALLOWED} characters")
    if REQUIRE_VALID_USERNAME and ALLOWED_USERNAMES:
        logger.info(f"Username whitelist enabled: {', '.join(ALLOWED_USERNAMES)}")
    else:
        logger.info("Username whitelist: disabled (all usernames accepted)")
    logger.info(f"Health check available at: http://{SERVER_HOST}:{SERVER_PORT}/health")
    logger.info(f"Stats and rate limits will be saved every {STATS_SAVE_INTERVAL} seconds")
    
    # Start periodic stats and rate limit saving in background
    import threading
    def periodic_save():
        while True:
            time.sleep(STATS_SAVE_INTERVAL)
            save_stats()
            save_rate_limits()
    
    save_thread = threading.Thread(target=periodic_save, daemon=True)
    save_thread.start()
    
    try:
        server = HTTPServer((SERVER_HOST, SERVER_PORT), Handler)
        logger.info("Server started successfully")
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        raise
    finally:
        # Save final state before shutdown (if not already saved by signal handler)
        try:
            save_stats()
            save_rate_limits()
        except:
            pass  # May have already been saved
        if server:
            try:
                server.server_close()
            except:
                pass
        logger.info("Shutdown complete")
