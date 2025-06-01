#!/usr/bin/env python3
"""
Brunnen-G API Daemon - Fixed Version
"""
import os
import json
import hashlib
import hmac
import subprocess
import sqlite3
import time
import logging
import uuid
import re
import getpass
import glob
import sys, shutil
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from systemd.journal import JournalHandler

API_PORT = 8080
DB_DIR = os.environ.get('BRUNNEN_DB_DIR', './data')
DB_FILES = glob.glob(os.path.join(DB_DIR, "*.db"))
if not DB_FILES:
    logging.error("No database found. Run shell script first.")
    sys.exit(1)
DB_NAME = DB_FILES[0]
LOG_FILE = "/var/log/brunnen_api.log"
MAX_PAYLOAD_SIZE = 1048576  # 1MB
ADDRESS_REGEX = re.compile(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.(coin|emc|lib|bazar)$')

class SecurityError(Exception): pass

def secure_subprocess(cmd_list, timeout=10, env_vars=None):
    """Secure subprocess execution with validation"""
    # Validate command exists and is executable
    cmd_path = shutil.which(cmd_list[0])
    if not cmd_path:
        raise SecurityError(f"Command not found: {cmd_list[0]}")
    
    # Use explicit environment
    safe_env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    if env_vars:
        safe_env.update(env_vars)
    
    return subprocess.run(
        [cmd_path] + cmd_list[1:],
        timeout=timeout,
        env=safe_env,
        capture_output=True,
        text=True,
        check=True
    )

def validate_inputs(data):
    """Comprehensive input validation"""
    if not isinstance(data, dict):
        raise ValueError("Data must be dictionary")
    
    for key, value in data.items():
        if not isinstance(key, str) or len(key) > 50:
            raise ValueError(f"Invalid key: {key}")
        
        if isinstance(value, str):
            if len(value) > 1024:
                raise ValueError(f"Value too long for {key}")
            # Check for injection patterns
            if re.search(r'[;&|`$()]', value):
                raise ValueError(f"Invalid characters in {key}")

def decrypt_tpm_metadata():
    """Decrypt TPM metadata if encrypted"""
    if not os.path.exists("/tpmdata/provisioning.enc"):
        return  # Not encrypted or doesn't exist
    
    if not os.path.exists("/tpmdata/.challenge"):
        raise Exception("Challenge file missing")
    
    with open("/tpmdata/.challenge", 'r') as f:
        challenge = f.read().strip()
    
    # Call YubiKey for decryption
    result = secure_subprocess(['ykchalresp', '-2', '-x', challenge], 
                          capture_output=True, text=True, check=True)
    aes_key = result.stdout.strip()
    
    # Decrypt metadata
    secure_subprocess([
        'openssl', 'enc', '-aes-256-cbc', '-d',
        '-in', '/tpmdata/provisioning.enc',
        '-out', '/tpmdata/provisioning.json',
        '-k', aes_key
    ], check=True)

# Authenticaion required decorator
def require_auth(permissions=None):
    def decorator(func):
        def wrapper(self, *args, **kwargs):
            api_key = self.headers.get('X-API-Key')
            app_name, user_perms, rate_limit = self.authenticate_app(api_key)
            
            if not app_name:
                self.send_error_response(401, "unauthorized", "Invalid API key")
                return
            
            if permissions and not self.check_permission(user_perms, permissions):
                self.send_error_response(403, "forbidden", f"{permissions} permission required")
                return
            
            return func(self, app_name, *args, **kwargs)
        return wrapper
    return decorator

# Ensure DB directory exists
os.makedirs(DB_DIR, exist_ok=True)

# Setup logging with fallback
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            JournalHandler(SYSLOG_IDENTIFIER='brunnen-api'),
            logging.StreamHandler()
        ]
    )
except Exception as e:
    logging.basicConfig(level=logging.INFO)
    logging.warning(f"Could not create log file: {e}")

class RateLimiter:
    def __init__(self, max_requests=60, window=60):
        self.requests = {}
        self.max_requests = max_requests
        self.window = window
        self.last_cleanup = time.time()
    
    def allow_request(self, key, limit=None):
        now = time.time()
        
        # Periodic cleanup every 5 minutes
        if now - self.last_cleanup > 300:
            self.clean_old_entries()
            self.last_cleanup = now
        
        if key not in self.requests:
            self.requests[key] = []
        
        self.requests[key] = [t for t in self.requests[key] if now - t < self.window]
        
        max_allowed = limit or self.max_requests
        if len(self.requests[key]) >= max_allowed:
            return False
        
        self.requests[key].append(now)
        return True
    
    def clean_old_entries(self):
        now = time.time()
        for key in list(self.requests.keys()):
            self.requests[key] = [t for t in self.requests[key] if now - t < self.window]
            if not self.requests[key]:
                del self.requests[key]

class APIHandler(BaseHTTPRequestHandler):
    rate_limiter = RateLimiter()

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', 
                         os.environ.get('CORS_ORIGIN', 'http://localhost:3000'))
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-API-Key, Content-Type, X-Request-ID')
        self.send_header('Access-Control-Max-Age', '86400')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()

    def authenticate_app(self, api_key):
        if not api_key:
            return None, None, None
        
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT app_name, api_key_hash, salt, permissions, rate_limit 
                FROM api_keys
            """)
            
            for row in cursor:
                app_name, stored_hash, salt, permissions, rate_limit = row
                # Constant-time comparison
                test_hash = hashlib.pbkdf2_hmac('sha256', api_key.encode(), salt.encode(), 100000).hex()
                if hmac.compare_digest(test_hash, stored_hash):
                    # Update last_used
                    cursor.execute("""
                        UPDATE api_keys 
                        SET last_used = ? 
                        WHERE app_name = ?
                    """, (int(time.time()), app_name))
                    conn.commit()
                    return app_name, permissions, rate_limit
            
            return None, None, None
    
    def check_permission(self, permissions, required):
        if not permissions:
            return False
        perms = (permissions or '').split(',')
        return required in perms or 'admin' in perms
    
    def sanitize_log_input(self, text):
        # Remove newlines and control characters
        return re.sub(r'[\x00-\x1f\x7f-\x9f\n\r]', '', str(text))[:100]
    
    def log_api_request(self, request_id, app_name, endpoint, method, status_code):
        with sqlite3.connect(DB_NAME) as conn:
            conn.execute("""
                INSERT INTO api_logs 
                (request_id, timestamp, app_name, endpoint, method, status_code, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id,
                int(time.time()),
                app_name or 'anonymous',
                self.sanitize_log_input(endpoint),
                method,
                status_code,
                self.client_address[0]
            ))
    
    def send_error_response(self, code, error_type, detail):
        request_id = self.headers.get('X-Request-ID', str(uuid.uuid4()))
        error = {
            "type": f"/errors/{error_type}",
            "title": self.responses.get(code, ['Unknown'])[0],
            "status": code,
            "detail": detail,
            "instance": f"/logs/{request_id}"
        }
        self.send_json_response(code, error, request_id)
    
    def send_json_response(self, code, data, request_id=None):
        response = json.dumps(data)
        
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response)))
        self.send_header('X-Request-ID', request_id or str(uuid.uuid4()))
        self.send_header('X-Content-Type-Options', 'nosniff') 
        self.send_header('X-Frame-Options', 'DENY')  

        # Configurable CORS
        allowed_origin = os.environ.get('CORS_ORIGIN', 'http://localhost:3000')
        self.send_header('Access-Control-Allow-Origin', allowed_origin)
        
        self.end_headers()
        self.wfile.write(response.encode())
    
    def validate_address(self, address):
        return bool(ADDRESS_REGEX.match(address))
    
    def query_user(self, address):
        try:
            with sqlite3.connect(DB_NAME) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT pubkey FROM address_keys WHERE address = ?", (address,))
                result = cursor.fetchone()
                
                if result:
                    return {"status": "success", "address": address, "pubkey": result[0]}
                else:
                    return {"status": "error", "message": "User not found"}
        except Exception as e:
            logging.error(f"Database error: {e}")
            return {"status": "error", "message": "Internal server error"}
    
    @require_auth('read')
    def handle_query(self, app_name, parsed, request_id):
        params = parse_qs(parsed.query)
        address = params.get('address', [''])[0]

        if not self.validate_address(address):
            self.send_error_response(400, "invalid_address", "Invalid address format")
            return

        result = self.query_user(address)
        status = 200 if result.get('status') == 'success' else 404
        self.send_json_response(status, result, request_id)

    @require_auth('admin') 
    def handle_metrics(self, app_name, request_id):
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) as total_requests,
                       COUNT(DISTINCT app_name) as unique_apps,
                       COUNT(DISTINCT ip_address) as unique_ips
                FROM api_logs WHERE timestamp > ?
            """, (int(time.time()) - 3600,))
            metrics = cursor.fetchone()

        self.send_json_response(200, {
            "requests_last_hour": metrics[0],
            "active_apps": metrics[1], 
            "unique_ips": metrics[2]
        }, request_id)

    def handle_health(self, request_id):
        # Public endpoint
        self.send_json_response(200, {
            "status": "healthy",
            "version": "1.0.0", 
            "timestamp": int(time.time())
        }, request_id)

    def do_GET(self):
        request_id = str(uuid.uuid4())
        parsed = urlparse(self.path)

        if parsed.path.startswith('/api/v1/'):
            endpoint = parsed.path[8:]

            if endpoint == 'query':
                self.handle_query(parsed, request_id)
            elif parsed.path == '/':
                try:
                    html_path = os.path.join(os.path.dirname(__file__), 'web', 'brunnen-g.html')
                    with open(html_path, 'r') as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html')
                    self.send_header('Content-Length', str(len(content)))
                    self.end_headers()
                    self.wfile.write(content.encode())
                    self.log_api_request(request_id, None, parsed.path, 'GET', 200)
                except FileNotFoundError:
                    self.send_error_response(404, "web_interface_not_found", "Web interface not available")
            elif endpoint == 'health':
                self.handle_health(request_id)
            elif endpoint == 'metrics':
                self.handle_metrics(request_id)
            else:
                self.send_error_response(404, "endpoint_not_found", f"Endpoint {endpoint} not found")

    def do_POST(self):
        request_id = str(uuid.uuid4())
        parsed = urlparse(self.path)

        # Size limit
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_PAYLOAD_SIZE:
            self.send_error_response(413, "payload_too_large", 
                               f"Maximum payload size is {MAX_PAYLOAD_SIZE} bytes")
            return
    
        # Extract API key
        api_key = self.headers.get('X-API-Key')
        app_name, permissions, rate_limit = self.authenticate_app(api_key)

        # Rate limiting
        if app_name and not self.rate_limiter.allow_request(app_name, rate_limit):
            self.send_error_response(429, "rate_limit_exceeded", 
                                   f"Rate limit of {rate_limit} requests/minute exceeded")
            self.log_api_request(request_id, app_name, parsed.path, 'POST', 429)
            return

        # Read and parse body
        body = self.rfile.read(content_length).decode()

        try:
            data = json.loads(body) if body else {}

            # Input length validation
            for key, value in data.items():
                if isinstance(value, str) and len(value) > 1024:
                    self.send_error_response(400, "field_too_long", 
                                           f"Field {key} exceeds maximum length of 1024")
                    return

        except json.JSONDecodeError:
            self.send_error_response(400, "invalid_json", "Request body must be valid JSON")
            return
        if parsed.path == '/api/v1/admin/keys' and self.check_permission(permissions, 'admin'):
            # Admin endpoint to manage API keys
            action = data.get('action')

            if action == 'create':
                new_app_name = data.get('app_name')
                new_permissions = data.get('permissions', 'read')

                if not new_app_name:
                    self.send_error_response(400, "missing_app_name", 
                                           "app_name required")
                    return

                api_key, salt, key_hash = generate_api_key()

                try:
                    with sqlite3.connect(DB_NAME) as conn:
                        conn.execute("""
                            INSERT INTO api_keys 
                            (app_name, api_key_hash, salt, permissions, created_at)
                            VALUES (?, ?, ?, ?, ?)
                        """, (new_app_name, key_hash, salt, new_permissions, int(time.time())))

                    self.send_json_response(200, {
                        "status": "success",
                        "app_name": new_app_name,
                        "api_key": api_key,
                        "message": "Save this key - it cannot be retrieved later"
                    }, request_id)
                except sqlite3.IntegrityError:
                    self.send_error_response(409, "app_exists", 
                                           "App name already exists")

            elif action == 'revoke':
                revoke_app_name = data.get('app_name')

                with sqlite3.connect(DB_NAME) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM api_keys WHERE app_name = ?", 
                                 (revoke_app_name,))

                    if cursor.rowcount > 0:
                        self.send_json_response(200, {
                            "status": "success",
                            "message": f"Revoked key for {revoke_app_name}"
                        }, request_id)
                    else:
                        self.send_error_response(404, "app_not_found", 
                                               "App name not found")
            else:
                self.send_error_response(400, "invalid_action", 
                                       "action must be 'create' or 'revoke'")

            self.log_api_request(request_id, app_name, parsed.path, 'POST', 200)

        else:
            self.send_error_response(404, "endpoint_not_found", 
                                   f"Endpoint {parsed.path} not found")
            self.log_api_request(request_id, app_name, parsed.path, 'POST', 404)


def generate_api_key():
    """Generate secure API key with salt"""
    api_key = os.urandom(32).hex()
    salt = os.urandom(16).hex()
    key_hash = hashlib.pbkdf2_hmac('sha256', api_key.encode(), salt.encode(), 100000).hex()
    return api_key, salt, key_hash

def main():
    print(f"Starting Brunnen-G API daemon on port {API_PORT}")
    print("API Version: 1.0.0")
    print(f"Database: {DB_NAME}")
    print(f"Logs: {LOG_FILE}")
    
    server = HTTPServer(('', API_PORT), APIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down API daemon")
        server.shutdown()

if __name__ == '__main__':
    main()