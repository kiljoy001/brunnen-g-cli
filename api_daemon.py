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
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

API_PORT = 8080
DB_DIR = os.environ.get('BRUNNEN_DB_DIR', '/var/lib/brunnen')
DB_NAME = os.path.join(DB_DIR, f"{hashlib.sha256((os.uname().nodename + getpass.getuser()).encode()).hexdigest()[:12]}.db")
LOG_FILE = "/var/log/brunnen_api.log"
MAX_PAYLOAD_SIZE = 1048576  # 1MB
ADDRESS_REGEX = re.compile(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.coin$')

# Ensure DB directory exists
os.makedirs(DB_DIR, exist_ok=True)

# Setup logging with fallback
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE, mode='a'),
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
    
    @staticmethod
    def setup_database_once():
        with sqlite3.connect(DB_NAME) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    app_name TEXT PRIMARY KEY,
                    api_key_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    permissions TEXT DEFAULT 'read',
                    rate_limit INTEGER DEFAULT 60,
                    created_at INTEGER,
                    last_used INTEGER
                );
                
                CREATE TABLE IF NOT EXISTS api_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT,
                    timestamp INTEGER,
                    app_name TEXT,
                    endpoint TEXT,
                    method TEXT,
                    status_code INTEGER,
                    ip_address TEXT
                );
                
                CREATE TABLE IF NOT EXISTS address_keys (
                    address TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    created_at INTEGER
                );
            """)
            conn.commit()
    
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
    
    def log_request(self, request_id, app_name, endpoint, method, status_code):
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
        
        # Configurable CORS
        allowed_origin = os.environ.get('CORS_ORIGIN', 'http://localhost:3000')
        self.send_header('Access-Control-Allow-Origin', allowed_origin)
        
        self.end_headers()
        self.wfile.write(response.encode())
    
    def validate_address(self, address):
        return bool(ADDRESS_REGEX.match(address))
    
    def validate_username_domain(self, username, domain):
        # Only alphanumeric, dots, dashes, underscores
        pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
        return pattern.match(username) and pattern.match(domain)
    
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
    
    def register_identity(self, username, domain):
        if not username or not domain:
            return {"status": "error", "message": "Missing username or domain"}
        
        if not self.validate_username_domain(username, domain):
            return {"status": "error", "message": "Invalid characters in username or domain"}
        
        address = f"{username}@{domain}"
        if not self.validate_address(address):
            return {"status": "error", "message": "Invalid address format"}
        
        try:
            # Use absolute path for security
            script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tpm/tpm_provisioning.sh'))
            
            result = subprocess.run(
                [script_path], 
                check=True,
                timeout=30,
                capture_output=True,
                text=True,
                env={**os.environ, 'USER': username, 'DOMAIN': domain}  # Pass as env vars
            )
            
            # Extract pubkey from result (implement based on script output)
            pubkey = result.stdout.strip()  # Adjust based on actual output
            
            # Store in database
            with sqlite3.connect(DB_NAME) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO address_keys (address, pubkey, created_at) 
                    VALUES (?, ?, ?)
                """, (address, pubkey, int(time.time())))
            
            return {"status": "success", "address": address}
            
        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "TPM provisioning timeout"}
        except subprocess.CalledProcessError as e:
            logging.error(f"TPM script failed: {e}")
            return {"status": "error", "message": "TPM provisioning failed"}
    
    def do_GET(self):
        request_id = str(uuid.uuid4())
        parsed = urlparse(self.path)

        # Extract API key
        api_key = self.headers.get('X-API-Key')
        app_name, permissions, rate_limit = self.authenticate_app(api_key)

        # App-specific rate limiting
        if app_name and not self.rate_limiter.allow_request(app_name, rate_limit):
            self.send_error_response(429, "rate_limit_exceeded", 
                                   f"Rate limit of {rate_limit} requests/minute exceeded")
            self.log_request(request_id, app_name, parsed.path, 'GET', 429)
            return

        # API versioning
        if parsed.path.startswith('/api/v1/'):
            endpoint = parsed.path[8:]  # Remove /api/v1/

            if endpoint == 'query':
                if not self.check_permission(permissions, 'read'):
                    self.send_error_response(403, "insufficient_permissions", 
                                           "Read permission required")
                    self.log_request(request_id, app_name, parsed.path, 'GET', 403)
                    return

                params = parse_qs(parsed.query)
                address = params.get('address', [''])[0]

                if not self.validate_address(address):
                    self.send_error_response(400, "invalid_address", 
                                           "Address must match pattern user@domain.coin")
                    self.log_request(request_id, app_name, parsed.path, 'GET', 400)
                    return

                result = self.query_user(address)
                status = 200 if result.get('status') == 'success' else 404
                self.send_json_response(status, result, request_id)
                self.log_request(request_id, app_name, parsed.path, 'GET', status)

            elif endpoint == 'health':
                # Public endpoint, no auth required
                self.send_json_response(200, {
                    "status": "healthy", 
                    "version": "1.0.0",
                    "timestamp": int(time.time())
                }, request_id)
                self.log_request(request_id, None, parsed.path, 'GET', 200)

            elif endpoint == 'metrics' and self.check_permission(permissions, 'admin'):
                # Admin-only endpoint for monitoring
                with sqlite3.connect(DB_NAME) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT COUNT(*) as total_requests,
                               COUNT(DISTINCT app_name) as unique_apps,
                               COUNT(DISTINCT ip_address) as unique_ips
                        FROM api_logs
                        WHERE timestamp > ?
                    """, (int(time.time()) - 3600,))  # Last hour
                    metrics = cursor.fetchone()

                self.send_json_response(200, {
                    "requests_last_hour": metrics[0],
                    "active_apps": metrics[1],
                    "unique_ips": metrics[2]
                }, request_id)
                self.log_request(request_id, app_name, parsed.path, 'GET', 200)

            else:
                self.send_error_response(404, "endpoint_not_found", 
                                       f"Endpoint {endpoint} not found")
                self.log_request(request_id, app_name, parsed.path, 'GET', 404)

        elif parsed.path == '/':
            # Serve documentation or web interface
            try:
                html_path = os.path.join(os.path.dirname(__file__), 'web', 'brunnen-g.html')
                with open(html_path, 'r') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content.encode())
            except FileNotFoundError:
                self.send_error_response(404, "web_interface_not_found", 
                                       "Web interface not available")
            self.log_request(request_id, None, parsed.path, 'GET', 200)

        else:
            self.send_error_response(404, "invalid_version", 
                                   "Use /api/v1/ for API access")
            self.log_request(request_id, app_name, parsed.path, 'GET', 404)

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
        self.log_request(request_id, app_name, parsed.path, 'POST', 429)
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
    
    if parsed.path == '/api/v1/register':
        if not self.check_permission(permissions, 'write'):
            self.send_error_response(403, "insufficient_permissions", 
                                   "Write permission required")
            self.log_request(request_id, app_name, parsed.path, 'POST', 403)
            return
        
        result = self.register_identity(data.get('username'), data.get('domain'))
        status = 200 if result['status'] == 'success' else 400
        self.send_json_response(status, result, request_id)
        self.log_request(request_id, app_name, parsed.path, 'POST', status)
        
    elif parsed.path == '/api/v1/sign':
        if not self.check_permission(permissions, 'write'):
            self.send_error_response(403, "insufficient_permissions", 
                                   "Write permission required")
            self.log_request(request_id, app_name, parsed.path, 'POST', 403)
            return
        
        signer = data.get('signer')
        payload = data.get('data')
        
        if not signer or not payload:
            self.send_error_response(400, "missing_fields", 
                                   "signer and data fields required")
            return
        
        # Call signing logic (to be implemented)
        result = {"status": "error", "message": "Signing not yet implemented"}
        self.send_json_response(501, result, request_id)
        self.log_request(request_id, app_name, parsed.path, 'POST', 501)
        
    elif parsed.path == '/api/v1/admin/keys' and self.check_permission(permissions, 'admin'):
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
                                   
        self.log_request(request_id, app_name, parsed.path, 'POST', 200)
        
    else:
        self.send_error_response(404, "endpoint_not_found", 
                               f"Endpoint {parsed.path} not found")
        self.log_request(request_id, app_name, parsed.path, 'POST', 404)

def do_OPTIONS(self):
    """Handle CORS preflight requests"""
    self.send_response(200)
    self.send_header('Access-Control-Allow-Origin', 
                     os.environ.get('CORS_ORIGIN', 'http://localhost:3000'))
    self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    self.send_header('Access-Control-Allow-Headers', 'X-API-Key, Content-Type, X-Request-ID')
    self.send_header('Access-Control-Max-Age', '86400')
    self.end_headers()

def generate_api_key():
    """Generate secure API key with salt"""
    api_key = os.urandom(32).hex()
    salt = os.urandom(16).hex()
    key_hash = hashlib.pbkdf2_hmac('sha256', api_key.encode(), salt.encode(), 100000).hex()
    return api_key, salt, key_hash

def main():
    APIHandler.setup_database_once()
    
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