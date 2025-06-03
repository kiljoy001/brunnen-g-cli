#!/usr/bin/env python3
"""
wazuh_monitor.py - Wazuh SIEM integration for Brunnen-G
"""

import json
import socket
import sys
import time
from datetime import datetime

WAZUH_SOCKET = "/var/ossec/queue/ossec/queue"

class WazuhMonitor:
    def __init__(self):
        self.enabled = self.check_enabled()
    
    def check_enabled(self):
        """Check if monitoring is enabled"""
        try:
            with open('/etc/brunnen-g/monitoring.conf', 'r') as f:
                config = json.load(f)
                return config.get('wazuh_enabled', False)
        except:
            return False
    
    def send_event(self, event_type, data):
        """Send event to Wazuh"""
        if not self.enabled:
            return
        
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'rule': {
                'level': 3,
                'description': f'Brunnen-G: {event_type}'
            },
            'agent': {'name': 'brunnen-g'},
            'data': data
        }
        
        # Format for Wazuh
        wazuh_msg = f"1:brunnen-g:{json.dumps(event)}"
        
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.sendto(wazuh_msg.encode(), WAZUH_SOCKET)
            sock.close()
        except Exception as e:
            print(f"Failed to send to Wazuh: {e}", file=sys.stderr)
    
    def log_identity_operation(self, operation, address, success=True):
        """Log identity operations"""
        self.send_event('identity_operation', {
            'operation': operation,
            'address': address,
            'success': success,
            'timestamp': int(time.time())
        })
    
    def log_api_access(self, endpoint, source_ip, status_code):
        """Log API access"""
        self.send_event('api_access', {
            'endpoint': endpoint,
            'source_ip': source_ip,
            'status_code': status_code,
            'timestamp': int(time.time())
        })
    
    def log_tpm_operation(self, operation, handle=None, success=True):
        """Log TPM operations"""
        self.send_event('tpm_operation', {
            'operation': operation,
            'handle': handle,
            'success': success,
            'timestamp': int(time.time())
        })
    
    def enable(self):
        """Enable Wazuh monitoring"""
        config = {'wazuh_enabled': True}
        try:
            import os
            os.makedirs('/etc/brunnen-g', exist_ok=True)
            with open('/etc/brunnen-g/monitoring.conf', 'w') as f:
                json.dump(config, f)
            self.enabled = True
            self.send_event('monitoring_enabled', {'timestamp': int(time.time())})
            return True
        except Exception as e:
            print(f"Failed to enable monitoring: {e}")
            return False
    
    def disable(self):
        """Disable Wazuh monitoring"""
        self.send_event('monitoring_disabled', {'timestamp': int(time.time())})
        config = {'wazuh_enabled': False}
        try:
            with open('/etc/brunnen-g/monitoring.conf', 'w') as f:
                json.dump(config, f)
            self.enabled = False
            return True
        except Exception as e:
            print(f"Failed to disable monitoring: {e}")
            return False
    
    def status(self):
        """Check monitoring status"""
        print(f"Wazuh monitoring: {'Enabled' if self.enabled else 'Disabled'}")
        
        # Check socket
        if os.path.exists(WAZUH_SOCKET):
            print(f"Wazuh socket: Available")
        else:
            print(f"Wazuh socket: Not found")
        
        # Check config
        if os.path.exists('/etc/brunnen-g/monitoring.conf'):
            print("Config file: Present")
        else:
            print("Config file: Missing")
    
    def test(self):
        """Send test event"""
        self.send_event('test_event', {
            'message': 'Brunnen-G monitoring test',
            'timestamp': int(time.time())
        })
        print("Test event sent")
        return True

if __name__ == '__main__':
    monitor = WazuhMonitor()
    
    if len(sys.argv) < 2:
        print("Usage: wazuh_monitor.py [enable|disable|status|test]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'enable':
        if monitor.enable():
            print("Monitoring enabled")
        else:
            print("Failed to enable monitoring")
            sys.exit(1)
    
    elif command == 'disable':
        if monitor.disable():
            print("Monitoring disabled")
        else:
            print("Failed to disable monitoring")
            sys.exit(1)
    
    elif command == 'status':
        monitor.status()
    
    elif command == 'test':
        monitor.test()
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)