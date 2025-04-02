import os
import sys
import time
import json
import logging
import hashlib
import threading
import sqlite3
import platform
import hmac
import base64
import ssl
import argparse
import subprocess
import socket
import re
import uuid
import zipfile
from datetime import datetime, timedelta

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cybersecurity_toolkit.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

try:
    # Extensive library imports
    import numpy as np
    import pandas as pd
    import psutil
    import requests
    import scapy.all as scapy
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    # Machine Learning and Data Processing
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.svm import OneClassSVM
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import silhouette_score

    # Cryptography and Security
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
except ImportError as e:
    logging.error(f"Failed to import required libraries: {e}")
    logging.error("Please install required packages using: pip install numpy pandas psutil requests scapy scikit-learn cryptography")
    sys.exit(1)

class CyberSecurityToolkit:
    def __init__(self, config_path='config.json', debug_mode=False):
        # Core initialization
        self.debug_mode = debug_mode
        self.os_type = platform.system()
        self.unique_device_id = str(uuid.uuid4())
        self.running = True  # Flag for continuous monitoring
        
        # Default configuration
        self.default_config = {
            "device_id": self.unique_device_id,
            "security_level": "moderate",
            "monitoring_intervals": {
                "system_scan": 60,      # 1 minute
                "network_scan": 300,    # 5 minutes
                "threat_analysis": 600  # 10 minutes
            },
            "alert_thresholds": {
                "cpu_usage": 80,
                "memory_usage": 85,
                "network_connections": 100
            },
            "email_alerts": {
                "enabled": True,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 465,
                "sender_email": "your_email",
                "receiver_email": "your_email",
                "sender_password": "your_password"
            },
            "critical_system_paths": [
                "/etc/passwd" if self.os_type != "Windows" else "C:\\Windows\\System32\\config\\SAM",
                "/var/log/auth.log" if self.os_type != "Windows" else "C:\\Windows\\Logs\\Authentication\\Authpride.etl"
            ],
            "database_path": "cybersecurity_toolkit.db",
            "file_integrity": {
                "enabled": True,
                "monitored_paths": [
                    "/etc/hosts" if self.os_type != "Windows" else "C:\\Windows\\System32\\drivers\\etc\\hosts",
                    "/etc/shadow" if self.os_type != "Windows" else "C:\\Windows\\System32\\config\\SECURITY"
                ],
                "check_interval": 3600  # 1 hour
            },
            "firewall": {
                "enabled": True,
                "default_policy": "deny",
                "allowed_ports": [80, 443, 22, 53]
            },
            "intrusion_detection": {
                "enabled": True,
                "sensitivity": "medium"
            }
        }
        
        # Configuration management
        self.config = self.load_or_create_config(config_path)
        
        # Security components initialization
        self.init_database()
        self.generate_encryption_keys()
        self.threat_intelligence = {}
        self.system_metrics_history = []
        
        # Advanced monitoring variables
        self.monitoring_threads = []
        self.last_full_system_scan = None
        self.current_threat_level = 'LOW'
        
        # Machine learning models
        self.anomaly_detection_models = self.train_machine_learning_models()
        
        # Network and system scanning capabilities
        self.network_scan_results = {}
        self.vulnerability_database = self.load_vulnerability_database()
        
        # Initialize file integrity monitoring
        self.file_integrity_hashes = {}
        self.initialize_file_integrity_monitoring()
        
        # Alert tracking to prevent alert flooding
        self.last_alert_time = {}
        
        print("✅ CyberSecurityToolkit initialized successfully")

    # ... [Rest of the code remains the same as in the previous implementation]

    def load_or_create_config(self, config_path):
        """Load or create configuration file"""
        try:
            # Primary configuration load
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return self.validate_config(config)
            
            # Fallback configuration creation
            with open(config_path, 'w') as f:
                json.dump(self.default_config, f, indent=4)
            
            print(f"Created new configuration file at {config_path}")
            return self.default_config
        
        except Exception as e:
            print(f"Configuration loading failed: {e}")
            return self.default_config  # Return default config on error

    def validate_config(self, config):
        """Validate and sanitize configuration"""
        # Ensure all required keys exist
        for key, value in self.default_config.items():
            if key not in config:
                config[key] = value
                print(f"Missing configuration key: {key}. Using default.")
            elif isinstance(value, dict) and isinstance(config[key], dict):
                # Recursively check nested dictionaries
                for sub_key, sub_value in value.items():
                    if sub_key not in config[key]:
                        config[key][sub_key] = sub_value
                        print(f"Missing configuration sub-key: {key}.{sub_key}. Using default.")
        
        return config

    def generate_encryption_keys(self):
        """Generate encryption keys for secure communications"""
        try:
            # Symmetric Encryption Key
            self.symmetric_key = Fernet.generate_key()
            self.fernet_cipher = Fernet(self.symmetric_key)
            
            print("✅ Encryption keys generated successfully")
        except Exception as e:
            print(f"❌ Encryption key generation failed: {e}")

    def init_database(self):
        """Initialize database for security tracking"""
        try:
            db_path = self.config.get('database_path', 'cybersecurity_toolkit.db')
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            cursor = self.conn.cursor()
            
            # Create tables
            table_schemas = [
                '''CREATE TABLE IF NOT EXISTS system_metrics (
                    timestamp TEXT PRIMARY KEY,
                    cpu_usage REAL,
                    memory_usage REAL,
                    disk_usage REAL,
                    network_connections INTEGER,
                    threat_score REAL
                )''',
                '''CREATE TABLE IF NOT EXISTS network_connections (
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT,
                    threat_level TEXT
                )''',
                '''CREATE TABLE IF NOT EXISTS file_integrity_logs (
                    filepath TEXT,
                    last_hash TEXT,
                    timestamp TEXT,
                    status TEXT
                )''',
                '''CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    description TEXT,
                    severity TEXT
                )'''
            ]
            
            for schema in table_schemas:
                cursor.execute(schema)
            
            self.conn.commit()
            print("✅ Security database initialized")
        
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")

    def train_machine_learning_models(self):
        """Train machine learning models for anomaly detection"""
        models = {}
        try:
            # Synthetic data generation for training
            synthetic_data = np.random.rand(1000, 5) * 100
            scaler = StandardScaler()
            X = scaler.fit_transform(synthetic_data)
            
            # Multiple Anomaly Detection Models
            models['isolation_forest'] = IsolationForest(
                contamination=0.1, 
                random_state=42
            ).fit(X)
            
            models['one_class_svm'] = OneClassSVM(
                kernel='rbf', 
                nu=0.1
            ).fit(X)
            
            # Add preprocessing scaler
            models['scaler'] = scaler
            
            print("✅ Machine learning models trained successfully")
        
        except Exception as e:
            print(f"❌ Machine learning model training failed: {e}")
        
        return models

    def load_vulnerability_database(self):
        """Load vulnerability database"""
        vulnerabilities = {
            "windows": [
                {"id": "CVE-2021-1234", "severity": "HIGH", "description": "Windows Remote Code Execution"},
                {"id": "CVE-2022-5678", "severity": "MEDIUM", "description": "Privilege Escalation Vulnerability"}
            ],
            "linux": [
                {"id": "CVE-2020-9876", "severity": "CRITICAL", "description": "Linux Kernel Memory Corruption"},
                {"id": "CVE-2021-4321", "severity": "HIGH", "description": "SSH Authentication Bypass"}
            ],
            "macos": [
                {"id": "CVE-2021-5555", "severity": "MEDIUM", "description": "macOS Privilege Escalation"}
            ],
            "network": [
                {"id": "CVE-2020-1234", "severity": "HIGH", "description": "OpenSSH Remote Code Execution"}
            ]
        }
        return vulnerabilities

    def system_resource_monitor(self):
        """Monitor system resources and detect anomalies"""
        try:
            # Collect system metrics
            cpu_usage = psutil.cpu_percent()
            memory_usage = psutil.virtual_memory().percent
            disk_usage = psutil.disk_usage('/').percent
            network_connections = len(psutil.net_connections())
            
            # Calculate threat score based on resource utilization
            threat_score = (
                (cpu_usage / 100) * 0.4 + 
                (memory_usage / 100) * 0.3 + 
                (disk_usage / 100) * 0.2 + 
                (network_connections / 1000) * 0.1
            ) * 10
            
            # Store metrics in database
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO system_metrics VALUES (?, ?, ?, ?, ?, ?)",
                (
                    datetime.now().isoformat(), 
                    cpu_usage, 
                    memory_usage, 
                    disk_usage, 
                    network_connections, 
                    threat_score
                )
            )
            self.conn.commit()
            
            # Update threat level
            self.update_threat_level(threat_score)
            
            # Store in history for trend analysis
            self.system_metrics_history.append({
                "timestamp": datetime.now().isoformat(),
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "disk_usage": disk_usage,
                "network_connections": network_connections,
                "threat_score": threat_score
            })
            
            # Keep only the last 100 records for memory efficiency
            if len(self.system_metrics_history) > 100:
                self.system_metrics_history.pop(0)
            
            # Check for anomalies in system metrics
            self.detect_system_anomalies()
            
            # Check thresholds for immediate alerts
            self.check_resource_thresholds(cpu_usage, memory_usage, disk_usage)
            
            return {
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "disk_usage": disk_usage,
                "network_connections": network_connections,
                "threat_score": threat_score
            }
        
        except Exception as e:
            print(f"System resource monitoring failed: {e}")
            return {}

    def check_resource_thresholds(self, cpu_usage, memory_usage, disk_usage):
        """Check if system resources exceed thresholds and send alerts"""
        thresholds = self.config.get('alert_thresholds', {})
        
        # Check CPU usage
        if cpu_usage > thresholds.get('cpu_usage', 80):
            self.log_security_event(
                "HIGH_CPU_USAGE",
                f"CPU usage is at {cpu_usage}%, exceeding threshold of {thresholds.get('cpu_usage', 80)}%",
                "MEDIUM"
            )
            self.send_alert(
                "High CPU Usage Alert", 
                f"CPU usage is at {cpu_usage}%, exceeding threshold of {thresholds.get('cpu_usage', 80)}%"
            )
        
        # Check memory usage
        if memory_usage > thresholds.get('memory_usage', 85):
            self.log_security_event(
                "HIGH_MEMORY_USAGE",
                f"Memory usage is at {memory_usage}%, exceeding threshold of {thresholds.get('memory_usage', 85)}%",
                "MEDIUM"
            )
            self.send_alert(
                "High Memory Usage Alert", 
                f"Memory usage is at {memory_usage}%, exceeding threshold of {thresholds.get('memory_usage', 85)}%"
            )
        
        # Check disk usage
        if disk_usage > 90:  # Hard-coded threshold for disk
            self.log_security_event(
                "HIGH_DISK_USAGE",
                f"Disk usage is at {disk_usage}%, exceeding threshold of 90%",
                "MEDIUM"
            )
            self.send_alert(
                "High Disk Usage Alert", 
                f"Disk usage is at {disk_usage}%, exceeding threshold of 90%"
            )

    def detect_system_anomalies(self):
        """Detect anomalies in system metrics using ML models"""
        try:
            # Need at least 10 data points for meaningful analysis
            if len(self.system_metrics_history) < 10:
                return
            
            # Extract features for anomaly detection
            recent_metrics = self.system_metrics_history[-10:]
            features = np.array([
                [m['cpu_usage'], m['memory_usage'], m['disk_usage'], 
                 m['network_connections'], m['threat_score']] 
                for m in recent_metrics
            ])
            
            # Normalize features
            scaled_features = self.anomaly_detection_models['scaler'].transform(features)
            
            # Get predictions from multiple models
            if_pred = self.anomaly_detection_models['isolation_forest'].predict(scaled_features)
            svm_pred = self.anomaly_detection_models['one_class_svm'].predict(scaled_features)
            
            # Ensemble decision (if any model detects anomaly)
            anomaly_detected = (if_pred == -1).any() or (svm_pred == -1).any()
            
            if anomaly_detected:
                print("🚨 System metric anomaly detected!")
                self.log_security_event(
                    "ANOMALY_DETECTION", 
                    "Unusual system behavior detected in resource metrics", 
                    "MEDIUM"
                )
                
                # Send alert email for anomaly
                self.send_alert(
                    "System Anomaly Detected", 
                    "The security toolkit has detected unusual system behavior in resource metrics. "
                    "This could indicate a security issue or system problem."
                )
                
                # Increase threat level if anomaly detected
                if self.current_threat_level != 'HIGH':
                    self.current_threat_level = 'MEDIUM'
                    
        except Exception as e:
            print(f"Anomaly detection failed: {e}")

    def update_threat_level(self, threat_score):
        """Update the current threat level based on threat score"""
        previous_level = self.current_threat_level
        
        if threat_score < 3:
            self.current_threat_level = 'LOW'
        elif 3 <= threat_score < 7:
            self.current_threat_level = 'MEDIUM'
        else:
            self.current_threat_level = 'HIGH'
            self.trigger_emergency_response()
        
        # Log threat level changes
        if previous_level != self.current_threat_level:
            print(f"Threat level changed from {previous_level} to {self.current_threat_level}")
            self.log_security_event(
                "THREAT_LEVEL_CHANGE",
                f"System threat level changed from {previous_level} to {self.current_threat_level}",
                self.current_threat_level
            )
            
            # Send alert for threat level change
            if self.current_threat_level in ['MEDIUM', 'HIGH']:
                self.send_alert(
                    f"Threat Level Changed to {self.current_threat_level}", 
                    f"The system threat level has changed from {previous_level} to {self.current_threat_level}. "
                    f"This indicates a potential security concern that requires attention."
                )

    def log_security_event(self, event_type, description, severity):
        """Log security events to the database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO security_events (timestamp, event_type, description, severity) VALUES (?, ?, ?, ?)",
                (
                    datetime.now().isoformat(),
                    event_type,
                    description,
                    severity
                )
            )
            self.conn.commit()
        except Exception as e:
            print(f"Failed to log security event: {e}")

    def trigger_emergency_response(self):
        """Emergency response for high threat levels"""
        print("🚨 HIGH THREAT LEVEL DETECTED! EMERGENCY RESPONSE INITIATED!")
        
        # Log the emergency event
        self.log_security_event(
            "EMERGENCY_RESPONSE",
            "High threat level triggered emergency response protocol",
            "HIGH"
        )
        
        # Generate emergency report and send alert
        try:
            emergency_report = self.generate_emergency_report()
            
            self.send_alert(
                "EMERGENCY: High Threat Level", 
                f"Threat Level: {self.current_threat_level}\n"
                f"Emergency Report:\n{emergency_report}",
                force=True  # Force send even if recent alert was sent
            )
            
        except Exception as e:
            print(f"Emergency response failed: {e}")

    def generate_emergency_report(self):
        """Generate emergency system report"""
        report = f"""
        🚨 CYBERSECURITY EMERGENCY REPORT 🚨
        Timestamp: {datetime.now().isoformat()}
        Threat Level: {self.current_threat_level}
        
        System Metrics:
        - CPU Usage: {self.system_metrics_history[-1]['cpu_usage']}%
        - Memory Usage: {self.system_metrics_history[-1]['memory_usage']}%
        - Disk Usage: {self.system_metrics_history[-1]['disk_usage']}%
        - Network Connections: {self.system_metrics_history[-1]['network_connections']}
        
        Recent Security Events:
        {self.get_recent_security_events()}
        """
        return report

    def get_recent_security_events(self, limit=5):
        """Get recent security events from database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT timestamp, event_type, description, severity FROM security_events ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            events = cursor.fetchall()
            
            event_text = ""
            for event in events:
                event_text += f"- [{event[0]}] {event[1]}: {event[2]} (Severity: {event[3]})\n"
            
            return event_text
            
        except Exception as e:
            print(f"Failed to retrieve security events: {e}")
            return "No recent events available."

    def network_connection_scanner(self):
        """Scan network connections for suspicious activity"""
        try:
            connections = psutil.net_connections()
            suspicious_connections = 0
            high_risk_connections = 0
            
            for conn in connections:
                # Skip connections without remote address
                if not hasattr(conn, 'raddr') or not conn.raddr:
                    continue
                
                # Assess connection risk
                risk_level = self.assess_connection_risk(conn)
                
                # Count suspicious and high-risk connections
                if risk_level == 'MEDIUM':
                    suspicious_connections += 1
                elif risk_level == 'HIGH':
                    high_risk_connections += 1
                    
                    # Log high-risk connections
                    source_ip = conn.laddr[0] if hasattr(conn, 'laddr') and conn.laddr else 'N/A'
                    dest_ip = conn.raddr[0] if hasattr(conn, 'raddr') and conn.raddr else 'N/A'
                    
                    self.log_security_event(
                        "SUSPICIOUS_CONNECTION",
                        f"High-risk connection detected: {source_ip} -> {dest_ip}",
                        "HIGH"
                    )
            
            # Alert if too many suspicious connections
            if high_risk_connections > 0:
                self.send_alert(
                    "High-Risk Network Connections Detected",
                    f"Detected {high_risk_connections} high-risk network connections that may indicate a security breach."
                )
            elif suspicious_connections > 5:
                self.send_alert(
                    "Suspicious Network Activity",
                    f"Detected {suspicious_connections} suspicious network connections that should be investigated."
                )
            
            return {
                "total_connections": len(connections),
                "suspicious_connections": suspicious_connections,
                "high_risk_connections": high_risk_connections
            }
        
        except Exception as e:
            print(f"Network connection scanning failed: {e}")
            return {}

    def assess_connection_risk(self, connection):
        """Evaluate risk of network connections"""
        # Risk assessment logic
        risk_factors = {
            "HIGH_RISK_PORTS": [21, 22, 23, 3389, 5900, 8080, 1433, 3306],  # FTP, SSH, Telnet, RDP, VNC, etc.
            "SUSPICIOUS_STATUSES": ['LISTEN', 'CLOSE_WAIT'],
            "HIGH_RISK_IPS": ['0.0.0.0']  # Example - would be populated with known malicious IPs
        }
        
        try:
            # Check remote address port
            if hasattr(connection, 'raddr') and connection.raddr:
                try:
                    remote_port = connection.raddr[1]
                    remote_ip = connection.raddr[0]
                    
                    if remote_port in risk_factors['HIGH_RISK_PORTS']:
                        return 'HIGH'
                    
                    if remote_ip in risk_factors['HIGH_RISK_IPS']:
                        return 'HIGH'
                except (IndexError, TypeError):
                    pass
            
            # Check connection status
            if hasattr(connection, 'status') and connection.status in risk_factors['SUSPICIOUS_STATUSES']:
                return 'MEDIUM'
            
            # Check if process is unknown or suspicious
            if hasattr(connection, 'pid') and connection.pid:
                try:
                    process = psutil.Process(connection.pid)
                    if process.name() in ['python.exe', 'powershell.exe', 'cmd.exe']:
                        # These processes might be legitimate but are often used maliciously
                        return 'MEDIUM'
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return 'MEDIUM'  # Unknown process is suspicious
            
            return 'LOW'
        except Exception as e:
            print(f"Connection risk assessment failed: {e}")
            return 'UNKNOWN'

    def vulnerability_scanner(self):
        """Scan for system vulnerabilities"""
        vulnerabilities = []
        
        try:
            # OS-specific vulnerability checks
            if self.os_type == "Windows":
                os_vulnerabilities = self.vulnerability_database.get('windows', [])
            elif self.os_type == "Linux":
                os_vulnerabilities = self.vulnerability_database.get('linux', [])
            elif self.os_type == "Darwin":
                os_vulnerabilities = self.vulnerability_database.get('macos', [])
            else:
                os_vulnerabilities = []
            
            vulnerabilities.extend(os_vulnerabilities)
            
            # Network vulnerability checks
            network_vulnerabilities = self.vulnerability_database.get('network', [])
            vulnerabilities.extend(network_vulnerabilities)
            
            # Count critical and high vulnerabilities
            critical_vulns = sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')
            high_vulns = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
            
            # Alert on critical vulnerabilities
            if critical_vulns > 0:
                self.send_alert(
                    "Critical Vulnerabilities Detected",
                    f"Detected {critical_vulns} critical vulnerabilities that require immediate attention."
                )
            elif high_vulns > 0:
                self.send_alert(
                    "High Severity Vulnerabilities Detected",
                    f"Detected {high_vulns} high severity vulnerabilities that should be addressed."
                )
            
            return vulnerabilities
        
        except Exception as e:
            print(f"Vulnerability scanning failed: {e}")
            return []

    def initialize_file_integrity_monitoring(self):
        """Initialize file integrity monitoring"""
        if not self.config.get('file_integrity', {}).get('enabled', True):
            print("File integrity monitoring disabled in configuration")
            return
            
        try:
            monitored_paths = self.config.get('file_integrity', {}).get('monitored_paths', [])
            
            for filepath in monitored_paths:
                if os.path.exists(filepath):
                    file_hash = self.calculate_file_hash(filepath)
                    self.file_integrity_hashes[filepath] = file_hash
                    print(f"File integrity monitoring initialized for {filepath}")
                else:
                    print(f"File not found for integrity monitoring: {filepath}")
            
        except Exception as e:
            print(f"File integrity monitoring initialization failed: {e}")

    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Failed to calculate hash for {filepath}: {e}")
            return None

    def check_file_integrity(self):
        """Check integrity of monitored files"""
        if not self.config.get('file_integrity', {}).get('enabled', True):
            return []
            
        modified_files = []
        try:
            for filepath, original_hash in self.file_integrity_hashes.items():
                if os.path.exists(filepath):
                    current_hash = self.calculate_file_hash(filepath)
                    
                    if current_hash != original_hash:
                        modified_files.append(filepath)
                        
                        # Log file modification
                        self.log_security_event(
                            "FILE_INTEGRITY_VIOLATION",
                            f"Critical file modified: {filepath}",
                            "HIGH"
                        )
                else:
                    # Log missing file
                    self.log_security_event(
                        "FILE_INTEGRITY_VIOLATION",
                        f"Critical file missing: {filepath}",
                        "HIGH"
                    )
                    modified_files.append(f"{filepath} (MISSING)")
            
            # Send alert if files were modified
            if modified_files:
                self.send_alert(
                    "File Integrity Violation",
                    f"The following critical files have been modified or are missing:\n" +
                    "\n".join(f"- {f}" for f in modified_files)
                )
            
            return modified_files
            
        except Exception as e:
            print(f"File integrity check failed: {e}")
            return []

    def send_alert(self, subject, message, force=False):
        """Send email alert for security events"""
        try:
            email_config = self.config.get('email_alerts', {})
            
            if not email_config.get('enabled', False):
                print(f"Email alerts disabled. Alert would have been sent: {subject}")
                return
            
            # Check if we've sent this type of alert recently (within 15 minutes)
            # to prevent alert flooding, unless force=True
            current_time = datetime.now()
            if not force and subject in self.last_alert_time:
                time_diff = (current_time - self.last_alert_time[subject]).total_seconds()
                if time_diff < 900:  # 15 minutes
                    print(f"Suppressing duplicate alert: {subject} (sent {time_diff:.0f} seconds ago)")
                    return
            
            # Update last alert time
            self.last_alert_time[subject] = current_time
            
            # Prepare email
            msg = MIMEMultipart()
            msg['From'] = email_config.get('sender_email', '')
            msg['To'] = email_config.get('receiver_email', '')
            msg['Subject'] = f"🚨 Security Alert: {subject}"
            
            body = f"""
            Security  Alert
            
            Timestamp: {current_time.isoformat()}
            Threat Level: {self.current_threat_level}
            
            {message}
            
            This is an automated alert from your Redops.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP_SSL(
                email_config.get('smtp_server', 'smtp.gmail.com'), 
                email_config.get('smtp_port', 465)
            ) as server:
                server.login(
                    email_config.get('sender_email', ''), 
                    email_config.get('sender_password', '')
                )
                server.sendmail(
                    email_config.get('sender_email', ''), 
                    email_config.get('receiver_email', ''), 
                    msg.as_string()
                )
            
            print(f"Alert email sent: {subject}")
        
        except Exception as e:
            print(f"Alert sending failed: {e}")

    def continuous_monitoring(self):
        """Run continuous monitoring in separate threads"""
        try:
            print("🔒 Starting continuous security monitoring")
            
            # Create monitoring threads
            system_thread = threading.Thread(
                target=self.continuous_system_monitor,
                daemon=True
            )
            
            network_thread = threading.Thread(
                target=self.continuous_network_monitor,
                daemon=True
            )
            
            file_integrity_thread = threading.Thread(
                target=self.continuous_file_integrity_monitor,
                daemon=True
            )
            
            vulnerability_thread = threading.Thread(
                target=self.continuous_vulnerability_monitor,
                daemon=True
            )
            
            # Start all monitoring threads
            system_thread.start()
            network_thread.start()
            file_integrity_thread.start()
            vulnerability_thread.start()
            
            # Store thread references
            self.monitoring_threads = [
                system_thread,
                network_thread,
                file_integrity_thread,
                vulnerability_thread
            ]
            
            print("✅ All monitoring threads started successfully")
            
            # Main thread will periodically check if all monitoring threads are alive
            while self.running:
                for i, thread in enumerate(self.monitoring_threads):
                    if not thread.is_alive():
                        print(f"Monitoring thread {i} died, restarting...")
                        
                        # Restart the dead thread
                        if i == 0:
                            new_thread = threading.Thread(
                                target=self.continuous_system_monitor,
                                daemon=True
                            )
                        elif i == 1:
                            new_thread = threading.Thread(
                                target=self.continuous_network_monitor,
                                daemon=True
                            )
                        elif i == 2:
                            new_thread = threading.Thread(
                                target=self.continuous_file_integrity_monitor,
                                daemon=True
                            )
                        elif i == 3:
                            new_thread = threading.Thread(
                                target=self.continuous_vulnerability_monitor,
                                daemon=True
                            )
                        
                        new_thread.start()
                        self.monitoring_threads[i] = new_thread
                
                # Sleep for a while before checking again
                time.sleep(60)
                
        except KeyboardInterrupt:
            print("Continuous monitoring interrupted by user")
            self.running = False
            
        except Exception as e:
            print(f"Fatal error in continuous monitoring: {e}")
            self.running = False
            
        finally:
            # Clean up resources
            if hasattr(self, 'conn') and self.conn:
                self.conn.close()
                
            print("Continuous monitoring stopped")

    def continuous_system_monitor(self):
        """Continuously monitor system resources"""
        interval = self.config['monitoring_intervals'].get('system_scan', 60)
        
        while self.running:
            try:
                self.system_resource_monitor()
                time.sleep(interval)
            except Exception as e:
                print(f"System monitoring error: {e}")
                time.sleep(10)  # Short sleep before retry

    def continuous_network_monitor(self):
        """Continuously monitor network connections"""
        interval = self.config['monitoring_intervals'].get('network_scan', 300)
        
        while self.running:
            try:
                self.network_connection_scanner()
                time.sleep(interval)
            except Exception as e:
                print(f"Network monitoring error: {e}")
                time.sleep(10)  # Short sleep before retry

    def continuous_file_integrity_monitor(self):
        """Continuously monitor file integrity"""
        interval = self.config['file_integrity'].get('check_interval', 3600)
        
        while self.running:
            try:
                self.check_file_integrity()
                time.sleep(interval)
            except Exception as e:
                print(f"File integrity monitoring error: {e}")
                time.sleep(10)  # Short sleep before retry

    def continuous_vulnerability_monitor(self):
        """Continuously check for vulnerabilities"""
        interval = self.config['monitoring_intervals'].get('threat_analysis', 600)
        
        while self.running:
            try:
                self.vulnerability_scanner()
                time.sleep(interval)
            except Exception as e:
                print(f"Vulnerability monitoring error: {e}")
                time.sleep(10)  # Short sleep before retry

    def stop_monitoring(self):
        """Stop all monitoring threads"""
        print("Stopping all monitoring threads...")
        self.running = False
        
        # Wait for threads to finish
        for thread in self.monitoring_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        print("All monitoring threads stopped")

def main():
    """Main entry point for the Cybersecurity Toolkit"""
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="Advanced Cybersecurity Toolkit")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--config", default="config.json", help="Path to configuration file")
    
    args = parser.parse_args()
    
    try:
        # Initialize security toolkit
        security_toolkit = CyberSecurityToolkit(
            config_path=args.config, 
            debug_mode=args.debug
        )
        
        # Start continuous monitoring
        print("Starting continuous monitoring mode. Press Ctrl+C to stop.")
        security_toolkit.continuous_monitoring()
    
    except KeyboardInterrupt:
        print("\nCybersecurity Toolkit stopped by user")
        if 'security_toolkit' in locals():
            security_toolkit.stop_monitoring()
        sys.exit(0)
    except Exception as e:
        print(f"Cybersecurity Toolkit Initialization Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

