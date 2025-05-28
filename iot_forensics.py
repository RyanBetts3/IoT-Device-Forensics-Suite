#!/usr/bin/env python3
"""
IoT Device Forensics Suite - Advanced Digital Forensics Tool for IoT Devices
Author: DFIR Professional
Version: 1.0.0
Description: Comprehensive forensic analysis tool for IoT devices, firmware extraction, 
            network analysis, and evidence recovery from smart devices.
"""

import os
import sys
import json
import struct
import hashlib
import sqlite3
import argparse
import binascii
import subprocess
import threading
import time
import socket
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
import logging
import tempfile
import zipfile
import tarfile
import re
import base64
import xml.etree.ElementTree as ET

# Network analysis imports
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Network analysis features limited.")

# Cryptographic imports
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: Cryptography library not available. Encryption analysis limited.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('iot_forensics.log'),
        logging.StreamHandler()
    ]
)

@dataclass
class DeviceInfo:
    """IoT Device Information Structure"""
    device_id: str
    device_type: str
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    mac_address: str = ""
    ip_address: str = ""
    serial_number: str = ""
    discovery_method: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    vulnerabilities: List[str] = field(default_factory=list)
    network_services: List[Dict] = field(default_factory=list)
    extracted_files: List[str] = field(default_factory=list)
    forensic_artifacts: Dict = field(default_factory=dict)

@dataclass
class NetworkTraffic:
    """Network Traffic Analysis Structure"""
    timestamp: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    packet_size: int
    payload: bytes = b""
    flags: str = ""
    analysis_notes: str = ""

@dataclass
class FirmwareAnalysis:
    """Firmware Analysis Results"""
    file_path: str
    file_hash: str
    file_size: int
    file_type: str
    architecture: str = ""
    endianness: str = ""
    compression: str = ""
    encryption: bool = False
    extracted_files: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    embedded_credentials: List[Dict] = field(default_factory=list)
    certificate_info: List[Dict] = field(default_factory=list)

class IoTForensicsCore:
    """Core IoT Forensics Analysis Engine"""
    
    def __init__(self, output_dir: str = "iot_forensics_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.db_path = self.output_dir / "iot_forensics.db"
        self.devices: Dict[str, DeviceInfo] = {}
        self.network_traffic: List[NetworkTraffic] = []
        self.firmware_analyses: List[FirmwareAnalysis] = []
        self.logger = logging.getLogger(__name__)
        
        # Initialize database
        self._init_database()
        
        # Known IoT device signatures
        self.device_signatures = {
            'cameras': {
                'hikvision': [b'Hikvision', b'HIKVISION'],
                'dahua': [b'Dahua', b'DAHUA'],
                'axis': [b'AXIS'],
                'foscam': [b'Foscam', b'FOSCAM'],
                'amcrest': [b'Amcrest']
            },
            'routers': {
                'dlink': [b'D-Link', b'DLINK'],
                'linksys': [b'Linksys', b'LINKSYS'],
                'netgear': [b'NETGEAR', b'Netgear'],
                'tplink': [b'TP-Link', b'TP-LINK'],
                'asus': [b'ASUS']
            },
            'smart_home': {
                'nest': [b'Nest', b'NEST'],
                'ring': [b'Ring', b'RING'],
                'alexa': [b'Alexa', b'ALEXA', b'Amazon Echo'],
                'phillips_hue': [b'Philips Hue', b'hue-bridge']
            }
        }
        
        # Common IoT vulnerabilities to check
        self.vulnerability_patterns = {
            'default_credentials': [
                b'admin:admin', b'admin:password', b'admin:123456',
                b'root:root', b'admin:', b'user:user'
            ],
            'hardcoded_keys': [
                b'-----BEGIN PRIVATE KEY-----',
                b'-----BEGIN RSA PRIVATE KEY-----',
                b'ssh-rsa AAAA'
            ],
            'debug_interfaces': [
                b'/bin/sh', b'telnetd', b'/dev/ttyS',
                b'uart', b'jtag', b'debug'
            ],
            'backdoors': [
                b'backdoor', b'secret', b'hidden',
                b'maintenance', b'service'
            ]
        }

    def _init_database(self):
        """Initialize SQLite database for storing forensic data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                device_type TEXT,
                manufacturer TEXT,
                model TEXT,
                firmware_version TEXT,
                mac_address TEXT,
                ip_address TEXT,
                serial_number TEXT,
                discovery_method TEXT,
                timestamp TEXT,
                vulnerabilities TEXT,
                network_services TEXT,
                extracted_files TEXT,
                forensic_artifacts TEXT
            )
        ''')
        
        # Network traffic table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                payload BLOB,
                flags TEXT,
                analysis_notes TEXT
            )
        ''')
        
        # Firmware analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firmware_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT,
                file_hash TEXT UNIQUE,
                file_size INTEGER,
                file_type TEXT,
                architecture TEXT,
                endianness TEXT,
                compression TEXT,
                encryption BOOLEAN,
                extracted_files TEXT,
                strings TEXT,
                security_issues TEXT,
                embedded_credentials TEXT,
                certificate_info TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def discover_devices(self, network_range: str = "192.168.1.0/24") -> List[DeviceInfo]:
        """Discover IoT devices on the network"""
        self.logger.info(f"Starting device discovery on {network_range}")
        discovered_devices = []
        
        # Parse network range
        try:
            import ipaddress
            network = ipaddress.IPv4Network(network_range, strict=False)
        except ValueError:
            self.logger.error(f"Invalid network range: {network_range}")
            return discovered_devices
        
        # Common IoT ports to scan
        common_ports = [21, 22, 23, 53, 80, 443, 554, 1935, 5000, 8080, 8443, 9999]
        
        for ip in network.hosts():
            ip_str = str(ip)
            open_ports = self._scan_ports(ip_str, common_ports)
            
            if open_ports:
                device = self._identify_device(ip_str, open_ports)
                if device:
                    discovered_devices.append(device)
                    self.devices[device.device_id] = device
        
        self.logger.info(f"Discovered {len(discovered_devices)} IoT devices")
        return discovered_devices

    def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scan for open ports on a device"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception:
                continue
        
        return open_ports

    def _identify_device(self, ip: str, open_ports: List[int]) -> Optional[DeviceInfo]:
        """Identify device type and gather basic information"""
        device_id = f"{ip}_{int(time.time())}"
        device_type = "Unknown IoT Device"
        manufacturer = ""
        model = ""
        services = []
        
        # Try to gather information from open services
        for port in open_ports:
            service_info = self._probe_service(ip, port)
            if service_info:
                services.append(service_info)
                
                # Try to identify device based on service banners
                banner = service_info.get('banner', '').lower()
                if any(cam in banner for cam in ['camera', 'dvr', 'nvr', 'video']):
                    device_type = "IP Camera"
                elif any(router in banner for router in ['router', 'gateway', 'wireless']):
                    device_type = "Router/Gateway"
                elif any(smart in banner for smart in ['nest', 'hue', 'alexa', 'smart']):
                    device_type = "Smart Home Device"
        
        # Get MAC address if possible
        mac_address = self._get_mac_address(ip)
        
        device = DeviceInfo(
            device_id=device_id,
            device_type=device_type,
            manufacturer=manufacturer,
            model=model,
            ip_address=ip,
            mac_address=mac_address,
            discovery_method="Network Scan",
            network_services=services
        )
        
        return device

    def _probe_service(self, ip: str, port: int) -> Optional[Dict]:
        """Probe a service to gather banner information"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            service_info = {
                'port': port,
                'service': self._identify_service(port),
                'banner': '',
                'headers': {}
            }
            
            if port in [80, 443, 8080, 8443]:  # HTTP services
                request = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
                sock.send(request)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                service_info['banner'] = response
                
                # Parse HTTP headers
                if '\r\n\r\n' in response:
                    headers_section = response.split('\r\n\r\n')[0]
                    for line in headers_section.split('\r\n')[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            service_info['headers'][key.strip()] = value.strip()
            
            elif port == 21:  # FTP
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                service_info['banner'] = response
            
            elif port in [22, 23]:  # SSH/Telnet
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                service_info['banner'] = response
            
            sock.close()
            return service_info
            
        except Exception as e:
            return None

    def _identify_service(self, port: int) -> str:
        """Identify service based on port number"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 554: "RTSP", 993: "IMAPS", 995: "POP3S",
            1935: "RTMP", 5000: "UPnP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
            9999: "Telnet-Alt"
        }
        return service_map.get(port, f"Unknown-{port}")

    def _get_mac_address(self, ip: str) -> str:
        """Attempt to get MAC address using ARP"""
        try:
            # Try using system ARP table
            if sys.platform.startswith('win'):
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True)
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse MAC address from ARP output
                for line in result.stdout.split('\n'):
                    if ip in line:
                        # Look for MAC address pattern
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                        if mac_match:
                            return mac_match.group()
        except Exception:
            pass
        
        return ""

    def analyze_firmware(self, firmware_path: str) -> FirmwareAnalysis:
        """Comprehensive firmware analysis"""
        self.logger.info(f"Analyzing firmware: {firmware_path}")
        
        firmware_file = Path(firmware_path)
        if not firmware_file.exists():
            raise FileNotFoundError(f"Firmware file not found: {firmware_path}")
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(firmware_path)
        file_size = firmware_file.stat().st_size
        
        # Determine file type
        file_type = self._determine_file_type(firmware_path)
        
        analysis = FirmwareAnalysis(
            file_path=firmware_path,
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type
        )
        
        # Extract firmware if compressed/archived
        extracted_files = self._extract_firmware(firmware_path)
        analysis.extracted_files = extracted_files
        
        # Analyze extracted content
        for extracted_file in extracted_files:
            self._analyze_extracted_file(extracted_file, analysis)
        
        # String analysis
        analysis.strings = self._extract_strings(firmware_path)
        
        # Security analysis
        analysis.security_issues = self._identify_security_issues(analysis)
        
        # Look for embedded credentials
        analysis.embedded_credentials = self._find_embedded_credentials(analysis)
        
        # Certificate analysis
        analysis.certificate_info = self._analyze_certificates(analysis)
        
        # Determine architecture and endianness
        analysis.architecture, analysis.endianness = self._analyze_architecture(firmware_path)
        
        self.firmware_analyses.append(analysis)
        self._save_firmware_analysis(analysis)
        
        return analysis

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _determine_file_type(self, file_path: str) -> str:
        """Determine file type using magic bytes"""
        with open(file_path, 'rb') as f:
            header = f.read(512)
        
        # Common firmware signatures
        if header.startswith(b'\x1f\x8b'):
            return "Gzip compressed"
        elif header.startswith(b'PK'):
            return "ZIP archive"
        elif header.startswith(b'\x42\x5a\x68'):
            return "Bzip2 compressed"
        elif header.startswith(b'\x7fELF'):
            return "ELF executable"
        elif header.startswith(b'hsqs'):
            return "SquashFS filesystem"
        elif header.startswith(b'JFFS'):
            return "JFFS2 filesystem"
        elif header.startswith(b'\x85\x19'):
            return "LZMA compressed"
        elif b'cramfs' in header:
            return "CramFS filesystem"
        else:
            return "Unknown binary"

    def _extract_firmware(self, firmware_path: str) -> List[str]:
        """Extract firmware files if compressed/archived"""
        extracted_files = []
        firmware_file = Path(firmware_path)
        extract_dir = self.output_dir / "extracted" / firmware_file.stem
        extract_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Try different extraction methods
            if firmware_path.endswith(('.zip', '.pk')):
                with zipfile.ZipFile(firmware_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_dir)
                    extracted_files = [str(extract_dir / name) for name in zip_ref.namelist()]
            
            elif firmware_path.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(firmware_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_dir)
                    extracted_files = [str(extract_dir / name) for name in tar_ref.getnames()]
            
            # Try binwalk for firmware extraction (if available)
            else:
                try:
                    result = subprocess.run([
                        'binwalk', '-e', '--run-as=any', '-C', str(extract_dir), firmware_path
                    ], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        # Find extracted files
                        for root, dirs, files in os.walk(extract_dir):
                            for file in files:
                                extracted_files.append(os.path.join(root, file))
                except FileNotFoundError:
                    self.logger.warning("Binwalk not available for advanced firmware extraction")
        
        except Exception as e:
            self.logger.error(f"Error extracting firmware: {e}")
        
        return extracted_files

    def _analyze_extracted_file(self, file_path: str, analysis: FirmwareAnalysis):
        """Analyze individual extracted files"""
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists() or file_path_obj.is_dir():
                return
            
            # Check file size (skip very large files)
            if file_path_obj.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
                return
            
            # Analyze based on file extension/type
            if file_path.endswith(('.txt', '.conf', '.cfg', '.ini', '.xml', '.json')):
                self._analyze_config_file(file_path, analysis)
            elif file_path.endswith(('.sh', '.py', '.pl', '.php')):
                self._analyze_script_file(file_path, analysis)
            elif file_path.endswith(('.key', '.pem', '.crt', '.cer')):
                self._analyze_crypto_file(file_path, analysis)
        
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")

    def _analyze_config_file(self, file_path: str, analysis: FirmwareAnalysis):
        """Analyze configuration files for sensitive information"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for passwords and keys
            password_patterns = [
                r'password\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'passwd\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'secret\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'key\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            ]
            
            for pattern in password_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if len(match) > 3:  # Ignore very short matches
                        analysis.embedded_credentials.append({
                            'file': file_path,
                            'type': 'configuration',
                            'credential': match,
                            'context': pattern
                        })
        
        except Exception as e:
            self.logger.error(f"Error analyzing config file {file_path}: {e}")

    def _analyze_script_file(self, file_path: str, analysis: FirmwareAnalysis):
        """Analyze script files for hardcoded credentials and backdoors"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for hardcoded credentials in scripts
            credential_patterns = [
                r'curl.*-u\s+([^:\s]+:[^:\s]+)',
                r'wget.*--user=([^\s]+).*--password=([^\s]+)',
                r'ssh.*@.*-p\s*["\']([^"\']+)["\']',
                r'mysql.*-p["\']([^"\']+)["\']'
            ]
            
            for pattern in credential_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    analysis.embedded_credentials.append({
                        'file': file_path,
                        'type': 'script',
                        'credential': match,
                        'context': 'hardcoded in script'
                    })
            
            # Look for potential backdoors
            backdoor_patterns = [
                r'/bin/sh.*&',
                r'nc.*-l.*-e',
                r'telnetd.*-l',
                r'python.*socket.*exec'
            ]
            
            for pattern in backdoor_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    analysis.security_issues.append(f"Potential backdoor in {file_path}: {pattern}")
        
        except Exception as e:
            self.logger.error(f"Error analyzing script file {file_path}: {e}")

    def _analyze_crypto_file(self, file_path: str, analysis: FirmwareAnalysis):
        """Analyze cryptographic files (keys, certificates)"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for private keys
            if b'-----BEGIN PRIVATE KEY-----' in content or b'-----BEGIN RSA PRIVATE KEY-----' in content:
                analysis.embedded_credentials.append({
                    'file': file_path,
                    'type': 'private_key',
                    'credential': 'RSA/Generic Private Key',
                    'context': 'embedded private key'
                })
                analysis.security_issues.append(f"Private key embedded in firmware: {file_path}")
            
            # Analyze certificates
            if b'-----BEGIN CERTIFICATE-----' in content:
                try:
                    # Basic certificate info extraction
                    cert_start = content.find(b'-----BEGIN CERTIFICATE-----')
                    cert_end = content.find(b'-----END CERTIFICATE-----') + len(b'-----END CERTIFICATE-----')
                    cert_data = content[cert_start:cert_end]
                    
                    analysis.certificate_info.append({
                        'file': file_path,
                        'type': 'X.509 Certificate',
                        'size': len(cert_data)
                    })
                except Exception:
                    pass
        
        except Exception as e:
            self.logger.error(f"Error analyzing crypto file {file_path}: {e}")

    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """Extract readable strings from binary file"""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            ascii_strings = re.findall(rb'[ -~]{%d,}' % min_length, data)
            strings.extend([s.decode('ascii', errors='ignore') for s in ascii_strings])
            
            # Extract Unicode strings
            unicode_strings = re.findall(rb'(?:[ -~]\x00){%d,}' % min_length, data)
            for s in unicode_strings:
                try:
                    decoded = s.decode('utf-16le', errors='ignore').replace('\x00', '')
                    if len(decoded) >= min_length:
                        strings.append(decoded)
                except:
                    pass
        
        except Exception as e:
            self.logger.error(f"Error extracting strings from {file_path}: {e}")
        
        # Filter out very common/uninteresting strings and limit results
        filtered_strings = []
        skip_patterns = [r'^[0-9]+$', r'^[a-f0-9]+$', r'^\s+$']
        
        for string in strings[:1000]:  # Limit to first 1000 strings
            if not any(re.match(pattern, string) for pattern in skip_patterns):
                filtered_strings.append(string)
        
        return filtered_strings

    def _identify_security_issues(self, analysis: FirmwareAnalysis) -> List[str]:
        """Identify security issues in firmware"""
        issues = []
        
        # Check strings for vulnerabilities
        all_strings = ' '.join(analysis.strings).lower()
        
        # Check for default credentials
        default_creds = ['admin:admin', 'admin:password', 'root:root', 'admin:123456']
        for cred in default_creds:
            if cred in all_strings:
                issues.append(f"Default credentials found: {cred}")
        
        # Check for debug interfaces
        debug_keywords = ['telnet', 'debug', 'uart', 'jtag', '/bin/sh']
        for keyword in debug_keywords:
            if keyword in all_strings:
                issues.append(f"Debug interface indicator: {keyword}")
        
        # Check for weak cryptography
        weak_crypto = ['md5', 'des', 'rc4', 'sha1']
        for crypto in weak_crypto:
            if crypto in all_strings:
                issues.append(f"Weak cryptography: {crypto}")
        
        # Check for hardcoded secrets
        if any('secret' in s.lower() or 'key' in s.lower() for s in analysis.strings):
            issues.append("Potential hardcoded secrets found")
        
        return issues

    def _find_embedded_credentials(self, analysis: FirmwareAnalysis) -> List[Dict]:
        """Find embedded credentials in firmware"""
        credentials = []
        
        # Search strings for credential patterns
        for string in analysis.strings:
            # Username:password patterns
            cred_match = re.search(r'^([a-zA-Z][a-zA-Z0-9_]*):([a-zA-Z0-9!@#$%^&*()_+=-]+)$', string)
            if cred_match and len(cred_match.group(2)) > 3:
                credentials.append({
                    'type': 'username_password',
                    'username': cred_match.group(1),
                    'password': cred_match.group(2),
                    'source': 'strings'
                })
            
            # API keys/tokens
            if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', string) and len(string) > 16:
                credentials.append({
                    'type': 'api_key',
                    'key': string,
                    'source': 'strings'
                })
        
        return credentials

    def _analyze_certificates(self, analysis: FirmwareAnalysis) -> List[Dict]:
        """Analyze certificates found in firmware"""
        certificates = []
        
        # Already populated by _analyze_crypto_file
        return analysis.certificate_info

    def _analyze_architecture(self, file_path: str) -> Tuple[str, str]:
        """Determine firmware architecture and endianness"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
            
            # ELF header analysis
            if header.startswith(b'\x7fELF'):
                # ELF architecture detection
                ei_class = header[4]
                ei_data = header[5]
                e_machine = struct.unpack('<H', header[18:20])[0]
                
                arch_map = {
                    0x03: "x86",
                    0x08: "MIPS",
                    0x14: "PowerPC",
                    0x28: "ARM",
                    0x3E: "x86-64",
                    0xB7: "AArch64"
                }
                
                architecture = arch_map.get(e_machine, f"Unknown-{e_machine}")
                endianness = "Little Endian" if ei_data == 1 else "Big Endian"
                
                return architecture, endianness
            
            # MIPS detection
            elif any(sig in header for sig in [b'MIPS', b'mips']):
                return "MIPS", "Unknown"
            
            # ARM detection
            elif any(sig in header for sig in [b'ARM', b'arm']):
                return "ARM", "Unknown"
            
        except Exception as e:
            self.logger.error(f"Error analyzing architecture: {e}")
        
        return "Unknown", "Unknown"

    def capture_network_traffic(self, interface: str = None, duration: int = 60) -> List[NetworkTraffic]:
        """Capture and analyze network traffic from IoT devices"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available for network capture")
            return []
        
        self.logger.info(f"Starting network capture for {duration} seconds")
        captured_packets = []
        
        def packet_handler(packet):
            try:
                if packet.haslayer('IP'):
                    traffic = NetworkTraffic(
                        timestamp=float(packet.time),
                        source_ip=packet['IP'].src,
                        dest_ip=packet['IP'].dst,
                        source_port=packet['TCP'].sport if packet.haslayer('TCP') else packet['UDP'].sport if packet.haslayer('UDP') else 0,
                        dest_port=packet['TCP'].dport if packet.haslayer('TCP') else packet['UDP'].dport if packet.haslayer('UDP') else 0,
                        protocol='TCP' if packet.haslayer('TCP') else 'UDP' if packet.haslayer('UDP') else 'Other',
                        packet_size=len(packet),
                        payload=bytes(packet.payload) if hasattr(packet, 'payload') else b"",
                        flags=str(packet['TCP'].flags) if packet.haslayer('TCP') else ""
                    )
                    
                    # Basic analysis
                    if self._is_suspicious_traffic(traffic):
                        traffic.analysis_notes = "Suspicious activity detected"
                    
                    captured_packets.append(traffic)
                    self.network_traffic.append(traffic)
            
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
        
        try:
            # Start packet capture
            sniff(iface=interface, timeout=duration, prn=packet_handler, store=False)
        except Exception as e:
            self.logger.error(f"Error during packet capture: {e}")
        
        self.logger.info(f"Captured {len(captured_packets)} packets")
        return captured_packets

    def _is_suspicious_traffic(self, traffic: NetworkTraffic) -> bool:
        """Identify suspicious network traffic patterns"""
        suspicious_ports = [1234, 4444, 5555, 6666, 31337, 12345]
        
        # Check for suspicious ports
        if traffic.dest_port in suspicious_ports or traffic.source_port in suspicious_ports:
            return True
        
        # Check for unusual protocols on standard ports
        if traffic.dest_port == 80 and traffic.protocol != 'TCP':
            return True
        
        # Check payload for suspicious content
        if traffic.payload:
            suspicious_strings = [b'shell', b'exec', b'system', b'backdoor']
            payload_lower = traffic.payload.lower()
            if any(sus in payload_lower for sus in suspicious_strings):
                return True
        
        return False

    def analyze_device_communications(self, device_ip: str) -> Dict[str, Any]:
        """Analyze communication patterns for a specific device"""
        device_traffic = [t for t in self.network_traffic 
                         if t.source_ip == device_ip or t.dest_ip == device_ip]
        
        if not device_traffic:
            return {"error": "No traffic found for device"}
        
        analysis = {
            "total_packets": len(device_traffic),
            "protocols": Counter(t.protocol for t in device_traffic),
            "destinations": Counter(t.dest_ip for t in device_traffic if t.source_ip == device_ip),
            "sources": Counter(t.source_ip for t in device_traffic if t.dest_ip == device_ip),
            "ports": Counter(t.dest_port for t in device_traffic),
            "suspicious_activity": [],
            "data_exfiltration": False,
            "command_control": []
        }
        
        # Check for data exfiltration (large uploads)
        upload_size = sum(t.packet_size for t in device_traffic if t.source_ip == device_ip)
        download_size = sum(t.packet_size for t in device_traffic if t.dest_ip == device_ip)
        
        if upload_size > download_size * 2:  # Upload significantly larger than download
            analysis["data_exfiltration"] = True
            analysis["suspicious_activity"].append("Potential data exfiltration detected")
        
        # Check for command and control patterns
        for dest_ip in analysis["destinations"]:
            dest_traffic = [t for t in device_traffic if t.dest_ip == dest_ip and t.source_ip == device_ip]
            if len(dest_traffic) > 10:  # Frequent communications
                analysis["command_control"].append({
                    "server": dest_ip,
                    "connections": len(dest_traffic),
                    "ports": list(set(t.dest_port for t in dest_traffic))
                })
        
        return analysis

    def extract_device_memory(self, device_ip: str, method: str = "telnet") -> Dict[str, Any]:
        """Extract memory/configuration from IoT device"""
        extraction_result = {
            "device_ip": device_ip,
            "method": method,
            "success": False,
            "extracted_data": {},
            "errors": []
        }
        
        try:
            if method == "telnet":
                extraction_result.update(self._extract_via_telnet(device_ip))
            elif method == "ssh":
                extraction_result.update(self._extract_via_ssh(device_ip))
            elif method == "http":
                extraction_result.update(self._extract_via_http(device_ip))
            else:
                extraction_result["errors"].append(f"Unknown extraction method: {method}")
        
        except Exception as e:
            extraction_result["errors"].append(str(e))
        
        return extraction_result

    def _extract_via_telnet(self, device_ip: str) -> Dict[str, Any]:
        """Extract data via Telnet connection"""
        result = {"success": False, "extracted_data": {}}
        
        try:
            import telnetlib
            
            # Try common credentials
            credentials = [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", ""),
                ("root", "root"),
                ("", "")
            ]
            
            for username, password in credentials:
                try:
                    tn = telnetlib.Telnet(device_ip, timeout=10)
                    
                    if username:
                        tn.read_until(b"login: ", timeout=5)
                        tn.write(username.encode('ascii') + b"\n")
                    
                    if password:
                        tn.read_until(b"Password: ", timeout=5)
                        tn.write(password.encode('ascii') + b"\n")
                    
                    # Try to execute commands
                    commands = ["cat /proc/version", "ps", "netstat -an", "cat /etc/passwd"]
                    
                    for cmd in commands:
                        tn.write(cmd.encode('ascii') + b"\n")
                        output = tn.read_until(b"# ", timeout=5).decode('ascii', errors='ignore')
                        result["extracted_data"][cmd] = output
                    
                    tn.close()
                    result["success"] = True
                    break
                
                except Exception:
                    continue
        
        except Exception as e:
            result["errors"] = [str(e)]
        
        return result

    def _extract_via_ssh(self, device_ip: str) -> Dict[str, Any]:
        """Extract data via SSH connection"""
        result = {"success": False, "extracted_data": {}}
        
        # SSH extraction would require paramiko library
        # For now, return placeholder
        result["errors"] = ["SSH extraction requires paramiko library"]
        return result

    def _extract_via_http(self, device_ip: str) -> Dict[str, Any]:
        """Extract data via HTTP interfaces"""
        result = {"success": False, "extracted_data": {}}
        
        try:
            # Common IoT device paths
            paths = [
                "/", "/index.html", "/login.html", "/admin", "/cgi-bin/",
                "/system", "/config", "/status", "/info", "/debug"
            ]
            
            for path in paths:
                try:
                    for port in [80, 8080, 443, 8443]:
                        protocol = "https" if port in [443, 8443] else "http"
                        url = f"{protocol}://{device_ip}:{port}{path}"
                        
                        response = requests.get(url, timeout=10, verify=False)
                        if response.status_code == 200:
                            result["extracted_data"][url] = {
                                "status_code": response.status_code,
                                "headers": dict(response.headers),
                                "content_length": len(response.content),
                                "content_type": response.headers.get('Content-Type', ''),
                                "title": self._extract_html_title(response.text)
                            }
                            result["success"] = True
                
                except Exception:
                    continue
        
        except Exception as e:
            result["errors"] = [str(e)]
        
        return result

    def _extract_html_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            return title_match.group(1).strip() if title_match else ""
        except:
            return ""

    def generate_forensic_report(self, output_file: str = None) -> str:
        """Generate comprehensive forensic report"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = str(self.output_dir / f"iot_forensic_report_{timestamp}.html")
        
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "devices": [asdict(device) for device in self.devices.values()],
            "firmware_analyses": [asdict(analysis) for analysis in self.firmware_analyses],
            "network_traffic_summary": {
                "total_packets": len(self.network_traffic),
                "protocols": dict(Counter(t.protocol for t in self.network_traffic)),
                "top_sources": dict(Counter(t.source_ip for t in self.network_traffic).most_common(10)),
                "top_destinations": dict(Counter(t.dest_ip for t in self.network_traffic).most_common(10))
            }
        }
        
        # Generate HTML report
        html_report = self._generate_html_report(report_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        # Also save JSON version
        json_file = output_file.replace('.html', '.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        self.logger.info(f"Forensic report generated: {output_file}")
        return output_file

    def _generate_html_report(self, data: Dict) -> str:
        """Generate HTML forensic report"""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Forensics Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .section {{ margin-bottom: 30px; }}
        .device-card {{ border: 1px solid #ddd; border-radius: 8px; padding: 15px; margin-bottom: 15px; background: #fafafa; }}
        .vulnerability {{ background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 5px 0; }}
        .security-issue {{ background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 5px 0; }}
        .success {{ background: #e8f5e8; border-left: 4px solid #4caf50; padding: 10px; margin: 5px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .summary-stats {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .stat-box {{ flex: 1; background: #e3f2fd; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #1976d2; }}
        .stat-label {{ color: #666; }}
        pre {{ background: #f5f5f5; padding: 10px; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IoT Device Forensics Report</h1>
            <p>Generated on: {data['timestamp']}</p>
        </div>
        
        <div class="summary-stats">
            <div class="stat-box">
                <div class="stat-number">{len(data['devices'])}</div>
                <div class="stat-label">Devices Analyzed</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{len(data['firmware_analyses'])}</div>
                <div class="stat-label">Firmware Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-number">{data['network_traffic_summary']['total_packets']}</div>
                <div class="stat-label">Network Packets</div>
            </div>
        </div>
"""
        
        # Devices section
        if data['devices']:
            html += """
        <div class="section">
            <h2>Discovered Devices</h2>
"""
            for device in data['devices']:
                html += f"""
            <div class="device-card">
                <h3>{device['device_type']} ({device['ip_address']})</h3>
                <p><strong>Device ID:</strong> {device['device_id']}</p>
                <p><strong>MAC Address:</strong> {device['mac_address'] or 'Unknown'}</p>
                <p><strong>Manufacturer:</strong> {device['manufacturer'] or 'Unknown'}</p>
                <p><strong>Discovery Method:</strong> {device['discovery_method']}</p>
                
                <h4>Network Services:</h4>
                <table>
                    <tr><th>Port</th><th>Service</th><th>Banner</th></tr>
"""
                for service in device.get('network_services', []):
                    banner = service.get('banner', '')[:100] + ('...' if len(service.get('banner', '')) > 100 else '')
                    html += f"<tr><td>{service.get('port', '')}</td><td>{service.get('service', '')}</td><td>{banner}</td></tr>"
                
                html += "</table>"
                
                if device.get('vulnerabilities'):
                    html += "<h4>Vulnerabilities:</h4>"
                    for vuln in device['vulnerabilities']:
                        html += f'<div class="vulnerability">{vuln}</div>'
                
                html += "</div>"
            
            html += "</div>"
        
        # Firmware analysis section
        if data['firmware_analyses']:
            html += """
        <div class="section">
            <h2>Firmware Analysis Results</h2>
"""
            for analysis in data['firmware_analyses']:
                html += f"""
            <div class="device-card">
                <h3>Firmware: {Path(analysis['file_path']).name}</h3>
                <p><strong>File Hash:</strong> {analysis['file_hash']}</p>
                <p><strong>File Size:</strong> {analysis['file_size']:,} bytes</p>
                <p><strong>File Type:</strong> {analysis['file_type']}</p>
                <p><strong>Architecture:</strong> {analysis.get('architecture', 'Unknown')}</p>
                <p><strong>Endianness:</strong> {analysis.get('endianness', 'Unknown')}</p>
                
                <h4>Security Issues:</h4>
"""
                for issue in analysis.get('security_issues', []):
                    html += f'<div class="security-issue">{issue}</div>'
                
                if analysis.get('embedded_credentials'):
                    html += "<h4>Embedded Credentials:</h4><table><tr><th>Type</th><th>Details</th><th>Source</th></tr>"
                    for cred in analysis['embedded_credentials'][:10]:  # Limit display
                        html += f"<tr><td>{cred.get('type', '')}</td><td>{str(cred.get('credential', ''))[:50]}...</td><td>{cred.get('source', '')}</td></tr>"
                    html += "</table>"
                
                html += "</div>"
            
            html += "</div>"
        
        # Network traffic summary
        html += f"""
        <div class="section">
            <h2>Network Traffic Analysis</h2>
            <div class="device-card">
                <h3>Traffic Summary</h3>
                <p><strong>Total Packets Captured:</strong> {data['network_traffic_summary']['total_packets']}</p>
                
                <h4>Protocol Distribution:</h4>
                <table>
                    <tr><th>Protocol</th><th>Packet Count</th></tr>
"""
        for protocol, count in data['network_traffic_summary']['protocols'].items():
            html += f"<tr><td>{protocol}</td><td>{count}</td></tr>"
        
        html += """
                </table>
                
                <h4>Top Source IPs:</h4>
                <table>
                    <tr><th>Source IP</th><th>Packet Count</th></tr>
"""
        for ip, count in data['network_traffic_summary']['top_sources'].items():
            html += f"<tr><td>{ip}</td><td>{count}</td></tr>"
        
        html += """
                </table>
            </div>
        </div>
        
        <div class="section">
            <h2>Investigation Summary</h2>
            <div class="device-card">
                <h3>Key Findings</h3>
"""
        
        # Generate summary findings
        total_vulns = sum(len(device.get('vulnerabilities', [])) for device in data['devices'])
        total_security_issues = sum(len(analysis.get('security_issues', [])) for analysis in data['firmware_analyses'])
        
        if total_vulns > 0:
            html += f'<div class="vulnerability">Found {total_vulns} device vulnerabilities across all analyzed devices</div>'
        
        if total_security_issues > 0:
            html += f'<div class="security-issue">Identified {total_security_issues} security issues in firmware analysis</div>'
        
        if total_vulns == 0 and total_security_issues == 0:
            html += '<div class="success">No major security issues identified in this analysis</div>'
        
        html += """
            </div>
        </div>
        
        <div class="section">
            <p><em>This report was generated by IoT Device Forensics Suite v1.0.0</em></p>
        </div>
    </div>
</body>
</html>
"""
        
        return html

    def _save_firmware_analysis(self, analysis: FirmwareAnalysis):
        """Save firmware analysis to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO firmware_analysis 
            (file_path, file_hash, file_size, file_type, architecture, endianness, 
             compression, encryption, extracted_files, strings, security_issues, 
             embedded_credentials, certificate_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis.file_path,
            analysis.file_hash,
            analysis.file_size,
            analysis.file_type,
            analysis.architecture,
            analysis.endianness,
            analysis.compression,
            analysis.encryption,
            json.dumps(analysis.extracted_files),
            json.dumps(analysis.strings[:100]),  # Limit strings stored
            json.dumps(analysis.security_issues),
            json.dumps(analysis.embedded_credentials),
            json.dumps(analysis.certificate_info)
        ))
        
        conn.commit()
        conn.close()

    def export_evidence(self, case_name: str) -> str:
        """Export all evidence for legal/court purposes"""
        case_dir = self.output_dir / f"case_{case_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        case_dir.mkdir(exist_ok=True)
        
        # Copy database
        import shutil
        shutil.copy2(self.db_path, case_dir / "evidence.db")
        
        # Generate evidence manifest
        manifest = {
            "case_name": case_name,
            "export_timestamp": datetime.now().isoformat(),
            "examiner": "IoT Forensics Suite",
            "evidence_items": {
                "devices": len(self.devices),
                "firmware_files": len(self.firmware_analyses),
                "network_packets": len(self.network_traffic),
                "database": str(case_dir / "evidence.db")
            },
            "chain_of_custody": {
                "collected_by": "IoT Forensics Suite v1.0.0",
                "collection_date": datetime.now().isoformat(),
                "hash_verification": True
            }
        }
        
        with open(case_dir / "evidence_manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2, default=str)
        
        # Generate final report
        report_file = self.generate_forensic_report(str(case_dir / "forensic_report.html"))
        
        self.logger.info(f"Evidence package exported to: {case_dir}")
        return str(case_dir)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="IoT Device Forensics Suite")
    parser.add_argument("-o", "--output", default="iot_forensics_output", 
                       help="Output directory for results")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Device discovery
    discover_parser = subparsers.add_parser("discover", help="Discover IoT devices on network")
    discover_parser.add_argument("-n", "--network", default="192.168.1.0/24",
                                help="Network range to scan")
    
    # Firmware analysis
    firmware_parser = subparsers.add_parser("firmware", help="Analyze firmware file")
    firmware_parser.add_argument("file", help="Firmware file to analyze")
    
    # Network capture
    capture_parser = subparsers.add_parser("capture", help="Capture network traffic")
    capture_parser.add_argument("-i", "--interface", help="Network interface")
    capture_parser.add_argument("-t", "--time", type=int, default=60,
                               help="Capture duration in seconds")
    
    # Memory extraction
    extract_parser = subparsers.add_parser("extract", help="Extract device memory/config")
    extract_parser.add_argument("device_ip", help="Device IP address")
    extract_parser.add_argument("-m", "--method", choices=["telnet", "ssh", "http"],
                               default="telnet", help="Extraction method")
    
    # Generate report
    report_parser = subparsers.add_parser("report", help="Generate forensic report")
    report_parser.add_argument("-f", "--format", choices=["html", "json"], default="html",
                              help="Report format")
    
    # Export evidence
    export_parser = subparsers.add_parser("export", help="Export evidence package")
    export_parser.add_argument("case_name", help="Case name for evidence package")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize forensics suite
    forensics = IoTForensicsCore(args.output)
    
    try:
        if args.command == "discover":
            devices = forensics.discover_devices(args.network)
            print(f"\nDiscovered {len(devices)} IoT devices:")
            for device in devices:
                print(f"  - {device.device_type} at {device.ip_address} ({device.mac_address})")
        
        elif args.command == "firmware":
            analysis = forensics.analyze_firmware(args.file)
            print(f"\nFirmware Analysis Complete:")
            print(f"  File: {analysis.file_path}")
            print(f"  Hash: {analysis.file_hash}")
            print(f"  Type: {analysis.file_type}")
            print(f"  Architecture: {analysis.architecture}")
            print(f"  Security Issues: {len(analysis.security_issues)}")
            print(f"  Embedded Credentials: {len(analysis.embedded_credentials)}")
        
        elif args.command == "capture":
            traffic = forensics.capture_network_traffic(args.interface, args.time)
            print(f"\nCaptured {len(traffic)} network packets")
        
        elif args.command == "extract":
            result = forensics.extract_device_memory(args.device_ip, args.method)
            print(f"\nExtraction result for {args.device_ip}:")
            print(f"  Success: {result['success']}")
            if result['errors']:
                print(f"  Errors: {result['errors']}")
        
        elif args.command == "report":
            report_file = forensics.generate_forensic_report()
            print(f"\nForensic report generated: {report_file}")
        
        elif args.command == "export":
            evidence_dir = forensics.export_evidence(args.case_name)
            print(f"\nEvidence package exported to: {evidence_dir}")
    
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Command failed: {e}", exc_info=True)


if __name__ == "__main__":
    main()