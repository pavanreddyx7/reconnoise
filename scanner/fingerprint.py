"""
Service and OS fingerprinting module
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from utils.logger import setup_logger

class Fingerprinter:
    """Service and application fingerprinting engine"""
    
    def __init__(self):
        self.logger = setup_logger(__name__)
        self.service_signatures = self._load_service_signatures()
        self.http_signatures = self._load_http_signatures()
        self.banner_patterns = self._load_banner_patterns()
        
    def _load_service_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load service identification signatures"""
        # **MODIFIED CODE BLOCK**
        return {
            'http': {
                'patterns': [b'HTTP/1.', b'HTTP/2'],
                'ports': [80, 8080, 8000, 3000],
                'confidence_weight': 0.9
            },
            'https': {
                'patterns': [b'\x16\x03\x01', b'\x16\x03\x02', b'\x16\x03\x03'], # TLS handshake patterns
                'ports': [443, 8443, 9443],
                'confidence_weight': 0.95
            },
            'ssh': {
                'patterns': [b'SSH-2.0', b'SSH-1.99'],
                'ports': [22],
                'confidence_weight': 0.95
            },
            'ftp': {
                'patterns': [b'220 ', b'FTP'],
                'ports': [21],
                'confidence_weight': 0.9
            },
            'smtp': {
                'patterns': [b'220 ', b'SMTP', b'ESMTP'],
                'ports': [25, 587, 465],
                'confidence_weight': 0.85
            },
            'dns': {
                'patterns': [b'\x00\x00\x84\x00\x00'],
                'ports': [53],
                'confidence_weight': 0.8
            },
            'mysql': {
                'patterns': [b'\x00\x00\x00\x0a', b'mysql_native_password'],
                'ports': [3306],
                'confidence_weight': 0.9
            },
            'postgresql': {
                'patterns': [b'SCRAM-SHA-256', b'PostgreSQL'],
                'ports': [5432],
                'confidence_weight': 0.9
            },
            'redis': {
                'patterns': [b'-NOAUTH', b'+PONG', b'Redis'],
                'ports': [6379],
                'confidence_weight': 0.9
            },
            'mongodb': {
                'patterns': [b'MongoDB', b'ismaster'],
                'ports': [27017],
                'confidence_weight': 0.9
            }
        }
        
    def _load_http_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load HTTP server signatures"""
        return {
            'apache': {
                'server_patterns': [b'Apache', b'apache'],
                'header_patterns': [b'X-Powered-By: PHP'],
                'confidence_weight': 0.8
            },
            'nginx': {
                'server_patterns': [b'nginx', b'Nginx'],
                'header_patterns': [],
                'confidence_weight': 0.85
            },
            'iis': {
                'server_patterns': [b'Microsoft-IIS', b'IIS'],
                'header_patterns': [b'X-Powered-By: ASP.NET'],
                'confidence_weight': 0.85
            },
            'cloudflare': {
                'server_patterns': [b'cloudflare'],
                'header_patterns': [b'CF-', b'cf-'],
                'confidence_weight': 0.9
            },
            'tomcat': {
                'server_patterns': [b'Tomcat', b'Apache Tomcat'],
                'header_patterns': [],
                'confidence_weight': 0.85
            },
            'jetty': {
                'server_patterns': [b'Jetty'],
                'header_patterns': [],
                'confidence_weight': 0.85
            }
        }
        
    def _load_banner_patterns(self) -> Dict[str, List[bytes]]:
        """Load banner grabbing patterns"""
        return {
            'version_info': [
                rb'(\d+\.\d+\.\d+)',
                rb'version (\d+\.\d+)',
                rb'v(\d+\.\d+)',
                rb'Ver (\d+\.\d+)'
            ],
            'os_info': [
                rb'Windows NT (\d+\.\d+)',
                rb'Ubuntu (\d+\.\d+)',
                rb'CentOS (\d+)',
                rb'Debian (\d+)'
            ],
            'software_info': [
                rb'OpenSSH_(\d+\.\d+)',
                rb'vsftpd (\d+\.\d+)',
                rb'ProFTPD (\d+\.\d+)'
            ]
        }
        
    def fingerprint_port(self, target: str, port: int, probe_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Fingerprint a specific port based on probe results
        """
        fingerprint = {
            'port': port,
            'service': 'unknown',
            'version': None,
            'os_hint': None,
            'confidence': 0.0,
            'signatures_matched': [],
            'details': {}
        }
        
        if not probe_results:
            return fingerprint
            
        # Collect all responses
        responses = []
        for result in probe_results:
            if result.get('success') and result.get('response'):
                responses.append(result['response'])
                
        if not responses:
            return fingerprint
            
        # Service identification
        service_matches = self._identify_service(responses, port)
        if service_matches:
            best_match = max(service_matches, key=lambda x: x['confidence'])
            fingerprint.update({
                'service': best_match['service'],
                'confidence': best_match['confidence'],
                'signatures_matched': [best_match['signature']]
            })
            
        # HTTP-specific fingerprinting
        http_responses = [r for r in responses if r.startswith(b'HTTP/')]
        if http_responses:
            http_info = self._fingerprint_http(http_responses[0])
            fingerprint['details'].update(http_info)
            
        # Banner analysis
        banner_info = self._analyze_banners(responses)
        fingerprint['details'].update(banner_info)
        
        # Version extraction
        version = self._extract_version(responses)
        if version:
            fingerprint['version'] = version
            
        # OS hints
        os_hint = self._detect_os_hints(responses)
        if os_hint:
            fingerprint['os_hint'] = os_hint
            
        return fingerprint
        
    def _identify_service(self, responses: List[bytes], port: int) -> List[Dict[str, Any]]:
        """
        Identify service based on response patterns
        """
        matches = []
        
        for service_name, sig_data in self.service_signatures.items():
            patterns = sig_data['patterns']
            expected_ports = sig_data.get('ports', [])
            weight = sig_data.get('confidence_weight', 0.5)
            
            for response in responses:
                pattern_matches = 0
                for pattern in patterns:
                    if response.startswith(pattern):
                        pattern_matches += 1
                        
                if pattern_matches > 0:
                    pattern_confidence = pattern_matches / len(patterns)
                    port_confidence = 1.0 if port in expected_ports else 0.5
                    
                    total_confidence = (pattern_confidence * weight + port_confidence * 0.3) / 1.3
                    
                    matches.append({
                        'service': service_name,
                        'confidence': min(total_confidence, 1.0),
                        'signature': f"{service_name}_pattern_match",
                        'pattern_matches': pattern_matches,
                        'response_size': len(response)
                    })
                    break 
                    
        return matches
        
    def _fingerprint_http(self, response: bytes) -> Dict[str, Any]:
        """
        Detailed HTTP server fingerprinting
        """
        info = {
            'http_version': None,
            'server': None,
            'powered_by': None,
            'status_code': None,
            'headers': {},
            'server_software': None
        }
        
        try:
            response_str = response.decode('utf-8', errors='ignore')
            lines = response_str.split('\n')
            
            if lines:
                status_line = lines[0].strip()
                if ' ' in status_line:
                    parts = status_line.split(' ', 2)
                    info['http_version'] = parts[0]
                    if len(parts) > 1 and parts[1].isdigit():
                        info['status_code'] = int(parts[1])
                        
                for line in lines[1:]:
                    line = line.strip()
                    if not line:
                        break
                    if ':' in line:
                        key, value = line.split(':', 1)
                        header_key = key.strip().lower()
                        header_value = value.strip()
                        info['headers'][header_key] = header_value
                        
                        if header_key == 'server':
                            info['server'] = header_value
                            info['server_software'] = self._identify_server_software(header_value.encode())
                        elif header_key == 'x-powered-by':
                            info['powered_by'] = header_value
                            
        except Exception as e:
            self.logger.debug(f"Error parsing HTTP response: {e}")
            
        return info
        
    def _identify_server_software(self, server_header: bytes) -> Optional[str]:
        """
        Identify server software from Server header
        """
        for software, sig_data in self.http_signatures.items():
            for pattern in sig_data['server_patterns']:
                if pattern in server_header:
                    return software
                    
        return None
        
    def _analyze_banners(self, responses: List[bytes]) -> Dict[str, Any]:
        """
        Analyze service banners for information
        """
        info = {
            'banners': [],
            'extracted_info': {}
        }
        
        for response in responses:
            try:
                banner_text = response.decode('utf-8', errors='ignore')
                if 0 < len(banner_text) < 1024: 
                    if any(keyword in banner_text.lower() for keyword in 
                           ['welcome', 'server', 'version', 'ready', 'hello', 'ssh', 'ftp', 'smtp']):
                        info['banners'].append(banner_text.strip())
                        
            except UnicodeDecodeError:
                continue
                
        for banner in info['banners']:
            banner_bytes = banner.encode()
            
            for p_type, patterns in self.banner_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, banner_bytes)
                    if matches:
                        key = p_type.replace('_info', 's')
                        info['extracted_info'].setdefault(key, [])
                        info['extracted_info'][key].extend([m.decode() for m in matches])
                        
        return info
        
    def _extract_version(self, responses: List[bytes]) -> Optional[str]:
        """
        Extract version information from responses
        """
        version_patterns = [
            rb'Server: \w+/([\d\.]+)',
            rb'(\d+\.\d+\.\d+)',
            rb'version (\d+\.\d+)',
            rb'v(\d+\.\d+)'
        ]
        
        for response in responses:
            for pattern in version_patterns:
                matches = re.findall(pattern, response, re.IGNORECASE)
                if matches:
                    return matches[0].decode('utf-8', errors='ignore')
                    
        return None
        
    def _detect_os_hints(self, responses: List[bytes]) -> Optional[str]:
        """
        Detect OS hints from responses
        """
        os_indicators = {
            'Windows': [b'Windows NT', b'Microsoft-IIS', b'ASP.NET'],
            'Linux': [b'Ubuntu', b'CentOS', b'Debian', b'Red Hat'],
        }
        
        for response in responses:
            for os_name, indicators in os_indicators.items():
                for indicator in indicators:
                    if indicator in response:
                        return os_name
                        
        return None
