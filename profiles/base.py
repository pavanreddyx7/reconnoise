"""
Base profile class for traffic reconnaissance
"""

import abc
import time
import random
from typing import List, Dict, Any, Optional, Tuple

class BaseProfile(abc.ABC):
    """Abstract base class for traffic profiles"""
    
    def __init__(self, name: str):
        self.name = name
        self.description = ""
        self.default_ports = []
        self.probe_delay = 0.1
        self.max_retries = 3
        
    @abc.abstractmethod
    def get_probes(self, port: int) -> List[bytes]:
        """
        Generate probe payloads for a specific port
        Returns list of byte sequences to send
        """
        pass
        
    @abc.abstractmethod
    def analyze_response(self, response: bytes, port: int) -> Dict[str, Any]:
        """
        Analyze response from target
        Returns dictionary with analysis results
        """
        pass
        
    @abc.abstractmethod
    def get_fingerprint_patterns(self) -> Dict[str, bytes]:
        """
        Get patterns used for fingerprinting this application
        Returns dict mapping pattern names to byte patterns
        """
        pass
        
    def get_timing_profile(self) -> Dict[str, float]:
        """
        Get timing characteristics for this profile
        Returns dict with timing parameters
        """
        return {
            'initial_delay': random.uniform(0.1, 0.5),
            'probe_interval': self.probe_delay,
            'response_timeout': 3.0,
            'retry_delay': 1.0
        }
        
    def get_default_ports(self) -> List[int]:
        """Get default ports for this profile"""
        return self.default_ports.copy()
        
    def should_scan_port(self, port: int) -> bool:
        """Determine if this profile should scan a specific port"""
        return port in self.default_ports or port in [80, 443, 8080, 8443]
        
    def get_user_agent(self) -> str:
        """Get user agent string for HTTP-based probes"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        return random.choice(agents)
        
    def generate_random_data(self, length: int) -> bytes:
        """Generate random data for probes"""
        return bytes([random.randint(0, 255) for _ in range(length)])
        
    def create_http_probe(self, method: str = "GET", path: str = "/", headers: Dict[str, str] = None) -> bytes:
        """Create HTTP probe"""
        if headers is None:
            headers = {}
            
        # Default headers
        default_headers = {
            "Host": "example.com",
            "User-Agent": self.get_user_agent(),
            "Accept": "*/*",
            "Connection": "close"
        }
        default_headers.update(headers)
        
        # Build request
        request_lines = [f"{method} {path} HTTP/1.1"]
        for key, value in default_headers.items():
            request_lines.append(f"{key}: {value}")
        request_lines.extend(["", ""])
        
        return "\r\n".join(request_lines).encode()
        
    def create_tls_probe(self) -> bytes:
        """Create TLS ClientHello probe"""
        # Simplified TLS 1.2 ClientHello
        tls_version = b"\x03\x03"  # TLS 1.2
        random_data = self.generate_random_data(32)
        session_id_len = b"\x00"
        
        # Cipher suites (simplified)
        cipher_suites = b"\x00\x02\x00\x35"  # AES256-SHA
        compression = b"\x01\x00"
        
        handshake_data = (
            tls_version + random_data + session_id_len + 
            cipher_suites + compression
        )
        
        # Handshake header
        handshake_header = b"\x01" + len(handshake_data).to_bytes(3, 'big') + handshake_data
        
        # Record header
        record_header = b"\x16" + tls_version + len(handshake_header).to_bytes(2, 'big')
        
        return record_header + handshake_header
        
    def parse_http_response(self, response: bytes) -> Dict[str, Any]:
        """Parse HTTP response"""
        try:
            response_str = response.decode('utf-8', errors='ignore')
            lines = response_str.split('\n')
            
            if not lines:
                return {}
                
            # Parse status line
            status_line = lines[0].strip()
            parts = status_line.split(' ', 2)
            
            result = {
                'protocol': parts[0] if len(parts) > 0 else '',
                'status_code': int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                'status_text': parts[2] if len(parts) > 2 else '',
                'headers': {}
            }
            
            # Parse headers
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    result['headers'][key.strip().lower()] = value.strip()
                    
            return result
            
        except Exception:
            return {}
            
    def calculate_confidence(self, matches: List[bool], weights: List[float] = None) -> float:
        """Calculate confidence score based on pattern matches"""
        if not matches:
            return 0.0
            
        if weights is None:
            weights = [1.0] * len(matches)
            
        if len(weights) != len(matches):
            weights = [1.0] * len(matches)
            
        total_weight = sum(weights)
        matched_weight = sum(w for m, w in zip(matches, weights) if m)
        
        return matched_weight / total_weight if total_weight > 0 else 0.0
        
    def extract_server_info(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract server information from HTTP headers"""
        info = {}
        
        if 'server' in headers:
            info['server'] = headers['server']
            
        if 'x-powered-by' in headers:
            info['powered_by'] = headers['x-powered-by']
            
        if 'content-type' in headers:
            info['content_type'] = headers['content-type']
            
        return info
