"""
Zoom traffic profile for reconnaissance
"""

import random
import struct
from typing import List, Dict, Any
from .base import BaseProfile

class ZoomProfile(BaseProfile):
    """Zoom video conferencing traffic profile"""
    
    def __init__(self):
        super().__init__("Zoom")
        self.description = "Zoom video conferencing service traffic profile"
        self.default_ports = [80, 443, 8080, 8801, 8802, 9887]
        self.probe_delay = 0.15
        
    def get_probes(self, port: int) -> List[bytes]:
        """Generate Zoom-specific probes"""
        probes = []
        
        if port in [80, 8080]:
            probes.extend(self._get_http_probes())
        elif port in [443]:
            probes.extend(self._get_https_probes())
            probes.append(self.create_tls_probe())
        elif port in [8801, 8802, 9887]:
            probes.extend(self._get_zoom_protocol_probes())
        else:
            probes.extend(self._get_generic_probes())
            
        return probes
        
    def _get_http_probes(self) -> List[bytes]:
        """Generate HTTP probes for Zoom web interface"""
        probes = []
        
        zoom_paths = [
            "/",
            "/signin",
            "/join",
            "/wc/join",
            "/j/",
            "/webapp",
            "/client/meetings",
            "/api/v1/meetings"
        ]
        
        zoom_headers = {
            "Host": "zoom.us",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Upgrade-Insecure-Requests": "1"
        }
        
        for path in zoom_paths[:4]:
            probe = self.create_http_probe("GET", path, zoom_headers)
            probes.append(probe)
            
        # Zoom API probe
        api_headers = zoom_headers.copy()
        api_headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })
        
        api_probe = self.create_http_probe("GET", "/api/v1/meetings", api_headers)
        probes.append(api_probe)
        
        return probes
        
    def _get_https_probes(self) -> List[bytes]:
        """Generate HTTPS probes for Zoom"""
        return [self.create_tls_probe()]
        
    def _get_zoom_protocol_probes(self) -> List[bytes]:
        """Generate Zoom proprietary protocol probes"""
        probes = []
        
        # Zoom uses a proprietary protocol for media
        # These are simplified probes based on observed patterns
        
        # Zoom handshake probe (simplified)
        zoom_magic = b'\x17\x01\x00\x00'
        zoom_version = b'\x00\x01'
        zoom_type = b'\x01'  # Connection request
        zoom_payload = self.generate_random_data(16)
        
        zoom_probe1 = zoom_magic + zoom_version + zoom_type + zoom_payload
        probes.append(zoom_probe1)
        
        # Alternative Zoom probe
        zoom_probe2 = b'\x00\x01\x00\x00' + struct.pack('>I', 12345) + b'\x00' * 8
        probes.append(zoom_probe2)
        
        # UDP-style probe (even though we're using TCP)
        udp_style_probe = b'ZOOM' + b'\x00' * 12 + struct.pack('>I', random.randint(1000, 9999))
        probes.append(udp_style_probe)
        
        return probes
        
    def _get_generic_probes(self) -> List[bytes]:
        """Generate generic probes"""
        return [
            b"GET / HTTP/1.1\r\nHost: zoom.us\r\n\r\n",
            self.generate_random_data(32)
        ]
        
    def analyze_response(self, response: bytes, port: int) -> Dict[str, Any]:
        """Analyze response for Zoom indicators"""
        analysis = {
            'service': 'unknown',
            'confidence': 0.0,
            'indicators': [],
            'app': None
        }
        
        if not response:
            return analysis
            
        response_str = response.decode('utf-8', errors='ignore').lower()
        
        # Zoom-specific indicators
        zoom_indicators = [
            'zoom',
            'zoom.us',
            'zoomapp',
            'zoomclient',
            'meeting',
            'webinar',
            'x-zm-',
            'zm-auth',
            'zoom-meeting'
        ]
        
        # HTTP response analysis
        if b'HTTP/' in response[:20]:
            analysis['service'] = 'HTTP'
            http_data = self.parse_http_response(response)
            
            headers = http_data.get('headers', {})
            matches = []
            
            # Check for Zoom indicators
            for indicator in zoom_indicators:
                if any(indicator in str(value).lower() for value in headers.values()):
                    matches.append(True)
                    analysis['indicators'].append(f"Header contains '{indicator}'")
                elif indicator in response_str:
                    matches.append(True)
                    analysis['indicators'].append(f"Response contains '{indicator}'")
                else:
                    matches.append(False)
                    
            # Zoom-specific header checks
            zoom_headers = ['x-zm-', 'zm-auth', 'x-zoom-', 'server']
            for header_prefix in zoom_headers:
                for header_name in headers.keys():
                    if header_prefix in header_name:
                        matches.append(True)
                        analysis['indicators'].append(f"Zoom header: {header_name}")
                        break
                        
            # Server header analysis
            server = headers.get('server', '')
            if 'zoom' in server or 'nginx' in server:
                matches.append(True)
                analysis['indicators'].append(f"Server: {server}")
                
            # Content analysis
            if 'join' in response_str and 'meeting' in response_str:
                matches.append(True)
                analysis['indicators'].append("Contains meeting join content")
                
            if 'zoomapp' in response_str or 'webclient' in response_str:
                matches.append(True)
                analysis['indicators'].append("Contains Zoom app references")
                
            analysis['confidence'] = self.calculate_confidence(matches)
            
            if analysis['confidence'] > 0.7:
                analysis['app'] = 'Zoom'
            elif analysis['confidence'] > 0.4:
                analysis['app'] = 'Possible Zoom'
                
        # TLS response analysis
        elif response.startswith(b'\x16\x03'):
            analysis['service'] = 'TLS/SSL'
            if len(response) > 50:
                analysis['confidence'] = 0.3
                analysis['indicators'].append("TLS handshake received")
                
        # Zoom proprietary protocol analysis
        elif port in [8801, 8802, 9887]:
            if response.startswith(b'\x17\x01') or b'ZOOM' in response:
                analysis['service'] = 'Zoom Protocol'
                analysis['confidence'] = 0.8
                analysis['app'] = 'Zoom'
                analysis['indicators'].append("Zoom proprietary protocol detected")
            elif len(response) > 0:
                analysis['service'] = 'Unknown Binary'
                analysis['confidence'] = 0.2
                analysis['indicators'].append("Binary response on Zoom port")
                
        return analysis
        
    def get_fingerprint_patterns(self) -> Dict[str, bytes]:
        """Get Zoom fingerprint patterns"""
        return {
            'zoom_domain': b'zoom.us',
            'zoom_app': b'zoomapp',
            'zoom_meeting': b'meeting',
            'zoom_join': b'/j/',
            'zoom_webapp': b'/webapp',
            'zoom_protocol': b'\x17\x01',
            'zoom_header': b'x-zm-',
            'zoom_client': b'zoomclient'
        }
        
    def get_timing_profile(self) -> Dict[str, float]:
        """Zoom-specific timing profile"""
        return {
            'initial_delay': random.uniform(0.1, 0.4),
            'probe_interval': 0.2,
            'response_timeout': 4.0,
            'retry_delay': 1.0
        }
