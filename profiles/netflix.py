"""
Netflix traffic profile for reconnaissance
"""

import random
from typing import List, Dict, Any
from .base import BaseProfile

class NetflixProfile(BaseProfile):
    """Netflix application traffic profile"""
    
    def __init__(self):
        super().__init__("Netflix")
        self.description = "Netflix streaming service traffic profile"
        self.default_ports = [80, 443, 8080, 8443]
        self.probe_delay = 0.2
        
    def get_probes(self, port: int) -> List[bytes]:
        """Generate Netflix-specific probes"""
        probes = []
        
        if port in [80, 8080]:
            # HTTP probes
            probes.extend(self._get_http_probes())
        elif port in [443, 8443]:
            # HTTPS probes
            probes.extend(self._get_https_probes())
            probes.append(self.create_tls_probe())
        else:
            # Generic probes
            probes.extend(self._get_generic_probes())
            
        return probes
        
    def _get_http_probes(self) -> List[bytes]:
        """Generate HTTP probes mimicking Netflix traffic"""
        probes = []
        
        # Netflix API endpoints
        netflix_paths = [
            "/api/shakti/v1/pathEvaluator",
            "/nq/website/memberapi/v1/path/dyndns",
            "/api/metadata/v1/titles",
            "/browse",
            "/watch",
            "/api/cadmium/metadata/v1",
            "/nq/website/memberapi/v1/profiles"
        ]
        
        netflix_headers = {
            "Host": "www.netflix.com",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "X-Netflix.request.client": "website",
            "X-Netflix.request.routing": '{"path": "/shakti", "requestId": "123"}',
            "Referer": "https://www.netflix.com/browse"
        }
        
        for path in netflix_paths[:3]:  # Limit to avoid detection
            probe = self.create_http_probe("GET", path, netflix_headers)
            probes.append(probe)
            
        # Netflix-specific POST probe
        post_data = '{"paths":[["genres"]],"authURL":"123456789"}'
        post_headers = netflix_headers.copy()
        post_headers.update({
            "Content-Type": "application/json",
            "Content-Length": str(len(post_data))
        })
        
        post_probe = self.create_http_probe("POST", "/api/shakti/v1/pathEvaluator", post_headers)
        post_probe += post_data.encode()
        probes.append(post_probe)
        
        return probes
        
    def _get_https_probes(self) -> List[bytes]:
        """Generate HTTPS probes for Netflix"""
        # For HTTPS, we mainly rely on TLS handshake and connection behavior
        return [self.create_tls_probe()]
        
    def _get_generic_probes(self) -> List[bytes]:
        """Generate generic probes"""
        return [
            b"GET / HTTP/1.1\r\nHost: netflix.com\r\n\r\n",
            self.generate_random_data(64)
        ]
        
    def analyze_response(self, response: bytes, port: int) -> Dict[str, Any]:
        """Analyze response for Netflix indicators"""
        analysis = {
            'service': 'unknown',
            'confidence': 0.0,
            'indicators': [],
            'app': None
        }
        
        if not response:
            return analysis
            
        response_str = response.decode('utf-8', errors='ignore').lower()
        
        # Netflix-specific indicators
        netflix_indicators = [
            'netflix',
            'nflx',
            'shakti',
            'cadmium',
            'x-netflix',
            'netflix.com',
            'nq/website',
            'memberapi'
        ]
        
        # HTTP response analysis
        if b'HTTP/' in response[:20]:
            analysis['service'] = 'HTTP'
            http_data = self.parse_http_response(response)
            
            # Check headers
            headers = http_data.get('headers', {})
            server_info = self.extract_server_info(headers)
            
            matches = []
            
            # Check for Netflix indicators in headers and content
            for indicator in netflix_indicators:
                if any(indicator in str(value).lower() for value in headers.values()):
                    matches.append(True)
                    analysis['indicators'].append(f"Header contains '{indicator}'")
                elif indicator in response_str:
                    matches.append(True)
                    analysis['indicators'].append(f"Response contains '{indicator}'")
                else:
                    matches.append(False)
                    
            # Special Netflix header checks
            netflix_headers = ['x-netflix', 'x-originating-url', 'x-netflix-request-id']
            for header in netflix_headers:
                if header in headers:
                    matches.append(True)
                    analysis['indicators'].append(f"Netflix header: {header}")
                    
            # Content-type checks
            if 'application/json' in headers.get('content-type', ''):
                if 'shakti' in response_str or 'cadmium' in response_str:
                    matches.append(True)
                    analysis['indicators'].append("Netflix API JSON response")
                    
            # Calculate confidence
            analysis['confidence'] = self.calculate_confidence(matches)
            
            if analysis['confidence'] > 0.7:
                analysis['app'] = 'Netflix'
            elif analysis['confidence'] > 0.4:
                analysis['app'] = 'Possible Netflix'
                
        # TLS response analysis
        elif response.startswith(b'\x16\x03'):
            analysis['service'] = 'TLS/SSL'
            # Basic TLS analysis - in a real implementation, 
            # you'd parse the certificate for Netflix domains
            if len(response) > 50:  # Reasonable handshake size
                analysis['confidence'] = 0.3
                analysis['indicators'].append("TLS handshake received")
                
        return analysis
        
    def get_fingerprint_patterns(self) -> Dict[str, bytes]:
        """Get Netflix fingerprint patterns"""
        return {
            'netflix_api_response': b'shakti',
            'netflix_header': b'X-Netflix',
            'netflix_domain': b'netflix.com',
            'netflix_api_path': b'/api/cadmium/',
            'netflix_member_api': b'memberapi',
            'netflix_routing': b'netflix.request.routing'
        }
        
    def get_timing_profile(self) -> Dict[str, float]:
        """Netflix-specific timing profile"""
        return {
            'initial_delay': random.uniform(0.2, 0.8),
            'probe_interval': 0.3,
            'response_timeout': 5.0,
            'retry_delay': 1.5
        }
