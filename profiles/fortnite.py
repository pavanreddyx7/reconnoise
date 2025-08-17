"""
Fortnite game traffic profile for reconnaissance
"""

import random
import struct
from typing import List, Dict, Any
from .base import BaseProfile

class FortniteProfile(BaseProfile):
    """Fortnite game traffic profile"""
    
    def __init__(self):
        super().__init__("Fortnite")
        self.description = "Fortnite game service traffic profile"
        self.default_ports = [80, 443, 5222, 5795, 9000, 9001, 9002]
        self.probe_delay = 0.1
        
    def get_probes(self, port: int) -> List[bytes]:
        """Generate Fortnite-specific probes"""
        probes = []
        
        if port in [80]:
            probes.extend(self._get_http_probes())
        elif port in [443]:
            probes.extend(self._get_https_probes())
            probes.append(self.create_tls_probe())
        elif port == 5222:
            probes.extend(self._get_xmpp_probes())
        elif port in [5795, 9000, 9001, 9002]:
            probes.extend(self._get_game_protocol_probes())
        else:
            probes.extend(self._get_generic_probes())
            
        return probes
        
    def _get_http_probes(self) -> List[bytes]:
        """Generate HTTP probes for Epic Games services"""
        probes = []
        
        epic_paths = [
            "/",
            "/account/api/oauth/token",
            "/fortnite/api/game/v2/profile",
            "/launcher/api/public/distributionpoints",
            "/account/api/public/account",
            "/friends/api/v1/public/friends",
            "/fortnite/api/matchmaking/session/findPlayer"
        ]
        
        epic_headers = {
            "Host": "fortnite-public-service-prod-b.ol.epicgames.com",
            "User-Agent": "Fortnite/++Fortnite+Release-12.61-CL-14297770 Windows/10.0.19041.1.256.64bit",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": "Bearer eg1~token_placeholder"
        }
        
        for path in epic_paths[:4]:
            probe = self.create_http_probe("GET", path, epic_headers)
            probes.append(probe)
            
        # Epic Games launcher probe
        launcher_headers = {
            "Host": "launcher-public-service-prod06.ol.epicgames.com",
            "User-Agent": "EpicGamesLauncher/12.0.1",
            "Accept": "application/json"
        }
        
        launcher_probe = self.create_http_probe("GET", "/launcher/api/public/distributionpoints", launcher_headers)
        probes.append(launcher_probe)
        
        return probes
        
    def _get_https_probes(self) -> List[bytes]:
        """Generate HTTPS probes for Epic Games"""
        return [self.create_tls_probe()]
        
    def _get_xmpp_probes(self) -> List[bytes]:
        """Generate XMPP probes (Fortnite uses XMPP for friends/chat)"""
        probes = []
        
        # XMPP stream initiation
        xmpp_probe1 = b'''<?xml version='1.0'?><stream:stream to='prod.ol.epicgames.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>'''
        probes.append(xmpp_probe1)
        
        # XMPP auth probe
        xmpp_probe2 = b'''<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGVwaWNfZ2FtZXMAcGFzc3dvcmQ=</auth>'''
        probes.append(xmpp_probe2)
        
        return probes
        
    def _get_game_protocol_probes(self) -> List[bytes]:
        """Generate game protocol probes"""
        probes = []
        
        # Unreal Engine network protocol probes
        # These are simplified based on observed patterns
        
        # Game handshake probe
        game_magic = b'\x00\x00\x00\x00'  # Unreal magic
        game_version = struct.pack('<I', 123456)
        game_type = b'\x01'
        game_probe1 = game_magic + game_version + game_type + self.generate_random_data(8)
        probes.append(game_probe1)
        
        # Connection request
        conn_probe = b'CONNECT' + b'\x00' * 10 + struct.pack('<I', random.randint(10000, 99999))
        probes.append(conn_probe)
        
        # Heartbeat-style probe
        heartbeat = struct.pack('<I', 0xDEADBEEF) + b'\x00' * 12
        probes.append(heartbeat)
        
        return probes
        
    def _get_generic_probes(self) -> List[bytes]:
        """Generate generic probes"""
        return [
            b"GET / HTTP/1.1\r\nHost: epicgames.com\r\n\r\n",
            self.generate_random_data(48)
        ]
        
    def analyze_response(self, response: bytes, port: int) -> Dict[str, Any]:
        """Analyze response for Fortnite/Epic Games indicators"""
        analysis = {
            'service': 'unknown',
            'confidence': 0.0,
            'indicators': [],
            'app': None
        }
        
        if not response:
            return analysis
            
        response_str = response.decode('utf-8', errors='ignore').lower()
        
        # Epic Games / Fortnite indicators
        epic_indicators = [
            'epicgames',
            'fortnite',
            'unreal',
            'epic games',
            'ol.epicgames.com',
            'launcher-public-service',
            'fortnite-public-service',
            'unrealengine'
        ]
        
        # HTTP response analysis
        if b'HTTP/' in response[:20]:
            analysis['service'] = 'HTTP'
            http_data = self.parse_http_response(response)
            
            headers = http_data.get('headers', {})
            matches = []
            
            # Check for Epic Games indicators
            for indicator in epic_indicators:
                if any(indicator in str(value).lower() for value in headers.values()):
                    matches.append(True)
                    analysis['indicators'].append(f"Header contains '{indicator}'")
                elif indicator in response_str:
                    matches.append(True)
                    analysis['indicators'].append(f"Response contains '{indicator}'")
                else:
                    matches.append(False)
                    
            # Epic Games specific headers
            epic_headers = ['x-epic-', 'epic-', 'unreal-']
            for header_prefix in epic_headers:
                for header_name in headers.keys():
                    if header_prefix in header_name:
                        matches.append(True)
                        analysis['indicators'].append(f"Epic header: {header_name}")
                        break
                        
            # Server analysis
            server = headers.get('server', '')
            if 'cloudfront' in server or 'amazon' in server:
                # Epic uses AWS CloudFront
                matches.append(True)
                analysis['indicators'].append("Uses CloudFront (Epic infrastructure)")
                
            # Content analysis
            json_keywords = ['account', 'oauth', 'token', 'profile', 'friends']
            for keyword in json_keywords:
                if keyword in response_str:
                    matches.append(True)
                    analysis['indicators'].append(f"Contains Epic API keyword: {keyword}")
                    break
                    
            # Error message analysis
            if 'epic games' in response_str or 'fortnite' in response_str:
                matches.append(True)
                analysis['indicators'].append("Contains Epic Games branding")
                
            analysis['confidence'] = self.calculate_confidence(matches)
            
            if analysis['confidence'] > 0.7:
                analysis['app'] = 'Fortnite/Epic Games'
            elif analysis['confidence'] > 0.4:
                analysis['app'] = 'Possible Epic Games'
                
        # XMPP response analysis
        elif b'<?xml' in response and b'stream:stream' in response:
            analysis['service'] = 'XMPP'
            if b'prod.ol.epicgames.com' in response or b'epicgames' in response:
                analysis['confidence'] = 0.9
                analysis['app'] = 'Fortnite XMPP'
                analysis['indicators'].append("Epic Games XMPP server detected")
            else:
                analysis['confidence'] = 0.3
                analysis['indicators'].append("XMPP server detected")
                
        # TLS response analysis
        elif response.startswith(b'\x16\x03'):
            analysis['service'] = 'TLS/SSL'
            if len(response) > 50:
                analysis['confidence'] = 0.3
                analysis['indicators'].append("TLS handshake received")
                
        # Game protocol analysis
        elif port in [5795, 9000, 9001, 9002]:
            if len(response) >= 4:
                # Check for Unreal Engine patterns
                if response[:4] == b'\x00\x00\x00\x00' or b'CONNECT' in response[:8]:
                    analysis['service'] = 'Game Protocol'
                    analysis['confidence'] = 0.7
                    analysis['app'] = 'Fortnite Game'
                    analysis['indicators'].append("Unreal Engine protocol detected")
                else:
                    analysis['service'] = 'Unknown Binary'
                    analysis['confidence'] = 0.2
                    analysis['indicators'].append("Binary response on game port")
                    
        return analysis
        
    def get_fingerprint_patterns(self) -> Dict[str, bytes]:
        """Get Fortnite fingerprint patterns"""
        return {
            'epic_domain': b'epicgames.com',
            'fortnite_service': b'fortnite-public-service',
            'launcher_service': b'launcher-public-service',
            'epic_oauth': b'/account/api/oauth/',
            'fortnite_profile': b'/fortnite/api/game/',
            'unreal_engine': b'unrealengine',
            'epic_xmpp': b'prod.ol.epicgames.com',
            'game_connect': b'CONNECT'
        }
        
    def get_timing_profile(self) -> Dict[str, float]:
        """Fortnite-specific timing profile"""
        return {
            'initial_delay': random.uniform(0.05, 0.3),
            'probe_interval': 0.1,
            'response_timeout': 3.0,
            'retry_delay': 0.8
        }
