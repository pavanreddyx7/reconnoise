"""
Probe injection engine for sending crafted traffic
"""

import socket
import time
import threading
from typing import List, Dict, Any, Optional, Callable
from utils.logger import setup_logger

class ProbeInjector:
    """Handles injection of probes to target services"""
    
    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
        self.logger = setup_logger(__name__)
        self._results = {}
        self._lock = threading.Lock()
        
    def inject_probe(self, port: int, probe: bytes, probe_name: str = "unknown") -> Dict[str, Any]:
        """
        Inject a single probe to target:port
        Returns response data and metadata
        """
        result = {
            'port': port,
            'probe_name': probe_name,
            'response': b'',
            'success': False,
            'error': None,
            'response_time': 0.0,
            'connection_time': 0.0
        }
        
        start_time = time.time()
        sock = None
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect
            connect_start = time.time()
            sock.connect((self.target, port))
            connect_end = time.time()
            
            result['connection_time'] = connect_end - connect_start
            
            # Send probe
            sock.send(probe)
            
            # Receive response
            response = b''
            try:
                # Try to receive data in chunks
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    
                    # Stop after reasonable amount of data or timeout
                    if len(response) > 65536:  # 64KB max
                        break
                        
            except socket.timeout:
                # Timeout is expected for some probes
                pass
            except Exception:
                # Other errors during receive
                pass
                
            result['response'] = response
            result['success'] = True
            
        except socket.timeout:
            result['error'] = 'Connection timeout'
            self.logger.debug(f"Timeout connecting to {self.target}:{port}")
            
        except ConnectionRefused:
            result['error'] = 'Connection refused'
            self.logger.debug(f"Connection refused {self.target}:{port}")
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.debug(f"Error probing {self.target}:{port}: {e}")
            
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
                    
        result['response_time'] = time.time() - start_time
        
        return result
        
    def inject_probes(self, port: int, probes: List[bytes], probe_names: List[str] = None) -> List[Dict[str, Any]]:
        """
        Inject multiple probes to a single port
        Returns list of results
        """
        if probe_names is None:
            probe_names = [f"probe_{i}" for i in range(len(probes))]
            
        results = []
        
        for i, probe in enumerate(probes):
            probe_name = probe_names[i] if i < len(probe_names) else f"probe_{i}"
            
            # Add small delay between probes
            if i > 0:
                time.sleep(0.1)
                
            result = self.inject_probe(port, probe, probe_name)
            results.append(result)
            
            # If we got a good response, we might not need more probes
            if result['success'] and len(result['response']) > 0:
                self.logger.debug(f"Got response from {probe_name} on port {port}")
                
        return results
        
    def inject_with_profile(self, port: int, profile) -> List[Dict[str, Any]]:
        """
        Inject probes using a traffic profile
        """
        if not profile:
            # Default probes without profile
            default_probes = [
                b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n",
                b"\x16\x03\x01\x00\x01\x01\x00",  # TLS handshake start
                b"CONNECT " + self.target.encode() + b":80 HTTP/1.1\r\n\r\n"
            ]
            return self.inject_probes(port, default_probes, ['http_get', 'tls_hello', 'http_connect'])
            
        # Get timing profile
        timing = profile.get_timing_profile()
        
        # Apply initial delay
        time.sleep(timing.get('initial_delay', 0.1))
        
        # Get probes from profile
        probes = profile.get_probes(port)
        
        if not probes:
            self.logger.debug(f"No probes available for port {port} in profile {profile.name}")
            return []
            
        probe_names = [f"{profile.name.lower()}_{i}" for i in range(len(probes))]
        
        # Inject probes with profile-specific timing
        results = []
        for i, probe in enumerate(probes):
            if i > 0:
                time.sleep(timing.get('probe_interval', 0.1))
                
            result = self.inject_probe(port, probe, probe_names[i])
            results.append(result)
            
        return results
        
    def batch_inject(self, port_probe_map: Dict[int, List[bytes]], 
                    callback: Optional[Callable] = None) -> Dict[int, List[Dict[str, Any]]]:
        """
        Inject probes to multiple ports
        port_probe_map: {port: [probe1, probe2, ...]}
        """
        results = {}
        
        for port, probes in port_probe_map.items():
            self.logger.debug(f"Injecting {len(probes)} probes to port {port}")
            
            port_results = self.inject_probes(port, probes)
            results[port] = port_results
            
            if callback:
                callback(port, port_results)
                
        return results
        
    def threaded_inject(self, port: int, probes: List[bytes], 
                       probe_names: List[str] = None) -> List[Dict[str, Any]]:
        """
        Inject probes using threading for parallel execution
        """
        results = [None] * len(probes)
        threads = []
        
        if probe_names is None:
            probe_names = [f"probe_{i}" for i in range(len(probes))]
            
        def inject_single(index, probe, name):
            try:
                result = self.inject_probe(port, probe, name)
                with self._lock:
                    results[index] = result
            except Exception as e:
                self.logger.error(f"Thread error injecting probe {name}: {e}")
                with self._lock:
                    results[index] = {
                        'port': port,
                        'probe_name': name,
                        'response': b'',
                        'success': False,
                        'error': str(e),
                        'response_time': 0.0,
                        'connection_time': 0.0
                    }
                    
        # Create and start threads
        for i, (probe, name) in enumerate(zip(probes, probe_names)):
            thread = threading.Thread(
                target=inject_single,
                args=(i, probe, name)
            )
            thread.daemon = True
            threads.append(thread)
            thread.start()
            
            # Small delay between thread starts
            time.sleep(0.05)
            
        # Wait for all threads
        for thread in threads:
            thread.join(timeout=self.timeout + 2)
            
        # Filter out None results (failed threads)
        return [r for r in results if r is not None]
        
    def get_connection_info(self, port: int) -> Dict[str, Any]:
        """
        Get basic connection information without sending probes
        """
        info = {
            'port': port,
            'open': False,
            'service': 'unknown',
            'response_time': 0.0
        }
        
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((self.target, port))
            info['open'] = True
            
            sock.close()
            
        except Exception:
            info['open'] = False
            
        info['response_time'] = time.time() - start_time
        
        return info
