"""
Scan scheduling and coordination module
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from queue import Queue

from .injector import ProbeInjector
from .collector import ResponseCollector
from utils.logger import setup_logger

class ScanScheduler:
    """Coordinates and schedules reconnaissance scans"""
    
    def __init__(self, target: str, ports: List[int], profile=None, 
                 threads: int = 10, timeout: int = 5, fingerprinter=None):
        self.target = target
        self.ports = ports
        self.profile = profile
        self.threads = min(threads, len(ports))  # Don't create more threads than ports
        self.timeout = timeout
        self.fingerprinter = fingerprinter
        
        self.logger = setup_logger(__name__)
        self.injector = ProbeInjector(target, timeout)
        self.collector = ResponseCollector()
        
        self.results = {}
        self.scan_progress = {'completed': 0, 'total': len(ports)}
        self._lock = threading.Lock()
        
    def execute(self) -> Dict[str, Any]:
        """
        Execute the complete scan
        """
        self.logger.info(f"Starting scan of {self.target} on {len(self.ports)} ports with {self.threads} threads")
        start_time = time.time()
        
        # Execute scan based on threading preference
        if self.threads == 1:
            results = self._execute_sequential()
        else:
            results = self._execute_parallel()
            
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        
        # Generate final results
        final_results = {
            'target': self.target,
            'scan_duration': scan_duration,
            'ports_scanned': len(self.ports),
            'profile_used': self.profile.name if self.profile else None,
            'results': results,
            'summary': self.collector.generate_summary(self.target)
        }
        
        return final_results
        
    def _execute_sequential(self) -> Dict[str, Any]:
        """
        Execute scan sequentially (single-threaded)
        """
        results = {}
        
        for i, port in enumerate(self.ports):
            self.logger.debug(f"Scanning port {port} ({i+1}/{len(self.ports)})")
            
            # Scan single port
            port_result = self._scan_port(port)
            results[f"{self.target}:{port}"] = port_result
            
            # Update progress
            with self._lock:
                self.scan_progress['completed'] += 1
                
            # Small delay between ports to avoid overwhelming target
            if i < len(self.ports) - 1:
                time.sleep(0.1)
                
        return results
        
    def _execute_parallel(self) -> Dict[str, Any]:
        """
        Execute scan in parallel using ThreadPoolExecutor
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(self._scan_port, port): port 
                for port in self.ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                
                try:
                    port_result = future.result(timeout=self.timeout + 5)
                    results[f"{self.target}:{port}"] = port_result
                    
                    self.logger.debug(f"Completed scan of port {port}")
                    
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {e}")
                    results[f"{self.target}:{port}"] = {
                        'port': port,
                        'status': 'error',
                        'error': str(e),
                        'probes': []
                    }
                    
                # Update progress
                with self._lock:
                    self.scan_progress['completed'] += 1
                    
        return results
        
    def _scan_port(self, port: int) -> Dict[str, Any]:
        """
        Scan a single port with probes
        """
        port_result = {
            'port': port,
            'status': 'closed',
            'service': 'unknown',
            'probes': [],
            'response_analysis': {},
            'fingerprint': None
        }
        
        try:
            # First, check if port is open
            connection_info = self.injector.get_connection_info(port)
            
            if not connection_info['open']:
                port_result['status'] = 'closed'
                port_result['response_time'] = connection_info['response_time']
                return port_result
                
            port_result['status'] = 'open'
            port_result['response_time'] = connection_info['response_time']
            
            # Inject probes
            if self.profile:
                probe_results = self.injector.inject_with_profile(port, self.profile)
            else:
                # **MODIFIED CODE BLOCK**
                # Default probes
                default_probes = [
                    # Standard HTTP GET probe
                    b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n",
                    # Add a basic TLS Client Hello probe for detecting HTTPS
                    b'\x16\x03\x01\x00\xce\x01\x00\x00\xca\x03\x03' + b'\x00' * 32 + b'\x00\x00\x20' + b'\xc0\x2c\xc0\x30\x00\x9f\xcc\xa9\xcc\xa8\xcc\xaa\xc0\x2b\xc0\x2f\x00\x9e\xc0\x24\xc0\x28\x00\x6b\xc0\x23\xc0\x27\x00\x67\xc0\x0a\xc0\x14\x00\x39\xc0\x09\xc0\x13\x00\x33' + b'\x01\x00'
                ]
                probe_results = self.injector.inject_probes(port, default_probes, ['http_get', 'tls_hello'])
                
            port_result['probes'] = probe_results
            
            # Collect responses
            self.collector.collect_batch(probe_results, self.target)
            
            # Analyze responses
            if probe_results:
                port_result['response_analysis'] = self.collector.analyze_responses(self.target, port)
                
                # Use profile to analyze responses if available
                if self.profile:
                    for probe_result in probe_results:
                        if probe_result.get('success') and probe_result.get('response'):
                            profile_analysis = self.profile.analyze_response(
                                probe_result['response'], 
                                port
                            )
                            
                            # Update service info based on profile analysis
                            if profile_analysis.get('service') != 'unknown':
                                port_result['service'] = profile_analysis['service']
                                
                            if profile_analysis.get('app'):
                                port_result['app'] = profile_analysis['app']
                                port_result['confidence'] = profile_analysis.get('confidence', 0.0)
                                
                            break
                            
                # Use fingerprinter if available
                if self.fingerprinter:
                    fingerprint_result = self.fingerprinter.fingerprint_port(
                        self.target, port, probe_results
                    )
                    if fingerprint_result:
                        port_result['fingerprint'] = fingerprint_result
                        
                        # Update service info from fingerprinting
                        if 'service' in fingerprint_result and fingerprint_result['service'] != 'unknown':
                            port_result['service'] = fingerprint_result['service']
                            
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {e}")
            port_result['status'] = 'error'
            port_result['error'] = str(e)
            
        return port_result
        
    def get_progress(self) -> Dict[str, Any]:
        """
        Get current scan progress
        """
        with self._lock:
            return self.scan_progress.copy()
            
    def is_complete(self) -> bool:
        """
        Check if scan is complete
        """
        progress = self.get_progress()
        return progress['completed'] >= progress['total']
        
    def get_intermediate_results(self) -> Dict[str, Any]:
        """
        Get results collected so far (for monitoring progress)
        """
        return {
            'progress': self.get_progress(),
            'collector_stats': self.collector.get_statistics(),
            'summary': self.collector.generate_summary(self.target) if self.collector.get_statistics()['total_responses'] > 0 else None
        }
        
    def pause_scan(self):
        """
        Pause the scan (implementation depends on execution model)
        """
        self.logger.info("Pause requested (not implemented in current version)")
        
    def resume_scan(self):
        """
        Resume paused scan
        """
        self.logger.info("Resume requested (not implemented in current version)")
        
    def cancel_scan(self):
        """
        Cancel ongoing scan
        """
        self.logger.info("Scan cancellation requested")
        
class AdaptiveScheduler(ScanScheduler):
    """
    Advanced scheduler with adaptive timing and load balancing
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response_times = []
        self.failure_count = 0
        self.adaptive_delay = 0.1
        
    def _scan_port(self, port: int) -> Dict[str, Any]:
        """
        Enhanced port scanning with adaptive timing
        """
        if len(self.response_times) > 3:
            avg_response_time = sum(self.response_times[-5:]) / min(5, len(self.response_times))
            if avg_response_time > 2.0:
                self.adaptive_delay = min(1.0, avg_response_time * 0.5)
            time.sleep(self.adaptive_delay)
            
        start_time = time.time()
        result = super()._scan_port(port)
        scan_time = time.time() - start_time
        
        self.response_times.append(scan_time)
        if len(self.response_times) > 20: 
            self.response_times.pop(0)
            
        if result.get('status') == 'error':
            self.failure_count += 1
            if self.failure_count > 5:
                self.adaptive_delay = min(2.0, self.adaptive_delay * 1.5)
        else:
            self.failure_count = 0
            
        return result
