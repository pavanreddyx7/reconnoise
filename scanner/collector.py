"""
Response collection and analysis module
"""

import time
import threading
from typing import Dict, List, Any, Optional
from collections import defaultdict
from utils.logger import setup_logger

class ResponseCollector:
    """Collects and processes probe responses"""
    
    def __init__(self):
        self.logger = setup_logger(__name__)
        self.responses = defaultdict(list)
        self.metadata = {}
        self._lock = threading.Lock()
        
    def collect_response(self, target: str, port: int, probe_name: str, 
                        response_data: bytes, metadata: Dict[str, Any] = None):
        """
        Collect a single response
        """
        timestamp = time.time()
        
        response_record = {
            'target': target,
            'port': port,
            'probe_name': probe_name,
            'response': response_data,
            'timestamp': timestamp,
            'size': len(response_data),
            'metadata': metadata or {}
        }
        
        with self._lock:
            key = f"{target}:{port}"
            self.responses[key].append(response_record)
            
        self.logger.debug(f"Collected response from {target}:{port} "
                         f"({len(response_data)} bytes) for probe {probe_name}")
                         
    def collect_batch(self, results: List[Dict[str, Any]], target: str):
        """
        Collect multiple responses from injection results
        """
        for result in results:
            if result.get('success', False) and result.get('response'):
                self.collect_response(
                    target=target,
                    port=result['port'],
                    probe_name=result.get('probe_name', 'unknown'),
                    response_data=result['response'],
                    metadata={
                        'response_time': result.get('response_time', 0.0),
                        'connection_time': result.get('connection_time', 0.0),
                        'error': result.get('error')
                    }
                )
                
    def get_responses(self, target: str, port: int = None) -> List[Dict[str, Any]]:
        """
        Get collected responses for target (and optionally specific port)
        """
        with self._lock:
            if port is not None:
                key = f"{target}:{port}"
                return self.responses.get(key, []).copy()
            else:
                # Return all responses for target
                all_responses = []
                for key, responses in self.responses.items():
                    if key.startswith(f"{target}:"):
                        all_responses.extend(responses)
                return all_responses
                
    def analyze_responses(self, target: str, port: int) -> Dict[str, Any]:
        """
        Analyze collected responses for patterns
        """
        responses = self.get_responses(target, port)
        
        if not responses:
            return {
                'total_responses': 0,
                'successful_probes': 0,
                'response_sizes': [],
                'patterns': [],
                'timing_analysis': {}
            }
            
        analysis = {
            'total_responses': len(responses),
            'successful_probes': len([r for r in responses if len(r['response']) > 0]),
            'response_sizes': [r['size'] for r in responses],
            'patterns': [],
            'timing_analysis': {},
            'probe_success_rate': {}
        }
        
        # Timing analysis
        response_times = [r['metadata'].get('response_time', 0) for r in responses]
        if response_times:
            analysis['timing_analysis'] = {
                'avg_response_time': sum(response_times) / len(response_times),
                'min_response_time': min(response_times),
                'max_response_time': max(response_times),
                'total_time': sum(response_times)
            }
            
        # Probe success rate analysis
        probe_stats = defaultdict(lambda: {'total': 0, 'successful': 0})
        for response in responses:
            probe_name = response['probe_name']
            probe_stats[probe_name]['total'] += 1
            if response['size'] > 0:
                probe_stats[probe_name]['successful'] += 1
                
        for probe_name, stats in probe_stats.items():
            if stats['total'] > 0:
                analysis['probe_success_rate'][probe_name] = stats['successful'] / stats['total']
                
        # Pattern detection
        analysis['patterns'] = self._detect_patterns(responses)
        
        return analysis
        
    def _detect_patterns(self, responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect common patterns in responses
        """
        patterns = []
        
        if not responses:
            return patterns
            
        # HTTP pattern detection
        http_responses = [r for r in responses if r['response'].startswith(b'HTTP/')]
        if http_responses:
            patterns.append({
                'type': 'HTTP',
                'count': len(http_responses),
                'description': 'HTTP protocol responses detected'
            })
            
            # Analyze HTTP status codes
            status_codes = []
            for response in http_responses:
                try:
                    status_line = response['response'].split(b'\n')[0].decode('utf-8', errors='ignore')
                    if ' ' in status_line:
                        parts = status_line.split(' ')
                        if len(parts) >= 2 and parts[1].isdigit():
                            status_codes.append(int(parts[1]))
                except:
                    continue
                    
            if status_codes:
                patterns.append({
                    'type': 'HTTP_STATUS',
                    'values': status_codes,
                    'description': f'HTTP status codes: {set(status_codes)}'
                })
                
        # TLS pattern detection
        tls_responses = [r for r in responses if r['response'].startswith(b'\x16\x03')]
        if tls_responses:
            patterns.append({
                'type': 'TLS',
                'count': len(tls_responses),
                'description': 'TLS/SSL handshake responses detected'
            })
            
        # Binary pattern detection
        binary_responses = [r for r in responses if self._is_binary(r['response'])]
        if binary_responses:
            patterns.append({
                'type': 'BINARY',
                'count': len(binary_responses),
                'description': 'Binary protocol responses detected'
            })
            
        # Size pattern detection
        response_sizes = [r['size'] for r in responses if r['size'] > 0]
        if response_sizes:
            avg_size = sum(response_sizes) / len(response_sizes)
            if avg_size > 10000:  # Large responses
                patterns.append({
                    'type': 'LARGE_RESPONSE',
                    'avg_size': avg_size,
                    'description': f'Large responses detected (avg: {avg_size:.0f} bytes)'
                })
                
        return patterns
        
    def _is_binary(self, data: bytes) -> bool:
        """
        Determine if data appears to be binary
        """
        if len(data) == 0:
            return False
            
        # Check for null bytes or high percentage of non-printable chars
        null_count = data.count(b'\x00')
        if null_count > 0:
            return True
            
        try:
            decoded = data.decode('utf-8')
            # If it decodes cleanly and has mostly printable chars, probably text
            printable_count = sum(1 for c in decoded if c.isprintable() or c.isspace())
            return printable_count / len(decoded) < 0.7
        except UnicodeDecodeError:
            return True
            
    def generate_summary(self, target: str) -> Dict[str, Any]:
        """
        Generate summary of all collected responses for a target
        """
        all_responses = self.get_responses(target)
        
        if not all_responses:
            return {
                'target': target,
                'total_responses': 0,
                'ports_responded': 0,
                'summary': 'No responses collected'
            }
            
        # Group by port
        ports_data = defaultdict(list)
        for response in all_responses:
            ports_data[response['port']].append(response)
            
        summary = {
            'target': target,
            'total_responses': len(all_responses),
            'ports_responded': len(ports_data),
            'port_analysis': {},
            'overall_patterns': [],
            'timing_summary': {}
        }
        
        # Analyze each port
        for port, port_responses in ports_data.items():
            port_analysis = self.analyze_responses(target, port)
            summary['port_analysis'][port] = port_analysis
            
        # Overall timing analysis
        all_times = []
        for response in all_responses:
            if 'response_time' in response['metadata']:
                all_times.append(response['metadata']['response_time'])
                
        if all_times:
            summary['timing_summary'] = {
                'total_scan_time': sum(all_times),
                'avg_response_time': sum(all_times) / len(all_times),
                'fastest_response': min(all_times),
                'slowest_response': max(all_times)
            }
            
        # Overall patterns
        all_patterns = []
        for port_analysis in summary['port_analysis'].values():
            all_patterns.extend(port_analysis['patterns'])
            
        # Consolidate patterns
        pattern_counts = defaultdict(int)
        for pattern in all_patterns:
            pattern_counts[pattern['type']] += pattern.get('count', 1)
            
        summary['overall_patterns'] = [
            {'type': ptype, 'total_count': count}
            for ptype, count in pattern_counts.items()
        ]
        
        return summary
        
    def export_responses(self, target: str, format: str = 'dict') -> Any:
        """
        Export collected responses in various formats
        """
        responses = self.get_responses(target)
        
        if format == 'dict':
            return {
                'target': target,
                'responses': responses,
                'summary': self.generate_summary(target)
            }
        elif format == 'json':
            import json
            data = self.export_responses(target, 'dict')
            # Convert bytes to base64 for JSON serialization
            import base64
            for response in data['responses']:
                response['response_b64'] = base64.b64encode(response['response']).decode()
                del response['response']
            return json.dumps(data, indent=2, default=str)
        elif format == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow(['target', 'port', 'probe_name', 'timestamp', 'size', 'response_time'])
            
            # Data
            for response in responses:
                writer.writerow([
                    response['target'],
                    response['port'],
                    response['probe_name'],
                    response['timestamp'],
                    response['size'],
                    response['metadata'].get('response_time', 0)
                ])
                
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
            
    def clear_responses(self, target: str = None):
        """
        Clear collected responses for target or all targets
        """
        with self._lock:
            if target:
                keys_to_remove = [k for k in self.responses.keys() if k.startswith(f"{target}:")]
                for key in keys_to_remove:
                    del self.responses[key]
                self.logger.info(f"Cleared responses for target {target}")
            else:
                self.responses.clear()
                self.logger.info("Cleared all responses")
                
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall collector statistics
        """
        with self._lock:
            total_responses = sum(len(responses) for responses in self.responses.values())
            total_targets = len(set(key.split(':')[0] for key in self.responses.keys()))
            total_ports = len(self.responses.keys())
            
            return {
                'total_responses': total_responses,
                'total_targets': total_targets,
                'total_ports': total_ports,
                'targets': list(set(key.split(':')[0] for key in self.responses.keys()))
            }
