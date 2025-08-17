"""
Parsing utilities for ports and results handling
"""

import re
from typing import List, Dict, Any, Optional, Union

class PortParser:
    """Utility class for parsing port specifications"""
    
    @staticmethod
    def parse_ports(port_spec: str) -> List[int]:
        """
        Parse port specification into list of port numbers
        
        Supported formats:
        - Single port: "80"
        - Multiple ports: "80,443,8080"
        - Port range: "1-1000"
        - Mixed: "22,80,443,8000-8010"
        """
        if not port_spec:
            return []
            
        ports = set()
        
        # Split by commas
        parts = [part.strip() for part in port_spec.split(',')]
        
        for part in parts:
            if not part:
                continue
                
            # Check if it's a range
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    # Validate range
                    if start_port > end_port:
                        start_port, end_port = end_port, start_port
                        
                    if start_port < 1 or end_port > 65535:
                        raise ValueError(f"Port range {start_port}-{end_port} is invalid")
                        
                    # Limit range size to prevent excessive port lists
                    if end_port - start_port > 10000:
                        raise ValueError(f"Port range too large: {start_port}-{end_port}")
                        
                    ports.update(range(start_port, end_port + 1))
                    
                except ValueError as e:
                    raise ValueError(f"Invalid port range '{part}': {e}")
                    
            else:
                # Single port
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port {port} is out of valid range (1-65535)")
                    ports.add(port)
                except ValueError:
                    raise ValueError(f"Invalid port number '{part}'")
                    
        return sorted(list(ports))
        
    @staticmethod
    def get_common_ports() -> List[int]:
        """Get list of commonly scanned ports"""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000
        ]
        
    @staticmethod
    def get_top_ports(count: int = 1000) -> List[int]:
        """Get top N most common ports"""
        # This would typically come from a database or file
        # For now, return a reasonable subset
        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9001,
            20, 69, 123, 161, 162, 389, 636, 873, 1433, 1521, 2049, 2121,
            3000, 5000, 5001, 5222, 5432, 5672, 5984, 6000, 6001, 6379,
            7000, 7001, 8000, 8001, 8008, 8081, 8888, 9080, 9090, 9200,
            27017, 27018, 27019, 28017
        ]
        
        # Extend with additional sequential ports if needed
        while len(top_ports) < count and len(top_ports) < 65535:
            next_port = max(top_ports) + 1
            if next_port <= 65535:
                top_ports.append(next_port)
            else:
                break
                
        return top_ports[:count]
        
    @staticmethod
    def validate_port_list(ports: List[int]) -> bool:
        """Validate a list of port numbers"""
        if not ports:
            return False
            
        for port in ports:
            if not isinstance(port, int) or port < 1 or port > 65535:
                return False
                
        return True

class ResultsHandler:
    """Utility class for handling and processing scan results"""
    
    def __init__(self, results: Dict[str, Any]):
        self.results = results
        
    def filter_open_ports(self) -> Dict[str, Any]:
        """Filter results to show only open ports"""
        filtered = {}
        
        if 'results' in self.results:
            for target_port, data in self.results['results'].items():
                if data.get('status') == 'open':
                    filtered[target_port] = data
                    
        return filtered
        
    def get_services_summary(self) -> Dict[str, List[str]]:
        """Get summary of identified services"""
        services = {}
        
        if 'results' in self.results:
            for target_port, data in self.results['results'].items():
                service = data.get('service', 'unknown')
                if service not in services:
                    services[service] = []
                services[service].append(target_port)
                
        return services
        
    def get_applications_summary(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get summary of identified applications"""
        applications = {}
        
        if 'results' in self.results:
            for target_port, data in self.results['results'].items():
                app = data.get('app')
                if app:
                    if app not in applications:
                        applications[app] = []
                    applications[app].append({
                        'target_port': target_port,
                        'confidence': data.get('confidence', 0.0),
                        'service': data.get('service', 'unknown')
                    })
                    
        return applications
        
    def get_high_confidence_results(self, min_confidence: float = 0.7) -> Dict[str, Any]:
        """Get results with confidence above threshold"""
        high_confidence = {}
        
        if 'results' in self.results:
            for target_port, data in self.results['results'].items():
                confidence = data.get('confidence', 0.0)
                if confidence >= min_confidence:
                    high_confidence[target_port] = data
                    
        return high_confidence
        
    def export_csv(self) -> str:
        """Export results to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'target_port', 'status', 'service', 'application', 
            'confidence', 'response_time', 'version', 'fingerprint'
        ])
        
        # Data
        if 'results' in self.results:
            for target_port, data in self.results['results'].items():
                writer.writerow([
                    target_port,
                    data.get('status', ''),
                    data.get('service', ''),
                    data.get('app', ''),
                    data.get('confidence', ''),
                    data.get('response_time', ''),
                    data.get('version', ''),
                    str(data.get('fingerprint', {}).get('service', ''))
                ])
                
        return output.getvalue()
        
    def export_json(self, pretty: bool = True) -> str:
        """Export results to JSON format"""
        import json
        
        if pretty:
            return json.dumps(self.results, indent=2, default=str)
        else:
            return json.dumps(self.results, default=str)
            
    def export_xml(self) -> str:
        """Export results to XML format"""
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append('<reconnoise_results>')
        
        # Metadata
        lines.append(f'  <target>{self.results.get("target", "")}</target>')
        lines.append(f'  <scan_duration>{self.results.get("scan_duration", 0):.2f}</scan_duration>')
        lines.append(f'  <ports_scanned>{self.results.get("ports_scanned", 0)}</ports_scanned>')
        
        # Results
        if 'results' in self.results:
            lines.append('  <scan_results>')
            for target_port, data in self.results['results'].items():
                lines.append(f'    <port_result target_port="{target_port}">')
                
                for key, value in data.items():
                    if key not in ['probes', 'response_analysis', 'fingerprint']:
                        lines.append(f'      <{key}>{self._escape_xml(str(value))}</{key}>')
                        
                lines.append('    </port_result>')
            lines.append('  </scan_results>')
            
        lines.append('</reconnoise_results>')
        return '\n'.join(lines)
        
    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters"""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&apos;')
        
    def enrich_results(self, fingerprinter) -> Dict[str, Any]:
        """
        Enrich results with additional analysis using fingerprinter
        """
        if not fingerprinter or 'results' not in self.results:
            return self.results
            
        enriched = self.results.copy()
        
        for target_port, data in enriched['results'].items():
            # Add fingerprint information if not already present
            if 'fingerprint' not in data or not data['fingerprint']:
                probe_results = data.get('probes', [])
                if probe_results:
                    try:
                        target, port_str = target_port.split(':')
                        port = int(port_str)
                        fingerprint = fingerprinter.fingerprint_port(target, port, probe_results)
                        data['enhanced_fingerprint'] = fingerprint
                    except (ValueError, AttributeError):
                        pass
                        
            # Calculate overall confidence score
            confidences = []
            if 'confidence' in data:
                confidences.append(data['confidence'])
            if 'fingerprint' in data and isinstance(data['fingerprint'], dict):
                if 'confidence' in data['fingerprint']:
                    confidences.append(data['fingerprint']['confidence'])
                    
            if confidences:
                data['overall_confidence'] = sum(confidences) / len(confidences)
                
        return enriched
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistical summary of results"""
        stats = {
            'total_ports_scanned': self.results.get('ports_scanned', 0),
            'scan_duration': self.results.get('scan_duration', 0),
            'open_ports': 0,
            'closed_ports': 0,
            'error_ports': 0,
            'services_identified': 0,
            'applications_identified': 0,
            'high_confidence_results': 0
        }
        
        if 'results' in self.results:
            for data in self.results['results'].values():
                status = data.get('status', 'unknown')
                if status == 'open':
                    stats['open_ports'] += 1
                elif status == 'closed':
                    stats['closed_ports'] += 1
                elif status == 'error':
                    stats['error_ports'] += 1
                    
                if data.get('service', 'unknown') != 'unknown':
                    stats['services_identified'] += 1
                    
                if data.get('app'):
                    stats['applications_identified'] += 1
                    
                if data.get('confidence', 0) > 0.7:
                    stats['high_confidence_results'] += 1
                    
        return stats
