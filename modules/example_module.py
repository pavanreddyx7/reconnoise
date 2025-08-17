"""
Example module/plugin for Reconnoise
This demonstrates how to create custom modules for extended functionality
"""

import json
from typing import Dict, List, Any, Optional
from utils.logger import setup_logger

class ExampleModule:
    """
    Example module showing how to extend Reconnoise functionality
    """
    
    def __init__(self):
        self.logger = setup_logger(__name__)
        self.name = "Example Module"
        self.version = "1.0.0"
        self.description = "Demonstrates custom module functionality"
        
    def process_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process scan results and add custom analysis
        """
        self.logger.info(f"Processing results with {self.name}")
        
        processed_results = results.copy()
        
        # Add custom analysis
        processed_results['custom_analysis'] = {
            'module_name': self.name,
            'module_version': self.version,
            'analysis': self._analyze_results(results)
        }
        
        return processed_results
        
    def _analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Custom analysis logic"""
        analysis = {
            'security_score': 0,
            'risk_level': 'low',
            'recommendations': [],
            'interesting_ports': [],
            'potential_vulnerabilities': []
        }
        
        if 'results' not in results:
            return analysis
            
        open_ports = []
        services = {}
        
        # Analyze each port result
        for target_port, data in results['results'].items():
            if data.get('status') == 'open':
                port = data.get('port')
                service = data.get('service', 'unknown')
                
                open_ports.append(port)
                services[service] = services.get(service, 0) + 1
                
                # Check for interesting ports
                if self._is_interesting_port(port, service):
                    analysis['interesting_ports'].append({
                        'port': port,
                        'service': service,
                        'reason': self._get_port_interest_reason(port, service)
                    })
                    
                # Check for potential vulnerabilities
                vulns = self._check_vulnerabilities(port, service, data)
                analysis['potential_vulnerabilities'].extend(vulns)
                
        # Calculate security score
        analysis['security_score'] = self._calculate_security_score(
            open_ports, services, analysis['potential_vulnerabilities']
        )
        
        # Determine risk level
        if analysis['security_score'] >= 80:
            analysis['risk_level'] = 'high'
        elif analysis['security_score'] >= 60:
            analysis['risk_level'] = 'medium'
        else:
            analysis['risk_level'] = 'low'
            
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(
            open_ports, services, analysis['potential_vulnerabilities']
        )
        
        return analysis
        
    def _is_interesting_port(self, port: int, service: str) -> bool:
        """Check if port/service combination is interesting"""
        interesting_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 3306, 3389, 5432, 6379]
        interesting_services = ['ftp', 'ssh', 'telnet', 'smtp', 'mysql', 'postgresql', 'redis']
        
        return port in interesting_ports or service in interesting_services
        
    def _get_port_interest_reason(self, port: int, service: str) -> str:
        """Get reason why port is interesting"""
        reasons = {
            21: "FTP service - check for anonymous access",
            22: "SSH service - check for weak authentication",
            23: "Telnet service - unencrypted communication",
            25: "SMTP service - potential for email relay",
            135: "RPC service - Windows management interface",
            139: "NetBIOS - file sharing service",
            445: "SMB service - file sharing, potential for lateral movement",
            1433: "SQL Server - database access",
            3306: "MySQL database - check for weak credentials",
            3389: "RDP service - remote desktop access",
            5432: "PostgreSQL database - check for default credentials",
            6379: "Redis service - often lacks authentication"
        }
        
        return reasons.get(port, f"Service {service} may require security review")
        
    def _check_vulnerabilities(self, port: int, service: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for potential vulnerabilities"""
        vulnerabilities = []
        
        # Example vulnerability checks
        if port == 21 and service == 'ftp':
            vulnerabilities.append({
                'type': 'potential_weak_service',
                'port': port,
                'service': service,
                'description': 'FTP service detected - check for anonymous access',
                'severity': 'medium'
            })
            
        if port == 23:
            vulnerabilities.append({
                'type': 'insecure_protocol',
                'port': port,
                'service': service,
                'description': 'Telnet uses unencrypted communication',
                'severity': 'high'
            })
            
        if port in [3306, 5432] and service in ['mysql', 'postgresql']:
            vulnerabilities.append({
                'type': 'database_exposure',
                'port': port,
                'service': service,
                'description': 'Database service exposed - verify access controls',
                'severity': 'high'
            })
            
        if port == 6379 and service == 'redis':
            vulnerabilities.append({
                'type': 'unauthenticated_service',
                'port': port,
                'service': service,
                'description': 'Redis service often lacks authentication',
                'severity': 'high'
            })
            
        return vulnerabilities
        
    def _calculate_security_score(self, open_ports: List[int], services: Dict[str, int], 
                                vulns: List[Dict[str, Any]]) -> int:
        """Calculate security score (0-100, higher = more risk)"""
        score = 0
        
        # Base score for number of open ports
        score += min(len(open_ports) * 2, 20)
        
        # Score for dangerous services
        dangerous_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 6379]
        for port in open_ports:
            if port in dangerous_ports:
                score += 10
                
        # Score for vulnerabilities
        for vuln in vulns:
            severity = vuln.get('severity', 'low')
            if severity == 'high':
                score += 20
            elif severity == 'medium':
                score += 10
            else:
                score += 5
                
        return min(score, 100)
        
    def _generate_recommendations(self, open_ports: List[int], services: Dict[str, int], 
                                vulns: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if len(open_ports) > 10:
            recommendations.append("Consider closing unnecessary ports to reduce attack surface")
            
        if 23 in open_ports:
            recommendations.append("Replace Telnet with SSH for secure remote access")
            
        if 21 in open_ports:
            recommendations.append("Secure FTP service or consider SFTP/FTPS alternatives")
            
        if any(port in [3306, 5432, 6379] for port in open_ports):
            recommendations.append("Ensure database services are properly secured with authentication")
            
        if 3389 in open_ports:
            recommendations.append("Secure RDP with strong authentication and network-level authentication")
            
        if vulns:
            recommendations.append(f"Address {len(vulns)} potential security issues identified")
            
        if not recommendations:
            recommendations.append("No immediate security concerns identified")
            
        return recommendations
        
    def export_report(self, results: Dict[str, Any], format: str = 'json') -> str:
        """Export analysis report in specified format"""
        
        if format.lower() == 'json':
            return json.dumps(results, indent=2, default=str)
            
        elif format.lower() == 'text':
            return self._generate_text_report(results)
            
        elif format.lower() == 'html':
            return self._generate_html_report(results)
            
        else:
            raise ValueError(f"Unsupported format: {format}")
            
    def _generate_text_report(self, results: Dict[str, Any]) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=== RECONNOISE SECURITY ANALYSIS REPORT ===")
        lines.append(f"Target: {results.get('target', 'unknown')}")
        lines.append(f"Scan Duration: {results.get('scan_duration', 0):.2f} seconds")
        lines.append("")
        
        if 'custom_analysis' in results:
            analysis = results['custom_analysis']['analysis']
            
            lines.append(f"Security Score: {analysis['security_score']}/100")
            lines.append(f"Risk Level: {analysis['risk_level'].upper()}")
            lines.append("")
            
            if analysis['interesting_ports']:
                lines.append("Interesting Ports:")
                for port_info in analysis['interesting_ports']:
                    lines.append(f"  - Port {port_info['port']} ({port_info['service']}): {port_info['reason']}")
                lines.append("")
                
            if analysis['potential_vulnerabilities']:
                lines.append("Potential Vulnerabilities:")
                for vuln in analysis['potential_vulnerabilities']:
                    lines.append(f"  - {vuln['description']} (Severity: {vuln['severity']})")
                lines.append("")
                
            if analysis['recommendations']:
                lines.append("Recommendations:")
                for i, rec in enumerate(analysis['recommendations'], 1):
                    lines.append(f"  {i}. {rec}")
                    
        return '\n'.join(lines)
        
    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reconnoise Security Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 15px; border-radius: 5px; }
                .section { margin: 20px 0; }
                .high-risk { color: #d32f2f; }
                .medium-risk { color: #f57c00; }
                .low-risk { color: #388e3c; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
        """
        
        html += f"""
        <div class="header">
            <h1>Reconnoise Security Analysis Report</h1>
            <p><strong>Target:</strong> {results.get('target', 'unknown')}</p>
            <p><strong>Scan Duration:</strong> {results.get('scan_duration', 0):.2f} seconds</p>
        </div>
        """
        
        if 'custom_analysis' in results:
            analysis = results['custom_analysis']['analysis']
            risk_class = f"{analysis['risk_level']}-risk"
            
            html += f"""
            <div class="section">
                <h2>Security Summary</h2>
                <p><strong>Security Score:</strong> {analysis['security_score']}/100</p>
                <p><strong>Risk Level:</strong> <span class="{risk_class}">{analysis['risk_level'].upper()}</span></p>
            </div>
            """
            
            if analysis['interesting_ports']:
                html += '<div class="section"><h2>Interesting Ports</h2><table>'
                html += '<tr><th>Port</th><th>Service</th><th>Reason</th></tr>'
                for port_info in analysis['interesting_ports']:
                    html += f"<tr><td>{port_info['port']}</td><td>{port_info['service']}</td><td>{port_info['reason']}</td></tr>"
                html += '</table></div>'
                
        html += '</body></html>'
        return html

# Module registration (if using a plugin system)
def get_module():
    """Return module instance for plugin system"""
    return ExampleModule()
