"""
Network utilities and helpers
"""

import socket
import ipaddress
import re
from typing import Union, List, Dict, Any, Optional, Tuple

class NetworkHelper:
    """Network utility functions"""
    
    @staticmethod
    def validate_target(target: str) -> bool:
        """
        Validate if target is a valid IP address or hostname
        """
        if not target:
            return False
            
        # Try as IP address first
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
            
        # Try as hostname
        try:
            # Basic hostname validation
            if len(target) > 253:
                return False
                
            # Check for valid characters
            if not re.match(r'^[a-zA-Z0-9.-]+$', target):
                return False
                
            # Check each label
            labels = target.split('.')
            for label in labels:
                if not label or len(label) > 63:
                    return False
                if label.startswith('-') or label.endswith('-'):
                    return False
                    
            return True
            
        except Exception:
            return False
            
    @staticmethod
    def resolve_hostname(hostname: str, timeout: int = 5) -> Optional[str]:
        """
        Resolve hostname to IP address
        """
        try:
            # Set socket timeout for DNS resolution
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(hostname)
            socket.setdefaulttimeout(None)  # Reset to default
            return ip
        except (socket.gaierror, socket.timeout):
            return None
        finally:
            socket.setdefaulttimeout(None)
            
    @staticmethod
    def reverse_dns_lookup(ip: str, timeout: int = 5) -> Optional[str]:
        """
        Perform reverse DNS lookup
        """
        try:
            socket.setdefaulttimeout(timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            socket.setdefaulttimeout(None)
            return hostname
        except (socket.herror, socket.timeout):
            return None
        finally:
            socket.setdefaulttimeout(None)
            
    @staticmethod
    def is_ip_address(target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
            
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is in private range"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
            
    @staticmethod
    def get_network_info(target: str) -> Dict[str, Any]:
        """
        Get comprehensive network information about target
        """
        info = {
            'target': target,
            'is_ip': False,
            'is_hostname': False,
            'resolved_ip': None,
            'reverse_dns': None,
            'is_private': False,
            'ip_version': None,
            'reachable': False
        }
        
        # Determine if target is IP or hostname
        if NetworkHelper.is_ip_address(target):
            info['is_ip'] = True
            info['resolved_ip'] = target
            
            try:
                ip_obj = ipaddress.ip_address(target)
                info['is_private'] = ip_obj.is_private
                info['ip_version'] = ip_obj.version
            except ValueError:
                pass
                
            # Try reverse DNS
            info['reverse_dns'] = NetworkHelper.reverse_dns_lookup(target)
            
        else:
            info['is_hostname'] = True
            # Try to resolve
            resolved_ip = NetworkHelper.resolve_hostname(target)
            if resolved_ip:
                info['resolved_ip'] = resolved_ip
                info['is_private'] = NetworkHelper.is_private_ip(resolved_ip)
                
                try:
                    ip_obj = ipaddress.ip_address(resolved_ip)
                    info['ip_version'] = ip_obj.version
                except ValueError:
                    pass
                    
        # Test basic reachability (ICMP would be better but requires privileges)
        if info['resolved_ip']:
            info['reachable'] = NetworkHelper.test_connectivity(info['resolved_ip'])
            
        return info
        
    @staticmethod
    def test_connectivity(target: str, port: int = 80, timeout: int = 3) -> bool:
        """
        Test basic connectivity to target
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
            
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
            
    @staticmethod
    def get_interface_info() -> List[Dict[str, Any]]:
        """
        Get network interface information
        Note: This is a simplified version. For full interface info,
        you'd typically use platform-specific libraries.
        """
        interfaces = []
        
        try:
            hostname = socket.gethostname()
            local_ip = NetworkHelper.get_local_ip()
            
            interfaces.append({
                'name': 'default',
                'ip': local_ip,
                'hostname': hostname
            })
            
        except Exception:
            pass
            
        return interfaces
        
    @staticmethod
    def parse_cidr(cidr: str) -> List[str]:
        """
        Parse CIDR notation and return list of IP addresses
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Limit to reasonable size to prevent memory issues
            if network.num_addresses > 1024:
                raise ValueError(f"Network too large: {network.num_addresses} addresses")
                
            return [str(ip) for ip in network.hosts()]
        except Exception as e:
            raise ValueError(f"Invalid CIDR notation '{cidr}': {e}")
            
    @staticmethod
    def expand_ip_range(ip_range: str) -> List[str]:
        """
        Expand IP range specification to list of IPs
        Supports formats: 192.168.1.1-10, 192.168.1.1-192.168.1.10
        """
        if '-' not in ip_range:
            return [ip_range]
            
        try:
            start_ip, end_part = ip_range.split('-', 1)
            start_ip = start_ip.strip()
            end_part = end_part.strip()
            
            # Validate start IP
            start_obj = ipaddress.ip_address(start_ip)
            
            # Handle different end formats
            if '.' in end_part:
                # Full IP address
                end_obj = ipaddress.ip_address(end_part)
            else:
                # Just the last octet
                ip_parts = start_ip.split('.')
                ip_parts[-1] = end_part
                end_obj = ipaddress.ip_address('.'.join(ip_parts))
                
            # Generate range
            start_int = int(start_obj)
            end_int = int(end_obj)
            
            if start_int > end_int:
                start_int, end_int = end_int, start_int
                
            if end_int - start_int > 1024:
                raise ValueError(f"IP range too large: {end_int - start_int + 1} addresses")
                
            return [str(ipaddress.ip_address(ip_int)) for ip_int in range(start_int, end_int + 1)]
            
        except Exception as e:
            raise ValueError(f"Invalid IP range '{ip_range}': {e}")
            
    @staticmethod
    def get_common_ports_for_service(service: str) -> List[int]:
        """Get common ports for a given service"""
        service_ports = {
            'http': [80, 8080, 8000, 3000, 8008, 8888],
            'https': [443, 8443, 9443],
            'ssh': [22],
            'ftp': [21, 2121],
            'smtp': [25, 587, 465],
            'pop3': [110, 995],
            'imap': [143, 993],
            'dns': [53],
            'dhcp': [67, 68],
            'snmp': [161, 162],
            'ldap': [389, 636],
            'mysql': [3306],
            'postgresql': [5432],
            'mongodb': [27017],
            'redis': [6379],
            'elasticsearch': [9200, 9300],
            'kafka': [9092],
            'zookeeper': [2181],
            'cassandra': [9042],
            'vnc': [5900, 5901, 5902],
            'rdp': [3389],
            'telnet': [23],
            'ntp': [123]
        }
        
        return service_ports.get(service.lower(), [])
        
    @staticmethod
    def check_port_accessibility(target: str, port: int, timeout: int = 3) -> Dict[str, Any]:
        """
        Check if a specific port is accessible
        """
        result = {
            'target': target,
            'port': port,
            'open': False,
            'filtered': False,
            'closed': False,
            'response_time': 0.0,
            'error': None
        }
        
        import time
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            connect_result = sock.connect_ex((target, port))
            
            if connect_result == 0:
                result['open'] = True
            else:
                result['closed'] = True
                
            sock.close()
            
        except socket.timeout:
            result['filtered'] = True
            result['error'] = 'timeout'
        except Exception as e:
            result['closed'] = True
            result['error'] = str(e)
            
        result['response_time'] = time.time() - start_time
        return result
        
    @staticmethod
    def batch_port_check(target: str, ports: List[int], timeout: int = 3) -> List[Dict[str, Any]]:
        """
        Check multiple ports for accessibility
        """
        results = []
        
        for port in ports:
            result = NetworkHelper.check_port_accessibility(target, port, timeout)
            results.append(result)
            
        return results
        
    @staticmethod
    def get_service_name(port: int, protocol: str = 'tcp') -> str:
        """
        Get service name for port number using system services database
        """
        try:
            return socket.getservbyport(port, protocol)
        except OSError:
            return 'unknown'
            
    @staticmethod
    def get_port_number(service: str, protocol: str = 'tcp') -> int:
        """
        Get port number for service name
        """
        try:
            return socket.getservbyname(service, protocol)
        except OSError:
            return 0
            
    @staticmethod
    def is_port_in_range(port: int, start: int, end: int) -> bool:
        """Check if port is within specified range"""
        return start <= port <= end
        
    @staticmethod
    def categorize_port(port: int) -> str:
        """Categorize port into well-known, registered, or dynamic"""
        if 1 <= port <= 1023:
            return 'well-known'
        elif 1024 <= port <= 49151:
            return 'registered'
        elif 49152 <= port <= 65535:
            return 'dynamic'
        else:
            return 'invalid'
            
class NetworkScanner:
    """Basic network scanning utilities"""
    
    def __init__(self, timeout: int = 3):
        self.timeout = timeout
        
    def ping_sweep(self, network: str) -> List[str]:
        """
        Perform ping sweep on network range
        Note: This uses TCP connect instead of ICMP due to privilege requirements
        """
        active_hosts = []
        
        try:
            # Parse network
            if '/' in network:
                # CIDR notation
                hosts = NetworkHelper.parse_cidr(network)
            elif '-' in network:
                # IP range notation
                hosts = NetworkHelper.expand_ip_range(network)
            else:
                # Single host
                hosts = [network]
                
            # Test each host
            for host in hosts:
                if NetworkHelper.test_connectivity(host, 80, self.timeout) or \
                   NetworkHelper.test_connectivity(host, 443, self.timeout) or \
                   NetworkHelper.test_connectivity(host, 22, self.timeout):
                    active_hosts.append(host)
                    
        except Exception as e:
            raise ValueError(f"Error in ping sweep: {e}")
            
        return active_hosts
        
    def port_scan(self, target: str, ports: List[int]) -> Dict[int, bool]:
        """
        Simple port scan
        """
        results = {}
        
        for port in ports:
            result = NetworkHelper.check_port_accessibility(target, port, self.timeout)
            results[port] = result['open']
            
        return results
        
    def service_detection(self, target: str, port: int) -> Dict[str, Any]:
        """
        Basic service detection through banner grabbing
        """
        service_info = {
            'port': port,
            'service': 'unknown',
            'banner': None,
            'version': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            # Try to get banner
            try:
                banner = sock.recv(1024)
                if banner:
                    service_info['banner'] = banner.decode('utf-8', errors='ignore')
                    service_info['service'] = NetworkHelper.get_service_name(port)
            except socket.timeout:
                pass
                
            sock.close()
            
        except Exception:
            pass
            
        return service_info
