#!/usr/bin/env python3
"""
Reconnoise - Traffic Reconnaissance Framework
Main entry point for the application
"""

import argparse
import json
import sys
import time

from scanner.scheduler import ScanScheduler
from scanner.fingerprint import Fingerprinter
from utils.parser import PortParser, ResultsHandler
from utils.logger import setup_logger
from utils.network import NetworkHelper
from profiles import netflix, zoom, fortnite

__version__ = "1.0.0"

class Reconnoise:
    """Main Reconnoise application class"""

    def __init__(self):
        self.logger = setup_logger(__name__)
        self.profiles = {
            'netflix': netflix.NetflixProfile(),
            'zoom': zoom.ZoomProfile(),
            'fortnite': fortnite.FortniteProfile()
        }
        self.scheduler = None
        self.fingerprinter = Fingerprinter()

    def validate_target(self, target):
        """Validate target address"""
        if not NetworkHelper.validate_target(target):
            self.logger.error(f"Invalid target: {target}")
            return False
        return True

    def run_scan(self, target, ports, profile_name=None, threads=10, timeout=5, output_file=None):
        """Execute the reconnaissance scan"""
        self.logger.info(f"Starting Reconnoise v{__version__}")
        self.logger.info(f"Target: {target}")
        self.logger.info(f"Ports: {ports}")
        self.logger.info(f"Profile: {profile_name or 'default'}")
        self.logger.info(f"Threads: {threads}")

        if not self.validate_target(target):
            return None

        port_list = PortParser.parse_ports(ports)
        if not port_list:
            self.logger.error("No valid ports specified")
            return None

        profile = None
        if profile_name and profile_name in self.profiles:
            profile = self.profiles[profile_name]
            self.logger.info(f"Using profile: {profile_name}")
        else:
            self.logger.info("Using default scanning mode")

        self.scheduler = ScanScheduler(
            target=target,
            ports=port_list,
            profile=profile,
            threads=threads,
            timeout=timeout,
            fingerprinter=self.fingerprinter
        )

        results = self.scheduler.execute()

        results_handler = ResultsHandler(results)
        enriched_results = results_handler.enrich_results(self.fingerprinter)

        if output_file:
            self.save_results(enriched_results, output_file)
        else:
            self.display_results(enriched_results)

        return enriched_results

    def save_results(self, results, filename):
        """Save results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self.logger.info(f"Results saved to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

    def display_results(self, results):
        """Display results to console"""
        print("\n" + "="*60)
        print("RECONNAISSANCE RESULTS")
        print("="*60)
        
        if not results.get('results'):
             print("No open ports or responsive services found.")
             print("\n" + "="*60)
             return

        for target_port, data in sorted(results['results'].items()):
            if data.get('status') != 'open':
                continue
            
            port = data.get('port', target_port.split(':')[-1])
            print(f"\nHost: {results.get('target')}  Port: {port}")
            print("-" * 25)
            print(f"  Status: {data.get('status', 'unknown')}")
            
            app = data.get('app', 'Unknown')
            confidence = data.get('confidence', 0.0)
            if app and confidence > 0.0:
                print(f"  Application: {app} (Confidence: {confidence:.2f})")

            fingerprint = data.get('fingerprint', {}) or {}
            service = fingerprint.get('service', data.get('service', 'unknown'))
            print(f"  Service: {service}")
            
            if fingerprint.get('version'):
                print(f"  Version: {fingerprint.get('version')}")

            if data.get('response_time'):
                print(f"  Response Time: {data['response_time']:.3f}s")

        print("\n" + "="*60)


def create_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Reconnoise - Traffic Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t 192.168.1.10 -p 80,443
  %(prog)s -t example.com -p 80,443,8080 --profile zoom
  %(prog)s -t 10.10.10.5 -p 1-1000 --threads 20
  %(prog)s -t target.com --profile fortnite --output report.json
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', required=True, help='Ports to scan (e.g., 80,443 or 1-1000)')
    parser.add_argument('--profile', choices=['netflix', 'zoom', 'fortnite'], help='Traffic profile to use for reconnaissance')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    return parser

def main():
    """Main function"""
    parser = create_parser()
    args = parser.parse_args()
    
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    reconnoise = Reconnoise()
    
    try:
        reconnoise.run_scan(
            target=args.target,
            ports=args.ports,
            profile_name=args.profile,
            threads=args.threads,
            timeout=args.timeout,
            output_file=args.output
        )
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
