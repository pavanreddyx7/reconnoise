"""
Logging configuration and utilities
"""

import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(name: str, level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Setup and configure logger
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
        
    # Set level
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    logger.setLevel(numeric_level)
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        try:
            # Create log directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
            
        except Exception as e:
            logger.warning(f"Could not create file handler for {log_file}: {e}")
    
    # Debug handler for verbose mode
    if numeric_level <= logging.DEBUG:
        debug_handler = logging.StreamHandler(sys.stderr)
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(detailed_formatter)
        logger.addHandler(debug_handler)
        
        # Remove simple console handler to avoid duplicate output
        logger.removeHandler(console_handler)
    
    return logger

class LoggingContext:
    """Context manager for temporary logging level changes"""
    
    def __init__(self, logger: logging.Logger, level: str):
        self.logger = logger
        self.new_level = getattr(logging, level.upper(), logging.INFO)
        self.old_level = None
        
    def __enter__(self):
        self.old_level = self.logger.level
        self.logger.setLevel(self.new_level)
        return self.logger
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.old_level is not None:
            self.logger.setLevel(self.old_level)

class ReconnoiseLogger:
    """Custom logger for Reconnoise with specialized methods"""
    
    def __init__(self, name: str, level: str = "INFO"):
        self.logger = setup_logger(name, level)
        
    def scan_start(self, target: str, ports_count: int, profile: str = None):
        """Log scan start"""
        profile_msg = f" with profile '{profile}'" if profile else ""
        self.logger.info(f"Starting scan of {target} ({ports_count} ports){profile_msg}")
        
    def scan_complete(self, target: str, duration: float, results_count: int):
        """Log scan completion"""
        self.logger.info(f"Scan of {target} completed in {duration:.2f}s - {results_count} results")
        
    def port_result(self, target: str, port: int, status: str, service: str = None):
        """Log port scan result"""
        service_msg = f" ({service})" if service else ""
        self.logger.debug(f"{target}:{port} - {status.upper()}{service_msg}")
        
    def probe_sent(self, target: str, port: int, probe_name: str):
        """Log probe transmission"""
        self.logger.debug(f"Sent {probe_name} probe to {target}:{port}")
        
    def response_received(self, target: str, port: int, size: int):
        """Log response reception"""
        self.logger.debug(f"Received {size} bytes from {target}:{port}")
        
    def fingerprint_match(self, target: str, port: int, service: str, confidence: float):
        """Log fingerprinting result"""
        self.logger.info(f"{target}:{port} identified as {service} (confidence: {confidence:.2f})")
        
    def profile_loaded(self, profile_name: str):
        """Log profile loading"""
        self.logger.info(f"Loaded traffic profile: {profile_name}")
        
    def error(self, message: str, exc_info: bool = False):
        """Log error with optional exception info"""
        self.logger.error(message, exc_info=exc_info)
        
    def warning(self, message: str):
        """Log warning"""
        self.logger.warning(message)
        
    def info(self, message: str):
        """Log info"""
        self.logger.info(message)
        
    def debug(self, message: str):
        """Log debug"""
        self.logger.debug(message)

# Global logger instances
_loggers = {}

def get_logger(name: str, level: str = "INFO") -> ReconnoiseLogger:
    """Get or create a ReconnoiseLogger instance"""
    if name not in _loggers:
        _loggers[name] = ReconnoiseLogger(name, level)
    return _loggers[name]

def configure_root_logger(level: str = "INFO", log_file: str = None):
    """Configure the root logger for the application"""
    root_logger = logging.getLogger()
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        
    # Setup new configuration
    setup_logger("reconnoise", level, log_file)

def silence_noisy_loggers():
    """Silence overly verbose third-party loggers"""
    noisy_loggers = [
        'urllib3.connectionpool',
        'requests.packages.urllib3',
        'paramiko.transport',
        'scapy'
    ]
    
    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)
