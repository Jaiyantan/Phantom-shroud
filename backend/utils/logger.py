"""
Logging Utility
Simple file-based logging for Phantom-shroud
"""

import logging
import os
from datetime import datetime


def setup_logger(name, log_file='logs/events.log', level=logging.INFO):
    """
    Setup logger with file and console handlers
    
    Args:
        name: Logger name
        log_file: Path to log file
        level: Logging level
        
    Returns:
        logging.Logger: Configured logger
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s - %(name)s - %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger


def log_event(event_type, severity, details, log_file='logs/events.log'):
    """
    Log security event
    
    Args:
        event_type: Type of event
        severity: Event severity (HIGH, MEDIUM, LOW)
        details: Event details dict
        log_file: Path to log file
    """
    logger = setup_logger('events', log_file)
    
    message = f"[{event_type}] {severity}: {details}"
    
    if severity == 'HIGH':
        logger.error(message)
    elif severity == 'MEDIUM':
        logger.warning(message)
    else:
        logger.info(message)


if __name__ == "__main__":
    # Test
    logger = setup_logger('test')
    logger.info("Logger initialized")
    log_event('TEST', 'HIGH', {'test': 'value'})
