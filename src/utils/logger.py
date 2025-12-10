#!/usr/bin/env python3
"""
Centralized logging configuration for Vulnhalla.

Provides consistent logging setup across all modules with support for:
- Console output (INFO level by default)
- Optional file logging (DEBUG level)
- Environment variable configuration
- Structured logging (JSON) option
"""

import logging
import sys
import os
from pathlib import Path
from typing import Optional

# Default configuration
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_LOG_FORMAT_SIMPLE = "%(levelname)s - %(message)s"  # Simpler format for console
DEFAULT_LOG_FORMAT_INFO = "%(message)s"  # Minimal format for INFO messages
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Track if logging has been initialized
_logging_initialized = False


def reset_logging() -> None:
    """
    Reset logging state
    
    Clears all handlers and resets the initialization flag.
    """
    global _logging_initialized
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    _logging_initialized = False


def suppress_third_party_loggers() -> None:
    """
    Suppress verbose logging from third-party libraries.
    
    Configures log levels for common third-party libraries that can be noisy.
    Respects THIRD_PARTY_LOG_LEVEL environment variable if set.
    """
    # Get third-party log level from environment, default to ERROR
    third_party_level_str = os.getenv("THIRD_PARTY_LOG_LEVEL", "ERROR").upper()
    third_party_level = getattr(logging, third_party_level_str, logging.ERROR)
    
    # LiteLLM - only show errors by default (can be verbose with INFO/DEBUG)
    logging.getLogger("LiteLLM").setLevel(third_party_level)
    
    # urllib3/requests - reduce HTTP connection noise
    logging.getLogger("urllib3").setLevel(third_party_level)
    logging.getLogger("urllib3.connectionpool").setLevel(third_party_level)
    logging.getLogger("requests").setLevel(third_party_level)


def setup_logging(
    log_level: Optional[str] = None,
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
    json_format: bool = False,
    simple_format: bool = False
) -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR). 
                   Defaults to environment variable LOG_LEVEL or INFO.
        log_file: Optional path to log file. If None, reads from LOG_FILE env var.
        log_format: Custom log format string. If None, uses default or JSON.
        json_format: If True, use JSON structured logging format.
        simple_format: If True, use simpler format without timestamps for console.
    """
    global _logging_initialized
    
    # Prevent duplicate initialization
    if _logging_initialized:
        return
    
    # Get configuration from environment or parameters
    level_str = log_level or os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper()
    log_file_path = log_file or os.getenv("LOG_FILE")
    log_format_str = log_format or os.getenv("LOG_FORMAT", "default")
    # Console format control:
    # - Default: INFO messages are minimal (message only), WARNING/ERROR/CRITICAL use simple format (LEVEL - message)
    # - If LOG_VERBOSE_CONSOLE=true: WARNING/ERROR/CRITICAL use full format (timestamp - logger - level - message)
    # - INFO always remains minimal regardless of verbose mode
    use_verbose_console = os.getenv("LOG_VERBOSE_CONSOLE", "false").lower() == "true"
    # Legacy support: LOG_SIMPLE_FORMAT still works but is deprecated in favor of LOG_VERBOSE_CONSOLE
    use_simple_format = simple_format or os.getenv("LOG_SIMPLE_FORMAT", "false").lower() == "true"
    
    # Convert string level to logging constant
    numeric_level = getattr(logging, level_str, logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    
    # Console handler (always present)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    
    if json_format or log_format_str.lower() == "json":
        # JSON structured logging
        try:
            import json
            from datetime import datetime
            
            class JSONFormatter(logging.Formatter):
                """Formatter that renders log records as JSON strings.

                This formatter is used when JSON logging is enabled. It converts the
                LogRecord into a JSON object with a timestamp, logger name, level, and
                message, and can optionally include extra fields such as progress.
                """
                
                def format(self, record):
                    """Format a LogRecord as a JSON string.

                    Args:
                        record: The log record to format.

                    Returns:
                        str: A JSON representation of the log record.
                    """
                    log_entry = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "level": record.levelname,
                        "logger": record.name,
                        "message": record.getMessage(),
                    }
                    # Add extra fields if present
                    if hasattr(record, "progress"):
                        log_entry["progress"] = record.progress
                    return json.dumps(log_entry)
            
            console_handler.setFormatter(JSONFormatter())
        except ImportError:
            # Fallback to default format if json not available
            formatter = logging.Formatter(
                DEFAULT_LOG_FORMAT,
                datefmt=DEFAULT_DATE_FORMAT
            )
            console_handler.setFormatter(formatter)
    else:
        # Standard formatted logging with level-based formatting
        # Default behavior:
        # - INFO: minimal format (message only)
        # - WARNING/ERROR/CRITICAL: simple format (LEVEL - message)
        # If LOG_VERBOSE_CONSOLE=true:
        # - INFO: still minimal (message only)
        # - WARNING/ERROR/CRITICAL: full format (timestamp - logger - level - message)
        class LevelBasedFormatter(logging.Formatter):
            """Formatter that uses different formats depending on log level.

            INFO messages are rendered in a minimal format (message only),
            while WARNING/ERROR/CRITICAL messages can use either a simple format
            (LEVEL - message) or a full format with timestamp and logger name.
            """
            def __init__(self, full_format, simple_format, datefmt=None, verbose=False):
                # Initialize with simple format as base (for WARNING/ERROR default behavior)
                super().__init__(simple_format, datefmt)
                self.full_format = full_format
                self.simple_format = simple_format
                self.verbose = verbose
                self._full_formatter = logging.Formatter(full_format, datefmt) if verbose else None
            
            def format(self, record):
                """Format a LogRecord using level-based formatting.

                INFO records are formatted as the plain message. Higher-severity
                records use either the simple or full format, depending on the
                configuration.

                Args:
                    record: The log record to format.

                Returns:
                    str: The formatted log message.
                """
                # For INFO level, always use minimal format (just the message)
                if record.levelno == logging.INFO:
                    return record.getMessage()
                # For WARNING, ERROR, CRITICAL
                else:
                    if self.verbose:
                        # Use full format with timestamp when verbose mode is enabled
                        return self._full_formatter.format(record)
                    else:
                        # Use simple format (LEVEL - message) by default
                        return super().format(record)
        
        formatter = LevelBasedFormatter(
            DEFAULT_LOG_FORMAT,
            DEFAULT_LOG_FORMAT_SIMPLE,
            datefmt=DEFAULT_DATE_FORMAT,
            verbose=use_verbose_console
        )
        console_handler.setFormatter(formatter)
    
    root_logger.addHandler(console_handler)
    
    # Suppress noisy third-party loggers
    suppress_third_party_loggers()
    
    # File handler (optional)
    if log_file_path:
        try:
            # Ensure log directory exists
            log_path = Path(log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)  # File always gets DEBUG level
            file_formatter = logging.Formatter(
                DEFAULT_LOG_FORMAT,
                datefmt=DEFAULT_DATE_FORMAT
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            # If file logging fails, log to console and continue
            root_logger.warning("Failed to set up file logging: %s", e)
    
    _logging_initialized = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.
    
    This is a convenience function that ensures logging is initialized
    and returns a logger with the given name.
    
    Args:
        name: Logger name (typically __name__ from the calling module)
    
    Returns:
        Logger instance
    """
    # Ensure logging is set up (idempotent)
    if not _logging_initialized:
        setup_logging()
    
    return logging.getLogger(name)


# Auto-setup on import
_AUTO_SETUP = os.getenv("VULNHALLA_AUTO_SETUP_LOGGING", "true").lower() == "true"
if _AUTO_SETUP:
    setup_logging()

