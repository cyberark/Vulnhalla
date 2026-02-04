#!/usr/bin/env python3
"""
Application Configuration Module

Loads general application configuration from .env file or environment variables.
Handles CodeQL path, GitHub token, and other non-LLM settings.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load .env file if it exists, otherwise try .env.example
if Path(".env").exists():
    load_dotenv(".env")
elif Path(".env.example").exists():
    load_dotenv(".env.example")


def get_codeql_path() -> str:
    """
    Get CodeQL executable path from .env file or environment variables.
    
    Returns:
        Path to CodeQL executable. Defaults to "codeql" if not set.
    """
    path = os.getenv("CODEQL_PATH", "codeql")
    # Strip quotes and Python raw string prefix if present
    if path and path != "codeql":
        path = path.strip('"').strip("'")
        # Remove 'r' prefix if present (Python raw string syntax, not valid in .env)
        if path.startswith("r\"") or path.startswith("r'"):
            path = path[2:]
            path = path.strip('"').strip("'")
    return path


def get_github_token() -> Optional[str]:
    """
    Get GitHub API token from .env file or environment variables.
    
    Returns:
        GitHub token string if set, None otherwise.
    """
    return os.getenv("GITHUB_TOKEN")


def get_github_api_url() -> str:
    """
    Get GitHub API base URL from .env file or environment variables.
    
    Supports both github.com and GitHub Enterprise Server.
    
    Returns:
        GitHub API base URL. Defaults to "https://api.github.com" for github.com.
        For GitHub Enterprise: "https://github.example.com/api/v3"
    """
    url = os.getenv("GITHUB_API_URL", "https://api.github.com")
    # Remove trailing slash for consistent URL construction
    return url.rstrip("/")


def get_github_ssl_verify() -> bool:
    """
    Get GitHub SSL verification setting from .env file or environment variables.
    
    For GitHub Enterprise with self-signed or internal CA certificates,
    set GITHUB_SSL_VERIFY=false to disable certificate verification.
    
    Returns:
        True to verify SSL certificates (default), False to skip verification.
    """
    value = os.getenv("GITHUB_SSL_VERIFY", "true").lower()
    return value not in ("false", "0", "no", "off")

