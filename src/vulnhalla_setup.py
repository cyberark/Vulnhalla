#!/usr/bin/env python3
"""
Vulnhalla Setup Command - CodeQL Configuration and Pack Installation

This module provides the `vulnhalla-setup` Poetry CLI command that:
- Validates CodeQL configuration
- Installs required CodeQL packs

Note: Python dependencies are managed by Poetry and should be installed via `poetry install`.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Get project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Initialize logging early
from src.utils.logger import setup_logging, get_logger
setup_logging()
logger = get_logger(__name__)


def main() -> None:
    """
    Main entry point for vulnhalla-setup command.
    
    Validates CodeQL configuration and installs CodeQL packs.
    """
    logger.info("Vulnhalla Setup")
    logger.info("=" * 50)
    
    # Install CodeQL packs
    # Check for CodeQL in PATH or .env
    codeql_cmd = None
    
    try:
        from src.utils.config import get_codeql_path
        from src.utils.config_validator import find_codeql_executable
        
        codeql_path = get_codeql_path()
        logger.debug("Checking CodeQL path: %s", codeql_path)
        
        # Use helper function to find executable
        codeql_cmd = find_codeql_executable()
        
        if codeql_cmd:
            if codeql_path == "codeql":
                logger.debug("Checking if 'codeql' is in PATH...")
                logger.info("[+] Found in PATH: %s", codeql_cmd)
            else:
                logger.info("[+] Found CodeQL path: %s", codeql_cmd)
        else:
            # Provide detailed error messages
            if codeql_path and codeql_path != "codeql":
                # Custom path specified - strip quotes if present
                codeql_path_clean = codeql_path.strip('"').strip("'")
                logger.error("[-] Path does not exist: %s", codeql_path_clean)
                if os.name == 'nt':
                    logger.debug("Also checked: %s.cmd", codeql_path_clean)
            else:
                logger.debug("Checking if 'codeql' is in PATH...")
                logger.error("[-] 'codeql' not found in PATH")
    except Exception as e:
        # Fallback to checking PATH
        logger.error("[-] Error loading config: %s", e)
        logger.debug("Falling back to PATH check...")
        codeql_cmd = shutil.which("codeql")
        if codeql_cmd:
            logger.info("[+] Found in PATH: %s", codeql_cmd)
    
    if codeql_cmd:
        logger.info("Installing CodeQL packs... This may take a moment")
        
        # Tools pack
        tools_dir = PROJECT_ROOT / "data/queries/cpp/tools"
        if tools_dir.exists():
            os.chdir(str(tools_dir))
            result = subprocess.run([codeql_cmd, "pack", "install"], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("Failed to install tools pack: %s", result.stderr)
            os.chdir(str(PROJECT_ROOT))
        
        # Issues pack
        issues_dir = PROJECT_ROOT / "data/queries/cpp/issues"
        if issues_dir.exists():
            os.chdir(str(issues_dir))
            result = subprocess.run([codeql_cmd, "pack", "install"], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("Failed to install issues pack: %s", result.stderr)
            os.chdir(str(PROJECT_ROOT))

        # Dynamic-language packs are additional; the existing C/C++ packs and setup flow are unchanged.
        for pack_dir in (
            PROJECT_ROOT / "data/queries/python/tools",
            PROJECT_ROOT / "data/queries/python/issues",
            PROJECT_ROOT / "data/queries/javascript/tools",
            PROJECT_ROOT / "data/queries/javascript/issues",
        ):
            if pack_dir.exists():
                os.chdir(str(pack_dir))
                result = subprocess.run(
                    [codeql_cmd, "pack", "install"],
                    check=False,
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    logger.warning("Failed to install CodeQL pack %s: %s", pack_dir, result.stderr)
                os.chdir(str(PROJECT_ROOT))
    else:
        logger.error("[-] CodeQL CLI not found. Skipping CodeQL pack installation.")
        logger.info("Install CodeQL CLI from: https://github.com/github/codeql-cli-binaries/releases")
        logger.info("After installation, either add CodeQL to your PATH or set CODEQL_PATH in your .env file.")
        logger.info("Then run: poetry run vulnhalla-setup or install packages manually")
        return
    
    # Optional: Validate CodeQL configuration if .env file exists
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        logger.debug("\nValidating CodeQL configuration...")
        try:
            from src.utils.config_validator import validate_codeql_path
            is_valid, error = validate_codeql_path()
            if is_valid:
                logger.info("[+] CodeQL configuration validated successfully!")
            else:
                logger.warning("[-] CodeQL configuration issue detected:")
                logger.warning("%s", error.split(chr(10))[0])  # Print first line of error
                logger.warning("Please fix this before running the pipeline.")
        except Exception as e:
            logger.warning("[-] Could not validate CodeQL configuration: %s", e)
            logger.info("This is not critical - you can fix configuration later.")
    
    logger.info("[+] Setup completed successfully!")
    logger.info("Next steps:")
    if not env_file.exists():
        logger.info("1. Create a .env file with all the required variables (see README.md)")
        logger.info("2. Run one of the following commands to start the pipeline:")
    else:
        logger.info("Run one of the following commands to start the pipeline:")
    logger.info("   • poetry run vulnhalla <org/repo>    # Analyze a specific repository")
    logger.info("   • poetry run vulnhalla-example       # See a full pipeline run")


if __name__ == "__main__":
    main()
