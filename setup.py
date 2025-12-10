#!/usr/bin/env python3
"""
Vulnhalla Setup Script - Cross platform one line installation
Usage: python setup.py
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

# Get project root
PROJECT_ROOT = Path(__file__).parent

# Add project root to Python path for imports
sys.path.insert(0, str(PROJECT_ROOT))

# Initialize logging early
from src.utils.logger import setup_logging, get_logger
setup_logging()
logger = get_logger(__name__)
# Check Python version
if sys.version_info >= (3, 14):
    logger.error("Python 3.14+ is not yet supported (grpcio wheels unavailable). Please use Python 3.11 or 3.12.")
    sys.exit(1)


def check_dependencies_installed() -> bool:
    """
    Check if all required dependencies are already installed by trying to import them.
    
    Returns:
        bool: True if all dependencies are installed, False otherwise.
    """
    try:
        import requests
        import dotenv
        import litellm
        import yaml
        import textual
        import pySmartDL
        return True
    except ImportError:
        return False


def main():
    """Run the Vulnhalla setup process.

    This script installs Python dependencies, verifies the CodeQL
    CLI configuration, installs required CodeQL packs, and prints
    next steps for running the analysis pipeline.
    """
    logger.info("Vulnhalla Setup")
    logger.info("=" * 50)
    
    # Check if virtual environment exists
    venv_path = PROJECT_ROOT / "venv"
    use_venv = venv_path.exists()
    
    if use_venv:
        # Use virtual environment pip
        if os.name == 'nt':  # Windows
            pip_exe = [str(PROJECT_ROOT / "venv/Scripts/pip.exe")]
        else:  # Unix/macOS/Linux
            pip_exe = [str(PROJECT_ROOT / "venv/bin/pip")]
        logger.info("Using virtual environment...")
    else:
        # Use system pip
        pip_exe = [sys.executable, "-m", "pip"]
        logger.info("Installing to current Python environment...")
    
    if check_dependencies_installed():
        logger.info("✅ All dependencies are already installed! Skipping installation.")
    else:
        # Install dependencies
        logger.info("📦 Installing Python dependencies... This may take a moment ⏳")
        try:
            subprocess.run(pip_exe + ["install","-q", "-r", str(PROJECT_ROOT / "requirements.txt")], check=True)
            logger.info("✅ Python dependencies installed successfully!")
        except subprocess.CalledProcessError as e:
            logger.error("\n❌ Setup failed. Please fix the missing dependencies and run setup.py again.")
            sys.exit(1)
    
    # Install CodeQL packs
    # Check for CodeQL in PATH or .env
    codeql_cmd = None
    
    try:
        from src.utils.config import get_codeql_path
        from src.utils.config_validator import find_codeql_executable
        
        codeql_path = get_codeql_path()
        logger.info("Checking CodeQL path: %s", codeql_path)
        
        # Use helper function to find executable
        codeql_cmd = find_codeql_executable()
        
        if codeql_cmd:
            if codeql_path == "codeql":
                logger.info("🔍 Checking if 'codeql' is in PATH...")
                logger.info("✅ Found in PATH: %s", codeql_cmd)
            else:
                logger.info("✅ Found CodeQL path: %s", codeql_cmd)
        else:
            # Provide detailed error messages
            if codeql_path and codeql_path != "codeql":
                # Custom path specified - strip quotes if present
                codeql_path_clean = codeql_path.strip('"').strip("'")
                logger.error("❌ Path does not exist: %s", codeql_path_clean)
                if os.name == 'nt':
                    logger.info("Also checked: %s.cmd", codeql_path_clean)
            else:
                logger.info("🔍 Checking if 'codeql' is in PATH...")
                logger.error("❌ 'codeql' not found in PATH")
    except Exception as e:
        # Fallback to checking PATH
        logger.error("❌ Error loading config: %s", e)
        logger.info("🔍 Falling back to PATH check...")
        codeql_cmd = shutil.which("codeql")
        if codeql_cmd:
            logger.info("✅ Found in PATH: %s", codeql_cmd)
    
    if codeql_cmd:
        logger.info("📦 Installing CodeQL packs... This may take a moment ⏳")
        
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
    else:
        logger.error("❌ CodeQL CLI not found. Skipping CodeQL pack installation.")
        logger.info("🔗 Install CodeQL CLI from: https://github.com/github/codeql-cli-binaries/releases")
        logger.info("   After installation, either add CodeQL to your PATH or set CODEQL_PATH in your .env file.")
        logger.info("   Then run: python setup.py or install packages manually")
        return
    
    # Optional: Validate CodeQL configuration if .env file exists
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        logger.info("\n🔍 Validating CodeQL configuration...")
        try:
            from src.utils.config_validator import validate_codeql_path
            is_valid, error = validate_codeql_path()
            if is_valid:
                logger.info("✅ CodeQL configuration validated successfully!")
            else:
                logger.warning("⚠️  CodeQL configuration issue detected:")
                logger.warning("   %s", error.split(chr(10))[0])  # Print first line of error
                logger.warning("   Please fix this before running the pipeline.")
        except Exception as e:
            logger.warning("⚠️  Could not validate CodeQL configuration: %s", e)
            logger.info("   This is not critical - you can fix configuration later.")
    
    logger.info("🎉 Setup completed successfully! 🎉")
    logger.info("🔗 Next steps:")
    if not env_file.exists():
        logger.info("1. Create a .env file with all the required variables (see README.md)")
        logger.info("2. Run one of the following commands to start the pipeline:")
    else:
        logger.info("Run one of the following commands to start the pipeline:")
    logger.info("   • python src/pipeline.py <repo_org/repo_name>    # Analyze a specific repository")
    logger.info("   • python src/pipeline.py                         # Analyze top 100 repositories")
    logger.info("   • python examples/example.py                     # See a full pipeline run")

if __name__ == "__main__":
    main()

