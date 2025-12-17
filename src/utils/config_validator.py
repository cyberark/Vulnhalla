#!/usr/bin/env python3
"""
Configuration Validator Module

Validates configuration at startup to catch errors early with clear messages.
"""

import os
from shlex import join
import shutil
from typing import List, Optional, Tuple
from typing import Dict, Any
from src.utils.config import get_codeql_path
from src.utils.llm_config import load_llm_config, ALLOWED_LLM_PROVIDERS
from src.utils.logger import get_logger

logger = get_logger(__name__)


def is_placeholder_api_key(api_key: Optional[str]) -> bool:
    """
    Check if an API key is a placeholder value.
    
    Checks for common placeholders: "your_api_key" (from .env.example) and "sk-..."
    
    Args:
        api_key: API key to check
    
    Returns:
        True if the API key appears to be a placeholder, False otherwise
    """
    if not api_key:
        return True
    
    api_key_str = str(api_key).strip()
    # Strip quotes if present (from .env file)
    api_key_str = api_key_str.strip('"').strip("'")
    api_key_lower = api_key_str.lower()
    
    # Check for the placeholder used in .env.example
    if "your_api_key" in api_key_lower or api_key_lower == "your-api-key":
        return True
    
    # Check for "sk-..." placeholder pattern
    if api_key_str == "sk-...":
        return True
    
    return False


def find_codeql_executable() -> Optional[str]:
    """
    Find the actual CodeQL executable path to use.
    
    Returns:
        Path to CodeQL executable if found, None otherwise.
        On Windows, returns path with .cmd extension if needed.
    """
    try:
        codeql_path = get_codeql_path()
        
        # Strip quotes if present
        if codeql_path:
            codeql_path = codeql_path.strip('"').strip("'")
        
        # If default "codeql", check if it's in PATH
        if codeql_path == "codeql":
            return shutil.which("codeql")
        
        # Custom path provided - check if file exists
        if os.path.exists(codeql_path):
            return codeql_path
        
        # Check with extensions (Windows)
        if os.name == 'nt':
            # Check .cmd extension (CodeQL uses .cmd on Windows)
            if os.path.exists(codeql_path + ".cmd"):
                return codeql_path + ".cmd"
            # Also check .exe for compatibility
            if os.path.exists(codeql_path + ".exe"):
                return codeql_path + ".exe"
        
        return None
    except Exception:
        # Fallback to checking PATH
        return shutil.which("codeql")


def validate_codeql_path() -> Tuple[bool, Optional[str]]:
    """
    Validate that CodeQL executable exists.
    
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if CodeQL path is valid
        - error_message: Error message if invalid, None if valid
    """
    codeql_path = get_codeql_path()
    
    # Check for placeholder value
    codeql_path_str = str(codeql_path).strip().lower()
    if "your_codeql_path" in codeql_path_str or codeql_path_str == "your-codeql-path":
        return False, (
            "CODEQL_PATH appears to be a placeholder value.\n"
            "Please set CODEQL_PATH in your .env file to the actual path of the CodeQL executable.\n"
            "On Windows: C:\\path\\to\\codeql\\codeql.cmd\n"
            "On Linux/macOS: /path/to/codeql/codeql or add 'codeql' to your PATH"
        )
    
    # If default "codeql", check if it's in PATH
    if codeql_path == "codeql":
        codeql_cmd = shutil.which("codeql")
        if not codeql_cmd:
            return False, (
                "CodeQL not found in PATH. Please either:\n"
                "  1. Install CodeQL and add it to your PATH, or\n"
                "  2. Set CODEQL_PATH in your .env file to the full path of the CodeQL executable.\n"
                "     On Windows: C:\\path\\to\\codeql\\codeql.cmd"
            )
        return True, None
    
    # Custom path provided - check if file exists
    if not os.path.exists(codeql_path):
        # Check with .cmd extension (CodeQL uses .cmd on Windows)
        if os.name == 'nt':
            if os.path.exists(codeql_path + ".cmd"):
                return True, None
        
        return False, (
            f"CodeQL executable not found at: {codeql_path}\n"
            "Please check that CODEQL_PATH in your .env file is correct.\n"
            "On Windows, the path must end with .cmd (e.g., C:\\path\\to\\codeql\\codeql.cmd)"
        )
    
    return True, None


def validate_llm_config_dict(config: Dict[str, Any]) -> bool:
    """
    Validate LLM configuration dictionary.
    
    Args:
        config: Configuration dictionary
    
    Returns:
        True if valid, raises ValueError if invalid
    """
    # Check required fields
    required_fields = ["provider", "model"]
    
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required configuration field: {field}")
    
    # Normalize aliases to canonical provider name
    provider = config["provider"]
    if provider == "google":
        provider = "gemini"
        config["provider"] = provider  # Update config with normalized value
    
    # Validate provider is in allowed list
    if provider not in ALLOWED_LLM_PROVIDERS:
        raise ValueError(
            f"Provider '{provider}' is not supported. "
            f"Allowed providers: {', '.join(sorted(ALLOWED_LLM_PROVIDERS))}"
        )
    
    # Validate provider specific requirements
    if provider == "azure":
        if "endpoint" not in config:
            raise ValueError("Azure provider requires 'endpoint' in configuration")
        if "api_key" not in config or not config["api_key"]:
            raise ValueError("Azure provider requires 'api_key' in configuration")
        if is_placeholder_api_key(config["api_key"]):
            raise ValueError("Azure provider requires a valid 'api_key'. Please set AZURE_OPENAI_API_KEY in your .env file with your actual API key.")
    
    elif provider == "bedrock":
        if "api_key" not in config or not config["api_key"]:
            raise ValueError("Bedrock provider requires 'api_key' (AWS_ACCESS_KEY_ID) in configuration")
        if is_placeholder_api_key(config["api_key"]):
            raise ValueError("Bedrock provider requires a valid 'api_key' (AWS_ACCESS_KEY_ID). Please set AWS_ACCESS_KEY_ID in your .env file with your actual AWS access key.")
        if "aws_secret_access_key" not in config or not config.get("aws_secret_access_key"):
            raise ValueError("Bedrock provider requires 'aws_secret_access_key' (AWS_SECRET_ACCESS_KEY) in configuration")
        if is_placeholder_api_key(config.get("aws_secret_access_key")):
            raise ValueError("Bedrock provider requires a valid 'aws_secret_access_key' (AWS_SECRET_ACCESS_KEY). Please set AWS_SECRET_ACCESS_KEY in your .env file with your actual AWS secret key.")
        if "endpoint" not in config or not config["endpoint"]:
            raise ValueError("Bedrock provider requires 'endpoint' (AWS_REGION_NAME) in configuration")
    
    elif provider == "ollama":
        # Ollama uses placeholder api_key
        if "endpoint" not in config:
            raise ValueError("Ollama provider requires 'endpoint' (OLLAMA_BASE_URL) in configuration")
    
    else:
        # All other providers require api_key
        if "api_key" not in config or not config["api_key"]:
            raise ValueError(f"{provider} provider requires 'api_key' in configuration")
        if is_placeholder_api_key(config["api_key"]):
            # Get the environment variable name for this provider
            env_var_map = {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "gemini": "GOOGLE_API_KEY",
                "mistral": "MISTRAL_API_KEY",
                "codestral": "MISTRAL_API_KEY",
                "groq": "GROQ_API_KEY",
                "openrouter": "OPENROUTER_API_KEY",
                "huggingface": "HUGGINGFACE_API_KEY",
                "cohere": "COHERE_API_KEY",
            }
            env_var = env_var_map.get(provider, "API_KEY")
            raise ValueError(
                f"{provider} provider requires a valid 'api_key'. "
                f"Please set {env_var} in your .env file with your actual API key. "
                f"Current value appears to be a placeholder."
            )
    
    return True


def validate_llm_config() -> Tuple[bool, Optional[str]]:
    """
    Validate LLM configuration.
    
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if LLM config is valid
        - error_message: Error message if invalid, None if valid
    """
    try:
        config = load_llm_config()
        validate_llm_config_dict(config)
        
        return True, None
    except ValueError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Error loading LLM configuration: {str(e)}"


def validate_logging_config() -> Tuple[bool, Optional[str]]:
    """
    Validate logging configuration from environment variables.
    
    Returns:
        Tuple of (is_valid, error_message)
        - is_valid: True if logging config is valid
        - error_message: Error message if invalid, None if valid
    """
    import logging
    
    # Validate LOG_LEVEL
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if log_level not in valid_levels:
        return False, (
            f"Invalid LOG_LEVEL: '{log_level}'. "
            f"Must be one of: {', '.join(sorted(valid_levels))}"
        )
    
    # Validate LOG_FORMAT
    log_format = os.getenv("LOG_FORMAT", "default").lower()
    valid_formats = {"default", "json"}
    if log_format not in valid_formats:
        return False, (
            f"Invalid LOG_FORMAT: '{log_format}'. "
            f"Must be one of: {', '.join(sorted(valid_formats))}"
        )
    
    # Validate LOG_VERBOSE_CONSOLE
    verbose_console = os.getenv("LOG_VERBOSE_CONSOLE", "false").lower()
    if verbose_console not in {"true", "false"}:
        return False, (
            f"Invalid LOG_VERBOSE_CONSOLE: '{verbose_console}'. "
            f"Must be 'true' or 'false'"
        )
    
    # Validate THIRD_PARTY_LOG_LEVEL
    third_party_level = os.getenv("THIRD_PARTY_LOG_LEVEL", "ERROR").upper()
    if third_party_level not in valid_levels:
        return False, (
            f"Invalid THIRD_PARTY_LOG_LEVEL: '{third_party_level}'. "
            f"Must be one of: {', '.join(sorted(valid_levels))}"
        )
    
    # Validate LOG_FILE (if set, check if path is valid format)
    log_file = os.getenv("LOG_FILE")
    if log_file:
        # Check if path contains invalid characters (basic validation)
        from pathlib import Path
        try:
            # Try to create a Path object to validate format
            log_path = Path(log_file)
            # Check if parent directory can be determined (basic path validation)
            if log_path.is_absolute() or log_path.parent != Path("."):
                # Path seems valid, but we don't check if directory exists (it will be created)
                pass
        except (ValueError, OSError) as e:
            return False, (
                f"Invalid LOG_FILE path: '{log_file}'. "
                f"Error: {str(e)}"
            )
    
    return True, None


def validate_all_config() -> Tuple[bool, List[str]]:
    """
    Validate all configuration (CodeQL, LLM, and Logging).
    
    Returns:
        Tuple of (is_valid, error_messages)
        - is_valid: True if all config is valid
        - error_messages: List of error messages (empty if valid)
    """
    errors: List[str] = []
    
    # Validate CodeQL path
    codeql_valid, codeql_error = validate_codeql_path()
    if not codeql_valid:
        errors.append(f"❌ CodeQL Configuration Error:\n{codeql_error}")
    
    # Validate LLM config
    llm_valid, llm_error = validate_llm_config()
    if not llm_valid:
        errors.append(f"❌ LLM Configuration Error:\n{llm_error}")
    
    # Validate Logging config
    logging_valid, logging_error = validate_logging_config()
    if not logging_valid:
        errors.append(f"❌ Logging Configuration Error:\n{logging_error}")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def validate_and_exit_on_error() -> None:
    """
    Validate all configuration and exit with error message if invalid.
    
    This is the main function to call at startup.
    
    Raises:
        LLMConfigError: If LLM configuration is invalid
        CodeQLConfigError: If CodeQL configuration is invalid
        VulnhallaError: If Logging configuration is invalid
    """
    from src.utils.exceptions import LLMConfigError, CodeQLConfigError, VulnhallaError
    
    is_valid, errors = validate_all_config()
    
    if not is_valid:
        errors_block = "\n\n".join(errors)
        
        has_llm_error = any("LLM" in error for error in errors)
        has_codeql_error = any("CodeQL" in error for error in errors)
        has_logging_error = any("Logging" in error for error in errors)
        
        # Priority: LLM > CodeQL > Logging
        if has_llm_error:
            raise LLMConfigError(errors_block)
        elif has_codeql_error:
            raise CodeQLConfigError(errors_block)
        elif has_logging_error:
            raise VulnhallaError(errors_block)
        else:
            raise VulnhallaError(errors_block)

