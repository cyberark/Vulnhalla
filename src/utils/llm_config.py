#!/usr/bin/env python3
"""
LLM Configuration Module

Loads LLM configuration from .env file or environment variables.
Supports multiple providers via LiteLLM.
"""

import os
from pathlib import Path
from typing import Dict, Optional, Any
from dotenv import load_dotenv

# Load .env file if it exists, otherwise try .env.example
if Path(".env").exists():
    load_dotenv(".env")
elif Path(".env.example").exists():
    load_dotenv(".env.example")

# Allowed LLM providers
ALLOWED_LLM_PROVIDERS = {
    "openai", "azure", "anthropic", "mistral", "codestral",
    "groq", "openrouter", "huggingface", "cohere", "bedrock",
    "vertex_ai", "gemini", "ollama"
}


def get_model_name(provider: Optional[str], model: Optional[str]) -> str:
    """
    Construct the model name in LiteLLM format.
    
    Args:
        provider: Provider name (e.g., "openai", "azure", "anthropic")
        model: Model name (e.g., "gpt-4o", "claude-3-opus", "openrouter/google/gemini-pro")
    
    Returns:
        Model name in LiteLLM format (e.g., "gpt-4o" or "azure/gpt-4o")
    """
    if not model:
        return "gpt-4o"  # Default fallback
    
    # For OpenAI, return as-is (no prefix needed)
    if provider == "openai":
        return model
    
    # For Azure, ensure model looks like "azure/<deployment_name>"
    if provider == "azure":
        if model.startswith("azure/"):
            return model
        return f"azure/{model}"
    
    # For all other providers, add provider/ prefix if not already present
    if provider:
        if model.startswith(f"{provider}/"):
            return model  # Already has correct prefix
        return f"{provider}/{model}"
    
    return model


def load_llm_config() -> Dict[str, Any]:
    """
    Load LLM configuration from .env file or environment variables.
    
    Returns:
        Dictionary with LLM configuration:
        {
            "provider": str,
            "model": str,
            "api_key": str,
            "endpoint": Optional[str],
            "api_version": Optional[str],
            "temperature": float,
            "top_p": float
        }
    
    Raises:
        ValueError: If required configuration is missing
    """
    # Determine provider
    provider = os.getenv("PROVIDER", "openai").lower()
    
    # Normalize aliases to canonical provider name
    if provider == "google":
        provider = "gemini"
    
    # Validate provider is in allowed list
    if provider not in ALLOWED_LLM_PROVIDERS:
        raise ValueError(
            f"Provider '{provider}' is not supported. "
            f"Allowed providers: {', '.join(sorted(ALLOWED_LLM_PROVIDERS))}"
        )
    
    # Get model name
    model = os.getenv("MODEL", "gpt-4o")
    
    # Get API key and provider-specific config based on provider
    api_key = None
    endpoint = None
    api_version = None
    
    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
    
    elif provider == "azure":
        api_key = os.getenv("AZURE_OPENAI_API_KEY") or os.getenv("AZURE_API_KEY")
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT") or os.getenv("AZURE_API_BASE")
        api_version = os.getenv("AZURE_OPENAI_API_VERSION") or os.getenv("AZURE_API_VERSION", "2024-08-01-preview")
    
    elif provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY")
    
    elif provider == "gemini":
        api_key = os.getenv("GOOGLE_API_KEY")
    
    elif provider == "mistral":
        api_key = os.getenv("MISTRAL_API_KEY")
    
    elif provider == "codestral":
        # Codestral uses Mistral API key
        api_key = os.getenv("MISTRAL_API_KEY")
    
    elif provider == "groq":
        api_key = os.getenv("GROQ_API_KEY")
    
    elif provider == "openrouter":
        api_key = os.getenv("OPENROUTER_API_KEY")
    
    elif provider == "huggingface":
        api_key = os.getenv("HUGGINGFACE_API_KEY")
    
    elif provider == "cohere":
        api_key = os.getenv("COHERE_API_KEY") or os.getenv("CO_API_KEY")
    
    elif provider == "bedrock":
        # Bedrock supports multiple authentication methods:
        # 1. AWS SSO via profile (recommended): AWS_PROFILE
        # 2. Static credentials: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
        # 3. Temporary credentials: Above + AWS_SESSION_TOKEN
        aws_profile = os.getenv("AWS_PROFILE")
        aws_region = os.getenv("AWS_REGION_NAME", "us-east-1")
        
        if aws_profile:
            # Profile-based auth (SSO, IAM roles) - SDK handles credential resolution
            api_key = "bedrock_profile_auth"
        else:
            # Static or temporary credentials
            api_key = os.getenv("AWS_ACCESS_KEY_ID")
        
        # Store region in endpoint field for Bedrock
        endpoint = aws_region
    
    elif provider == "vertex_ai":
        # Vertex AI uses GCP credentials (service account JSON or GOOGLE_APPLICATION_CREDENTIALS)
        # No API key needed, but we set a placeholder to pass validation
        gcp_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not gcp_creds and not Path("~/.config/gcloud/application_default_credentials.json").expanduser().exists():
            raise ValueError(
                "GCP credentials not found. Set GOOGLE_APPLICATION_CREDENTIALS or run 'gcloud auth application-default login'"
            )
        api_key = "vertex_ai_placeholder"
    
    elif provider == "ollama":
        # Ollama uses OLLAMA_BASE_URL (defaults to http://localhost:11434)
        endpoint = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        # Ollama doesn't require API key, but we set a placeholder to pass validation
        api_key = "ollama_placeholder"
    
    # Get optional parameters
    temperature = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    top_p = float(os.getenv("LLM_TOP_P", "0.2"))
    
    config = {
        "provider": provider,
        "model": get_model_name(provider, model),
        "api_key": api_key,
        "temperature": temperature,
        "top_p": top_p
    }
    
    # Add provider-specific fields
    if endpoint:
        config["endpoint"] = endpoint
    if api_version:
        config["api_version"] = api_version
    
    # Special handling for Bedrock (store AWS credentials and profile)
    if provider == "bedrock":
        config["aws_region"] = endpoint  # Store region in endpoint field
        
        # Profile-based authentication (AWS SSO, IAM roles)
        aws_profile = os.getenv("AWS_PROFILE")
        if aws_profile:
            config["aws_profile"] = aws_profile
        else:
            # Static or temporary credentials
            config["aws_secret_access_key"] = os.getenv("AWS_SECRET_ACCESS_KEY")
            aws_session_token = os.getenv("AWS_SESSION_TOKEN")
            if aws_session_token:
                config["aws_session_token"] = aws_session_token
    
    # Special handling for Vertex AI (store GCP project/location if provided)
    if provider == "vertex_ai":
        if os.getenv("GCP_PROJECT_ID"):
            config["gcp_project_id"] = os.getenv("GCP_PROJECT_ID")
        if os.getenv("GCP_LOCATION"):
            config["gcp_location"] = os.getenv("GCP_LOCATION")
    
    return config


