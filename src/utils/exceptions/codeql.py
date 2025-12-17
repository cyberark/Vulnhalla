"""CodeQL-related exceptions."""

from src.utils.exceptions.base import VulnhallaError


class CodeQLError(VulnhallaError):
    """Base class for all CodeQL-related errors."""
    pass


class CodeQLConfigError(CodeQLError):
    """CodeQL configuration errors (path, executable, packs, etc.)."""
    pass


class CodeQLExecutionError(CodeQLError):
    """CodeQL query/database execution/decoding errors."""
    pass


