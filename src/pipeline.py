#!/usr/bin/env python3
"""
Pipeline orchestration for Vulnhalla.
This module coordinates the complete analysis pipeline:
1. Fetch CodeQL databases
2. Run CodeQL queries
3. Classify results with LLM
4. Open UI (optional)
"""
import sys
from pathlib import Path
from typing import Optional

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.codeql.fetch_repos import fetch_codeql_dbs
from src.codeql.run_codeql_queries import compile_and_run_codeql_queries
from src.utils.config import get_codeql_path
from src.utils.config_validator import validate_and_exit_on_error
from src.utils.logger import setup_logging, get_logger
from src.utils.exceptions import (
    CodeQLError, CodeQLConfigError, CodeQLExecutionError,
    LLMError, LLMConfigError, LLMApiError,
    VulnhallaError
)
from src.vulnhalla import IssueAnalyzer
from src.ui.ui_app import main as ui_main

# Initialize logging
setup_logging()
logger = get_logger(__name__)


def _log_exception_cause(e: Exception) -> None:
    """
    Log the cause of an exception if available and not already included in the exception message.
    Checks both e.cause (if set via constructor) and e.__cause__ (if set via 'from e').
    """
    cause = getattr(e, 'cause', None) or getattr(e, '__cause__', None)
    if cause:
        # Only log cause if it's not already included in the exception message
        cause_str = str(cause)
        error_str = str(e)
        if cause_str not in error_str:
            logger.error("   Cause: %s", cause)


def analyze_pipeline(repo: Optional[str] = None, lang: str = "c", threads: int = 16, open_ui: bool = True) -> None:
    """
    Run the complete Vulnhalla pipeline: fetch, analyze, classify, and optionally open UI.
    
    Args:
        repo: Optional GitHub repository name (e.g., "redis/redis"). If None, fetches top repos.
        lang: Programming language code. Defaults to "c".
        threads: Number of threads for CodeQL operations. Defaults to 16.
        open_ui: Whether to open the UI after completion. Defaults to True.
    
    Note:
        This function catches and handles all exceptions internally, logging errors
        and exiting with code 1 on failure. It does not raise exceptions.
    """
    logger.info("🚀 Starting Vulnhalla Analysis Pipeline")
    logger.info("=" * 60)
    
    try:
        # Validate configuration before starting
        validate_and_exit_on_error()
    except (CodeQLConfigError, LLMConfigError, VulnhallaError) as e:
        # Format error message for display
        message = f"""
⚠️ Configuration Validation Failed
============================================================
{str(e)}
============================================================
Please fix the configuration errors above and try again.
See README.md for configuration reference.
"""
        logger.error(message)
        _log_exception_cause(e)
        sys.exit(1)
    
    try:
        # Step 1: Fetch CodeQL databases
        logger.info("\n[1/4] Fetching CodeQL Databases")
        logger.info("-" * 60)
        if repo:
            logger.info("Fetching database for: %s", repo)
            fetch_codeql_dbs(lang=lang, threads=threads, single_repo=repo)
        else:
            logger.info("Fetching top repositories for language: %s", lang)
            fetch_codeql_dbs(lang=lang, max_repos=100, threads=4)
    except CodeQLConfigError as e:
        logger.error("❌ Configuration error while fetching CodeQL databases: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your GitHub token and permissions.")
        sys.exit(1)
    except CodeQLError as e:
        logger.error("❌ Failed to fetch CodeQL databases: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check file permissions, disk space, and GitHub API access.")
        sys.exit(1)
    
    try:
        # Step 2: Run CodeQL queries
        logger.info("\n[2/4] Running CodeQL Queries")
        logger.info("-" * 60)
        compile_and_run_codeql_queries(
            codeql_bin=get_codeql_path(),
            lang=lang,
            threads=threads,
            timeout=300
        )
    except CodeQLConfigError as e:
        logger.error("❌ Configuration error while running CodeQL queries: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your CODEQL_PATH configuration.")
        sys.exit(1)
    except CodeQLExecutionError as e:
        logger.error("❌ Failed to execute CodeQL queries: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your CodeQL installation and database files.")
        sys.exit(1)
    except CodeQLError as e:
        logger.error("❌ CodeQL error: %s", e)
        _log_exception_cause(e)
        sys.exit(1)
    
    try:
        # Step 3: Classify results with LLM
        logger.info("\n[3/4] Classifying Results with LLM")
        logger.info("-" * 60)
        analyzer = IssueAnalyzer(lang=lang)
        analyzer.run()
    except LLMConfigError as e:
        logger.error("❌ LLM configuration error: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your LLM configuration and API credentials in .env file.")
        sys.exit(1)
    except LLMApiError as e:
        logger.error("❌ LLM API error: %s", e)
        _log_exception_cause(e)
        logger.error("   Please check your API key, network connection, and rate limits.")
        sys.exit(1)
    except LLMError as e:
        logger.error("❌ LLM error: %s", e)
        _log_exception_cause(e)
        sys.exit(1)
    except CodeQLError as e:
        logger.error("❌ CodeQL error while reading database files: %s", e)
        _log_exception_cause(e)
        logger.error("   This step reads CodeQL database files (YAML, ZIP, CSV) to prepare data for LLM analysis.")
        logger.error("   Please check your CodeQL databases and files are accessible.")
        sys.exit(1)
    except VulnhallaError as e:
        logger.error("❌ File system error while saving results: %s", e)
        _log_exception_cause(e)
        logger.error("   This step writes analysis results to disk and creates output directories.")
        logger.error("   Please check file permissions and disk space.")
        sys.exit(1)
    
    # Step 4: Open UI
    if open_ui:
        logger.info("\n[4/4] Opening UI")
        logger.info("-" * 60)
        logger.info("✅ Pipeline completed successfully!")
        logger.info("Opening results UI...")
        ui_main()
    else:
        logger.info("\n✅ Pipeline completed successfully!")
        logger.info("View results with: python src/ui/ui_app.py")


def main_analyze() -> None:
    """
    CLI entry point for the complete analysis pipeline.
    Usage:
        vulnhalla-analyze                    # Analyze top 100 repos
        vulnhalla-analyze redis/redis        # Analyze specific repo
    """
    # Parse command line arguments
    repo = None
    if len(sys.argv) > 1:
        repo = sys.argv[1]
        if "/" not in repo:
            logger.error("❌ Error: Repository must be in format 'org/repo'")
            logger.error("   Example: python src/pipeline.py redis/redis")
            logger.error("   Or run without arguments to analyze top repositories")
            sys.exit(1)
    analyze_pipeline(repo=repo)


if __name__ == '__main__':
    main_analyze()