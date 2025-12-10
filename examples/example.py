#!/usr/bin/env python3

"""
example.py
----------
Example usage of Vulnhalla - demonstrates a full pipeline run:
1) Fetch CodeQL databases (from fetch_repos.py),
2) Run CodeQL queries (from run_codeql_queries.py),
3) Analyze results with LLM (from vulnhalla.py).
"""

import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.codeql.fetch_repos import fetch_codeql_dbs
from src.codeql.run_codeql_queries import compile_and_run_codeql_queries, DEFAULT_LANG
from src.vulnhalla import IssueAnalyzer
from src.utils.config import get_codeql_path
from src.utils.config_validator import validate_and_exit_on_error
from src.utils.logger import setup_logging, get_logger
from src.ui.ui_app import main as ui_main

logger = get_logger(__name__)


def main():
    """Run an end-to-end example of the Vulnhalla pipeline.

    This function fetches CodeQL databases for two demo
    repositories, runs CodeQL queries, classifies the findings
    using the configured LLM provider, writes the results
    to the output directory, and opens the results UI.
    """
    # Initialize logging
    setup_logging()
    logger.info("Starting Vulnhalla pipeline... This may take a few minutes.")
    logger.info("")
    
    # Validate configuration before starting
    validate_and_exit_on_error()
    
    # 1) Fetch CodeQL database
    logger.info("[1/3] Fetching CodeQL DBs")
    fetch_codeql_dbs(
        lang="c",          # Or use fetch_repos.LANG if set
        threads=4,        # Higher threads may exceed GitHub rate limits. Add a GitHub token if you need higher throughput.
        
        single_repo="videolan/vlc"
    )
    fetch_codeql_dbs(lang="c", threads=16, single_repo="redis/redis")

    # 2) Run CodeQL queries on all downloaded databases
    logger.info("\n[2/3] Running CodeQL Queries")
    compile_and_run_codeql_queries(
        codeql_bin=get_codeql_path(),
        lang="c",
        threads=16,
        timeout=300
    )

    # 3) Build/Analyze CodeQL results
    logger.info("\n[3/3] Building and Analyzing Results")
    # Load configuration from .env file (create .env from .env.example)
    # Or use: analyzer = IssueAnalyzer(lang="c", api_key="your-api-key")
    analyzer = IssueAnalyzer(lang="c")
    analyzer.run()

    logger.info("\n✅ Pipeline completed successfully!")
    logger.info("Opening results UI...")
    ui_main()

if __name__ == "__main__":
    main()
