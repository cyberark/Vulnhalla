#!/usr/bin/env python3

"""
example.py
----------
Example usage of Vulnhalla - demonstrates a full pipeline run for multiple repositories.

This example processes two repositories using the analyze_pipeline function,
which handles:
1) Fetching CodeQL databases
2) Running CodeQL queries
3) Analyzing results with LLM
4) Opening the results UI (once at the end)
"""

import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import analyze_pipeline
from src.utils.logger import setup_logging, get_logger

logger = get_logger(__name__)


def main():
    """
    Run an end-to-end example of the Vulnhalla pipeline for multiple repositories.

    This function processes two demo repositories using the analyze_pipeline function.
    Each repository goes through the complete pipeline:
    - Fetch CodeQL databases
    - Run CodeQL queries
    - Classify findings using the configured LLM provider
    - Write results to the output directory
    
    After processing both repositories, the results UI is opened once.
    """
    # Initialize logging
    setup_logging()
    logger.info("Starting Vulnhalla pipeline example... This may take a few minutes.")
    logger.info("")
    
    # Process videolan/vlc
    analyze_pipeline(
        repo="videolan/vlc",
        lang="c",
        threads=4,  # Lower threads to avoid GitHub rate limits
        open_ui=False  # Open UI once at the end
    )
    
    # Process redis/redis
    analyze_pipeline(
        repo="redis/redis",
        lang="c",
        threads=16,
    )

if __name__ == "__main__":
    main()
