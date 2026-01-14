#!/usr/bin/env python3
"""
Data models for Vulnhalla UI.
"""

from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class Issue:
    """
    Represents a single analyzed issue from CodeQL analysis results.
    
    Attributes:
        id (str): Issue identifier extracted from filename (e.g., "1", "2").
        name (str): Issue name or type.
        file (str): File path basename.
        line (int): Line number where the issue occurs.
        status (str): LLM classification status ("true", "false", or "more").
        issue_type (str): Issue type directory name.
        lang (str): Language code.
        repo (str): Repository name in format "org/repo" (e.g., "redis/redis").
        raw_path (str): Path to the _raw.json file.
        final_path (str): Path to the _final.json file.
        raw_data (Optional[Dict]): Parsed raw JSON data.
        final_data (Optional[List]): Parsed final JSON containing LLM messages.
        manual_decision (Optional[str]): Manual verdict set by user ("True Positive", 
            "False Positive", "Uncertain", or None for "Not Set").
    """
    id: str
    name: str
    file: str
    line: int
    status: str
    issue_type: str
    lang: str
    repo: str
    raw_path: str
    final_path: str
    raw_data: Optional[Dict] = None
    final_data: Optional[List] = None
    manual_decision: Optional[str] = None


# Constants for status ordering (used in sorting)
STATUS_ORDER: Dict[str, int] = {"true": 0, "false": 1, "more": 2}

MANUAL_DECISION_ORDER: Dict[Optional[str], int] = {
    "True Positive": 0,
    "False Positive": 1,
    "Uncertain": 2,
    "Not Set": 3,
    None: 3
}

# Status display mapping (internal status -> display text)
STATUS_DISPLAY_MAP: Dict[str, str] = {
    "true": "True Positive",
    "false": "False Positive",
    "more": "Needs More Data"
}


def format_status_display(status: str) -> str:
    """
    Format status value for display.

    Args:
        status (str): Internal status value ("true", "false", or "more").

    Returns:
        str: Display text for the status.
    """
    return STATUS_DISPLAY_MAP.get(status, status)


def format_manual_decision(manual_decision: Optional[str]) -> str:
    """
    Format manual decision value for display.

    Args:
        manual_decision (Optional[str]): Manual decision value or None.

    Returns:
        str: Display text for the manual decision ("Not Set" if None).
    """
    return manual_decision if manual_decision else "Not Set"


def get_default_sort_key(issue: "Issue") -> float:
    """
    Get default sort key for an issue (numeric ID).

    Args:
        issue (Issue): Issue to get sort key for.

    Returns:
        float: Numeric ID or inf if ID is not numeric.
    """
    return int(issue.id) if issue.id.isdigit() else float('inf')


def get_sort_key_for_column(column: str) -> Optional[Callable[["Issue"], any]]:
    """
    Get sort key function for a given column name.

    Args:
        column (str): Column name to sort by.

    Returns:
        Optional[Callable]: Sort key function, or None if column not supported.
    """
    sort_keys: Dict[str, Callable[["Issue"], any]] = {
        "ID": lambda issue: int(issue.id) if issue.id.isdigit() else float('inf'),
        "Repo": lambda issue: issue.repo.lower(),
        "Issue name": lambda issue: issue.name.lower(),
        "File": lambda issue: issue.file.lower(),
        "LLM decision": lambda issue: STATUS_ORDER.get(issue.status, 99),
        "Manual decision": lambda issue: MANUAL_DECISION_ORDER.get(issue.manual_decision, 3),
    }
    return sort_keys.get(column)

