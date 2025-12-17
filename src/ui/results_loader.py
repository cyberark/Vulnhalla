#!/usr/bin/env python3
"""
Results loader for parsing issue results from output/results/ directory.
"""

import os
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ui.models import Issue
from src.utils.logger import get_logger
from src.utils.exceptions import VulnhallaError

logger = get_logger(__name__)


class ResultsLoader:
    """
    Loads and parses issue results from output/results/ directory.
    """
    
    def __init__(self, results_root: str = "output/results"):
        """
        Initialize the ResultsLoader.

        Args:
            results_root (str): Root directory containing analysis results. 
                Defaults to "output/results".
        """
        self.results_root = Path(results_root)
    
    def extract_status(self, content: str) -> str:
        """
        Extract status code from LLM content.

        Args:
            content (str): The LLM message content to analyze.

        Returns:
            str: Status code - "true" (if 1337 found), "false" (if 1007 found), 
                or "more" (otherwise).
        """
        if not content:
            return "more"
        content_lower = content.lower()
        if "1337" in content_lower:
            return "true"
        elif "1007" in content_lower:
            return "false"
        return "more"
    
    def parse_final_json(self, path: Path) -> Optional[List[Dict]]:
        """
        Parse _final.json file containing LLM messages.

        Handles both valid JSON and malformed Python list representations.

        Args:
            path (Path): Path to the _final.json file.

        Returns:
            Optional[List[Dict]]: List of message dictionaries, or None if parsing fails.
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError as e:
            logger.error("File not found: %s", path)
            return None
        except PermissionError as e:
            logger.error("Permission denied reading file: %s", path)
            return None
        except OSError as e:
            logger.error("OS error reading file: %s", path)
            return None
    
        try:
            return json.loads(content)
        except json.JSONDecodeError:
                # Parse manually
                messages = []
                for match in re.finditer(r"\{'role':", content):
                    start = match.start()
                    # Find the matching closing brace
                    brace_count = 0
                    end = start
                    in_single_quote = False
                    in_double_quote = False
                    escape_next = False
                    for i in range(start, len(content)):
                        char = content[i]
                        if escape_next:
                            escape_next = False
                            continue
                        if char == '\\':
                            escape_next = True
                            continue
                        if char == "'" and not escape_next and not in_double_quote:
                            in_single_quote = not in_single_quote
                            continue
                        if char == '"' and not escape_next and not in_single_quote:
                            in_double_quote = not in_double_quote
                            continue
                        if not in_single_quote and not in_double_quote:
                            if char == '{':
                                brace_count += 1
                            elif char == '}':
                                brace_count -= 1
                                if brace_count == 0:
                                    end = i + 1
                                    break
                    
                    dict_str = content[start:end]
                    
                    role_match = re.search(r"'role':\s*['\"]([^'\"]+)['\"]", dict_str)
                    # Extract content field
                    content_match = None
                    
                    # Determine which quote type used for content
                    content_key_pos = dict_str.find("'content':")
                    if content_key_pos >= 0:
                        # Find the quote character after 'content':
                        quote_start = content_key_pos + len("'content':")
                        # Skip whitespace
                        while quote_start < len(dict_str) and dict_str[quote_start] in ' \t\n':
                            quote_start += 1
                        if quote_start < len(dict_str):
                            quote_char = dict_str[quote_start]
                            if quote_char == '"':
                                content_pattern = r"'content':\s*\"((?:[^\"\\]|\\.)*)\""
                                content_match = re.search(content_pattern, dict_str, re.DOTALL)
                            elif quote_char == "'":
                                content_pattern = r"'content':\s*'((?:[^'\\]|\\.|'')*)'"
                                content_match = re.search(content_pattern, dict_str, re.DOTALL)
                    
                    if not content_match:
                        content_pattern = r"'content':\s*'((?:[^'\\]|\\.|'')*)'"
                        content_match = re.search(content_pattern, dict_str, re.DOTALL)
                        if not content_match:
                            content_pattern = r"'content':\s*\"((?:[^\"\\]|\\.)*)\""
                            content_match = re.search(content_pattern, dict_str, re.DOTALL)
                    
                    if role_match and content_match:
                        content_str = content_match.group(1)
                        content_str = content_str.replace('\\n', '\n').replace("\\'", "'").replace('\\"', '"').replace('\\\\', '\\')
                        messages.append({
                            'role': role_match.group(1),
                            'content': content_str
                        })
                return messages if messages else None
        except Exception:
            return None
        
    def parse_raw_json(self, path: Path) -> Optional[Dict]:
        """
        Parse _raw.json file containing original CodeQL issue data.

        Args:
            path (Path): Path to the _raw.json file.

        Returns:
            Optional[Dict]: Parsed JSON data as a dictionary, or None if parsing fails.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.loads(f.read().replace("\n", "\\n"))
        except FileNotFoundError as e:
            logger.error("File not found: %s", path)
            return None
        except PermissionError as e:
            logger.error("Permission denied reading file: %s", path)
            return None
        except json.JSONDecodeError as e:
            logger.error("JSON error parsing %s: %s", path, e)
            return None
        except OSError as e:
            logger.error("OS error reading file: %s", path)
            return None
    
    @staticmethod
    def _extract_issue_name(raw_data: Dict, issue_type: str) -> str:
        """
        Extract issue name from raw_data.

        Args:
            raw_data (Dict): Raw JSON data containing issue information.
            issue_type (str): Fallback issue type if name cannot be extracted.

        Returns:
            str: Issue name extracted from prompt or function name, or issue_type as fallback.
        """
        issue_name = raw_data.get("current_function", {}).get("function_name", issue_type)
        if "prompt" in raw_data:
            name_match = re.search(r'Name:\s*([^\n]+)', raw_data["prompt"])
            if name_match:
                return name_match.group(1).strip()
        return issue_name
    
    @staticmethod
    def _extract_file_info(raw_data: Dict) -> tuple[str, int]:
        """
        Extract file basename and line number from raw_data.

        Args:
            raw_data (Dict): Raw JSON data containing function information.

        Returns:
            tuple[str, int]: Tuple of (file_basename, line_number).
        """
        func = raw_data.get("current_function", {})
        file_path = func.get("file", "")
        return (os.path.basename(file_path) if file_path else "unknown", int(func.get("start_line", 0)))
    
    @staticmethod
    def _extract_repo_from_db_path(db_path: str) -> str:
        """
        Extract repository name (org/repo) from database path.
        
        Database path structure: output/databases/<lang>/<org>/<repo> 
        We extract the repo name from the basename of db_path, and the org name from
        the parent directory.
        
        Args:
            db_path (str): The database path from raw_data (e.g., "output/databases/c/redis/cpp")
        
        Returns:
            str: Repository name in format "org/repo" (e.g., "redis/cpp")
        """
        if not db_path:
            return "unknown/unknown"
        
        try:
            # DB path Structure: output/databases/<lang>/<org>/<repo>
            # Example: output/databases/c/redis/cpp
            repo_name = os.path.basename(db_path)
            parent_dir = os.path.dirname(db_path)
            org_name = os.path.basename(parent_dir)
            
            if org_name and repo_name:
                return f"{org_name}/{repo_name}"
            else:
                return "unknown/unknown"
        except Exception:
            return "unknown/unknown"
    
    def load_all_issues(self, lang: str) -> Tuple[List[Issue], List[str]]:
        """
        Scan output/results/<lang>/<issue_type>/ and load all issues.

        Args:
            lang (str): Language code to scan (e.g., "c").

        Returns:
            Tuple[List[Issue], List[str]]: 
                - List of Issue objects loaded from all issue type directories.
                - List of error messages for files that failed to load.
        """
        issues = []
        errors = []
        lang_dir = self.results_root / lang
        
        if not lang_dir.exists():
            return issues, errors
        
        # Scan each issue_type directory
        for issue_type_dir in lang_dir.iterdir():
            if not issue_type_dir.is_dir():
                continue
            
            issue_type = issue_type_dir.name
            
            # Find all _final.json files
            for final_file in issue_type_dir.glob("*_final.json"):
                # Extract issue ID from filename
                issue_id = final_file.stem.replace("_final", "")
                
                # Find corresponding _raw.json
                raw_file = final_file.parent / f"{issue_id}_raw.json"
                
                if not raw_file.exists():
                    errors.append(f"Missing raw file for issue {issue_id}: {raw_file}")
                    continue
                
                # Parse JSON files
                final_data = self.parse_final_json(final_file)
                raw_data = self.parse_raw_json(raw_file)
                
                if not final_data:
                    errors.append(f"Failed to parse final JSON: {final_file}")
                    continue
                
                if not raw_data:
                    errors.append(f"Failed to parse raw JSON: {raw_file}")
                    continue
                
                file_basename, start_line = self._extract_file_info(raw_data)
                issue_name = self._extract_issue_name(raw_data, issue_type)
                
                # Extract repo from db_path in raw_data
                db_path = raw_data.get("db_path", "")
                repo = self._extract_repo_from_db_path(db_path) if db_path else "unknown/unknown"
                
                # Extract status from final_data
                status = "more"
                # Try to find status in assistant messages
                for msg in reversed(final_data):
                    if isinstance(msg, dict) and msg.get("role", "").lower() == "assistant":
                        content = msg.get("content", "")
                        if content:
                            status = self.extract_status(content)
                            if status != "more":
                                break
                # No status found in assistant messages, check all messages
                if status == "more":
                    for msg in reversed(final_data):
                        if isinstance(msg, dict) and "content" in msg:
                            status = self.extract_status(msg.get("content", ""))
                            if status != "more":
                                break
                
                issue = Issue(
                    id=issue_id,
                    name=issue_name,
                    file=file_basename,
                    line=start_line,
                    status=status,
                    issue_type=issue_type,
                    lang=lang,
                    repo=repo,
                    raw_path=str(raw_file),
                    final_path=str(final_file),
                    raw_data=raw_data,
                    final_data=final_data
                )
                issues.append(issue)
        
        return issues, errors

