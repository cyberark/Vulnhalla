#!/usr/bin/env python3
"""
Core analysis engine for Vulnhalla.

This module coordinates the aggregation of raw CodeQL findings and their
classification by an LLM. It loads issues from CodeQL result files,
groups them by issue type, runs LLM-based analysis to decide whether
each finding is a true positive, false positive, or needs more data,
and writes structured result files for further inspection (e.g. in the UI).

Analysis Pipeline Algorithm:
    1. Collect DBs via get_all_dbs(dbs_folder), parse issues.csv, group by issue['name'].
    2. For each issue: find containing function via find_function_by_line() (smallest line range).
    3. Extract snippet and full function code.
    4. Replace bracket references in the message; if references point outside current function, append those functions' code.
    5. Build prompt; save *_raw.json; run LLM analysis; save *_final.json.
    6. Classify by substring: "1337" → true, "1007" → false, else → more; log stats.
"""

from pathlib import Path, PurePosixPath
import csv
import re
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

# Import from common
from src.utils.common_functions import (
    get_all_dbs,
    read_file_lines_from_zip,
    read_file as read_file_utf8,
    write_file_ascii,
    read_yml
)

# Script that holds your GPT logic
from src.llm.llm_analyzer import LLMAnalyzer
from src.utils.config_validator import validate_and_exit_on_error
from src.utils.logger import get_logger
from src.utils.exceptions import VulnhallaError, CodeQLError

logger = get_logger(__name__)


class IssueAnalyzer:
    """
    Analyzes all issues in CodeQL databases, fetches relevant code snippets,
    and forwards them to an LLM (via llm_analyzer) for triage.
    """

    def __init__(self, lang: str = "c", config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the IssueAnalyzer with default parameters.

        Args:
            lang (str, optional): The language code. Defaults to 'c'.
            config (Dict, optional): Full LLM configuration dictionary. If not provided, loads from .env file.
        """
        self.lang = lang
        self.db_path: Optional[str] = None
        self.code_path: Optional[str] = None
        self.config = config

    # ----------------------------------------------------------------------
    # 1. CSV Parsing and Data Gathering
    # ----------------------------------------------------------------------

    def parse_issues_csv(self, file_name: str) -> List[Dict[str, str]]:
        """
        Reads the issues.csv file produced by CodeQL (with a custom or default
        set of columns) and returns a list of dicts.

        Args:
            file_name (str): The path to 'issues.csv'.

        Returns:
            List[Dict[str, str]]: A list of issue objects parsed from CSV rows.
        
        Raises:
            CodeQLError: If file cannot be read (not found, permission denied, etc.).
        """
        field_names = [
            "name", "help", "type", "message",
            "file", "start_line", "start_offset",
            "end_line", "end_offset"
        ]
        issues = []
        try:
            with Path(file_name).open("r", encoding="utf-8") as f:
                csv_reader = csv.DictReader(f, fieldnames=field_names)
                for row in csv_reader:
                    issues.append(row)
        except FileNotFoundError as e:
            raise CodeQLError(f"Issues CSV file not found: {file_name}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading issues CSV: {file_name}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading issues CSV: {file_name}") from e
        return issues

    def collect_issues_from_databases(self, dbs_folder: str) -> Dict[str, List[Dict[str, str]]]:
        """
        Searches through all CodeQL databases in `dbs_folder`, collects issues
        from each DB, and groups them by issue name.

        Args:
            dbs_folder (str): The folder containing the language-specific databases.

        Returns:
            Dict[str, List[Dict[str, str]]]: All issues, grouped by issue name.
        
        Raises:
            CodeQLError: If database folder cannot be accessed or issues cannot be read.
        """
        issues_statistics: Dict[str, List[Dict[str, str]]] = {}
        # get_all_dbs() raises CodeQLError on errors
        dbs_path = get_all_dbs(dbs_folder)
        for curr_db in dbs_path:
            logger.info("Processing DB: %s", curr_db)
            curr_db_path = Path(curr_db)
            function_tree_csv = curr_db_path / "FunctionTree.csv"
            issues_file = curr_db_path / "issues.csv"

            if function_tree_csv.exists() and issues_file.exists():
                # parse_issues_csv() raises CodeQLError on errors
                issues = self.parse_issues_csv(str(issues_file))
                for issue in issues:
                    if issue["name"] not in issues_statistics:
                        issues_statistics[issue["name"]] = []
                    issue["db_path"] = curr_db
                    issues_statistics[issue["name"]].append(issue)
            else:
                logger.error("Error: Execute run_codeql_queries.py first!")
                continue

        return issues_statistics

    # ----------------------------------------------------------------------
    # 2. Function and Snippet Extraction
    # ----------------------------------------------------------------------

    def find_function_by_line(self, function_tree_file: str, file_path: str, line: int) -> Optional[Dict[str, str]]:
        """
        Finds the most specific (smallest) function containing the given file and line number.

        Algorithm:
            - Iterate rows where file_path substring appears
            - Keep rows where start_line <= line <= end_line and file_path in function["file"]
            - Return function with smallest (end_line - start_line), else None

        Args:
            function_tree_file (str): Path to the 'FunctionTree.csv' file.
            file_path (str): File path substring to match (uses substring containment).
            line (int): The line number to check within function range.

        Returns:
            Optional[Dict[str, str]]: The best matching function dictionary, or None if not found.
        
        Raises:
            CodeQLError: If function tree file cannot be read (not found, permission denied, etc.).
        """
        keys = ["function_name", "file", "start_line", "function_id", "end_line", "caller_id"]
        best_function = None
        smallest_range = float('inf')

        try:
            with Path(function_tree_file).open("r", encoding="utf-8") as f:
                for row in f:
                    if file_path in row:
                        fields = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', row.strip())
                        if len(fields) != len(keys):
                            continue  # Skip malformed rows

                        function = dict(zip(keys, fields))
                        try:
                            start_line = int(function["start_line"])
                            end_line = int(function["end_line"])
                        except ValueError:
                            continue  # Skip if lines aren't integers

                        # Check if the target line falls within this function's range
                        if start_line <= line <= end_line:
                            if file_path in function["file"]:
                                # Greedy selection: track the function with smallest range
                                # (most specific/nested function containing the line)
                                size = end_line - start_line
                                if size < smallest_range:
                                    best_function = function
                                    smallest_range = size
        except FileNotFoundError as e:
            raise CodeQLError(f"Function tree file not found: {function_tree_file}") from e
        except PermissionError as e:
            raise CodeQLError(f"Permission denied reading function tree file: {function_tree_file}") from e
        except OSError as e:
            raise CodeQLError(f"OS error while reading function tree file: {function_tree_file}") from e

        return best_function

    def extract_function_code(self, code_file: List[str], function_dict: Dict[str, str]) -> str:
        """
        Produces lines of the function's code from a list of lines.

        Args:
            code_file (List[str]): A list of lines for the entire file.
            function_dict (Dict[str, str]): The dictionary describing the function.

        Returns:
            str: A snippet string of code for the function.
        """
        if not function_dict:
            return ""
        start_line = int(function_dict["start_line"]) - 1
        end_line = int(function_dict["end_line"])
        snippet_lines = code_file[start_line:end_line]
        snippet = "\n".join(
            f"{start_line + i}: {s.replace(chr(9), '    ')}"
            for i, s in enumerate(snippet_lines)
        )
        return snippet

    # ----------------------------------------------------------------------
    # 3. Text Replacement & Prompt Building
    # ----------------------------------------------------------------------

    def create_bracket_reference_replacer(
        self,
        db_path: str,
        code_path: str
    ) -> Callable[[re.Match], str]:
        """
        Creates a replacement callback for re.sub to transform CodeQL bracket references
        into readable code snippets.

        Algorithm:
            - Parse (variable, path_type, file_path, line, offsets)
            - Resolve path: relative:// → code_path + file_path; else strip leading '/'
            - Read from src.zip, slice snippet, return "var 'snippet' (filename:line)"

        Args:
            db_path (str): Path to the current CodeQL database.
            code_path (str): Base path to the code. May differ on Windows vs. Linux.

        Returns:
            Callable[[re.Match], str]: A function that can be used with `re.sub`.
        
        Note:
            The returned callback function may raise `CodeQLError` if ZIP file cannot be read.
        """
        def replacement(match):
            variable = match.group(1)
            path_type = match.group(2)
            file_path = match.group(3)
            line_number = match.group(4)
            start_offset = match.group(5)
            end_offset = match.group(6)

            if path_type == "relative://":
                full_path = code_path + file_path
            else:
                full_path = file_path[1:] if file_path.startswith("/") else file_path

            code_text = read_file_lines_from_zip(
                str(Path(db_path) / "src.zip"),
                full_path
            )
            code_lines = code_text.split("\n")
            snippet = code_lines[int(line_number) - 1][int(start_offset) - 1:int(end_offset)]

            file_name = PurePosixPath(file_path).name
            return f"{variable} '{snippet}' ({file_name}:{int(line_number)})"

        return replacement

    def build_prompt_by_template(
        self,
        issue: Dict[str, str],
        message: str,
        snippet: str,
        code: str
    ) -> str:
        """
        Builds the final 'prompt' template to feed into an LLM, combining
        the code snippet, code content, and a set of hints.

        Args:
            issue (Dict[str, str]): The issue dictionary from parse_issues_csv.
            message (str): The processed "message" text to embed.
            snippet (str): The direct snippet from the code for the particular highlight.
            code (str): Additional code context (e.g. entire function).

        Returns:
            str: A final prompt string with the template + hints + snippet + code.
        
        Raises:
            VulnhallaError: If template files cannot be read (not found, permission denied, etc.).
        """
        # If language is 'c', many queries are stored under 'cpp'
        lang_folder = "cpp" if self.lang == "c" else self.lang

        # Try to read an existing template specific to the issue name
        templates_base = Path("data/templates") / lang_folder
        hints_path = templates_base / f"{issue['name']}.template"
        if not hints_path.exists():
            hints_path = templates_base / "general.template"

        hints = read_file_utf8(str(hints_path))

        # Read the larger general template
        template_path = templates_base / "template.template"
        template = read_file_utf8(str(template_path))

        file_name = PurePosixPath(issue["file"]).name
        location = f"look at {file_name}:{int(issue['start_line'])} with '{snippet}'"

        # Special case for "Use of object after its lifetime has ended"
        if issue["name"] == "Use of object after its lifetime has ended":
            message = message.replace("here", f"here ({location})", 1)

        prompt = template.format(
            name=issue["name"],
            description=issue["help"],
            message=message,
            location=location,
            hints=hints,
            code=code
        )
        return prompt

    # ----------------------------------------------------------------------
    # 4. Saving LLM Results
    # ----------------------------------------------------------------------

    def ensure_directories_exist(self, dirs: List[str]) -> None:
        """
        Creates all directories in the given list if they do not already exist.

        Args:
            dirs (List[str]): A list of directory paths to create if missing.
        
        Raises:
            VulnhallaError: If directory creation fails (permission denied, etc.).
        """
        for d in dirs:
            dir_path = Path(d)
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                except PermissionError as e:
                    raise VulnhallaError(f"Permission denied creating directory: {d}") from e
                except OSError as e:
                    raise VulnhallaError(f"OS error creating directory: {d}") from e


    # ----------------------------------------------------------------------
    # 5. Main Analysis Routine
    # ----------------------------------------------------------------------

    def save_raw_input_data(
        self,
        prompt: str,
        function_tree_file: str,
        current_function: Dict[str, str],
        results_folder: str,
        issue_id: int
    ) -> None:
        """
        Saves the raw input data (prompt, function tree info, etc.) to a JSON file before
        sending it to the LLM.

        Args:
            prompt (str): The final prompt text sent to the LLM.
            function_tree_file (str): Path to 'FunctionTree.csv'.
            current_function (Dict[str, str]): The currently found function dict.
            results_folder (str): Folder path where we store the result files.
            issue_id (int): The numeric ID of the current issue.
        
        Raises:
            VulnhallaError: If file cannot be written (permission denied, etc.).
        """
        raw_data = json.dumps({
            "function_tree_file": function_tree_file,
            "current_function": current_function,
            "db_path": self.db_path,
            "code_path": self.code_path,
            "prompt": prompt
        }, ensure_ascii=False)

        raw_output_file = Path(results_folder) / f"{issue_id}_raw.json"
        write_file_ascii(str(raw_output_file), raw_data)

    def format_llm_messages(self, messages: List[str]) -> str:
        """
        Converts the list of messages returned by the LLM into a JSON-ish string to
        store as output.

        Args:
            messages (List[str]): The messages from the LLM.

        Returns:
            str: A string representation of LLM messages (somewhat JSON-formatted).
        """
        gpt_result = "[\n    " + ",\n    ".join(
            f"'''{item}'''" if "\n" in item else repr(item) for item in messages).replace("\\n", "\n    ").replace(
            "\\t", " ") + "\n]"
        return gpt_result

    def determine_issue_status(self, llm_content: str) -> str:
        """
        Checks the content returned by the LLM to see if it includes certain
        status codes that classify the issue as 'true' or 'false' or 'more'.

        Args:
            llm_content (str): The text content from the LLM's final response.

        Returns:
            str: "true" if content has '1337', "false" if content has '1007',
                 otherwise "more".
        """
        if "1337" in llm_content:
            return "true"
        elif "1007" in llm_content:
            return "false"
        else:
            return "more"

    def append_extra_functions(
        self,
        extra_lines: List[tuple[str, str, str]],
        function_tree_file: str,
        src_zip_path: str,
        code: str,
        current_function: Dict[str, str]
    ) -> Tuple[str, List[Dict[str, str]]]:
        """
        Appends code from additional functions referenced outside the current function.

        Algorithm:
            - Skip references within current function range
            - For external refs: find containing function via find_function_by_line(), dedupe by dict equality
            - Append extracted function code; return updated code and functions list

        Args:
            extra_lines (List[tuple[str, str, str]]): References as (path_type, file_path, line_number).
            function_tree_file (str): Path to 'FunctionTree.csv'.
            src_zip_path (str): Path to the DB's src.zip file.
            code (str): The existing code snippet.
            current_function (Dict[str, str]): The currently found function dict.

        Returns:
            Tuple[str, List[Dict[str, str]]]: Extended code snippet and list of all functions.
        
        Raises:
            CodeQLError: If function tree file or ZIP file cannot be read.
        """
        functions = [current_function]
        for another_func_ref in extra_lines:
            # Unpack reference tuple: (path_type, file_path, line_number)
            path_type, file_ref, line_ref = another_func_ref
            file_ref = file_ref.strip()

            # Resolve file path based on path type
            if path_type == "relative://":
                file_ref = self.code_path + file_ref
            else:
                # Remove leading slash for absolute paths (file://)
                file_ref = file_ref[1:] if file_ref.startswith("/") else file_ref

            # If it's within the same function's line range, skip
            start_line_func = int(current_function["start_line"])
            end_line_func = int(current_function["end_line"])
            if start_line_func <= int(line_ref) <= end_line_func:
                continue

            # Find the function containing this reference using the greedy selection algorithm
            new_function = self.find_function_by_line(function_tree_file, "/" + file_ref, int(line_ref))
            # Deduplication: Only add if function was found and not already in the list
            if new_function and new_function not in functions:
                functions.append(new_function)
                # Read the function's source file and extract its code
                code_file2 = read_file_lines_from_zip(src_zip_path, file_ref).split("\n")
                code += (
                    "\n\nfile: " + file_ref + "\n" +
                    self.extract_function_code(code_file2, new_function)
                )

        return code, functions

    def process_issue_type(
        self,
        issue_type: str,
        issues_of_type: List[Dict[str, str]],
        llm_analyzer: LLMAnalyzer
    ) -> None:
        """
        Processes all issues of a single type. Builds file/folder paths, runs
        analysis, calls the LLM, and saves results.

        Algorithm (per issue):
            - Normalize paths (Windows: ':'→'_', '\'→'/'; Linux: strip leading '/')
            - Find function; extract snippet [start_offset-1:end_offset]
            - Replace bracket refs; append extra functions if needed
            - Build prompt; save raw/final; run LLM
            - Classify by '1337'/'1007'/else; log stats

        Args:
            issue_type (str): The name of the issue type.
            issues_of_type (List[Dict[str, str]]): All issues belonging to that type.
            llm_analyzer (LLMAnalyzer): The LLM analyzer instance to use for queries.
        
        Raises:
            CodeQLError: If database files cannot be read (YAML, ZIP, CSV, etc.).
            VulnhallaError: If result files cannot be written.
            LLMError: If LLM analysis fails.
        """
        results_folder = Path("output/results") / self.lang / issue_type.replace(" ", "_").replace("/", "-")
        self.ensure_directories_exist([str(results_folder)])

        issue_id = 0
        real_issues = []
        false_issues = []
        more_data = []

        logger.info("Found %d issues of type %s", len(issues_of_type), issue_type)
        logger.info("")
        for issue in issues_of_type:
            issue_id += 1
            self.db_path = issue["db_path"]
            db_path_obj = Path(self.db_path)
            db_yml_path = db_path_obj / "codeql-database.yml"
            db_yml = read_yml(str(db_yml_path))
            self.code_path = db_yml["sourceLocationPrefix"]

            # Path normalization for cross-platform compatibility:
            # Windows paths contain ":" (e.g., "C:\path\to\code") which conflicts with
            # ZIP archive path handling. We normalize by:
            # - Replacing ":" with "_" (e.g., "C_" instead of "C:")
            # - Converting backslashes to forward slashes
            # Linux paths are absolute (start with "/") which we remove for ZIP access
            if ":" in self.code_path:
                # Windows path: normalize drive letter and separators
                self.code_path = self.code_path.replace(":", "_").replace("\\", "/")
            else:
                # Linux path: remove leading slash
                self.code_path = self.code_path[1:]

            function_tree_file = str(db_path_obj / "FunctionTree.csv")
            src_zip_path = str(db_path_obj / "src.zip")

            full_file_path = self.code_path + issue["file"]
            code_file_contents = read_file_lines_from_zip(src_zip_path, full_file_path).split("\n")

            current_function = self.find_function_by_line(
                function_tree_file,
                "/" + self.code_path + issue["file"],
                int(issue["start_line"])
            )
            if not current_function:
                logger.warning("issue %s: Can't find the function or function is too big!", issue_id)
                continue

            snippet = code_file_contents[int(issue["start_line"]) - 1][
                int(issue["start_offset"]) - 1:int(issue["end_offset"])
            ]

            code = (
                "file: " + self.code_path + issue["file"] + "\n" +
                self.extract_function_code(code_file_contents, current_function)
            )

            # Replace bracket refs in message
            bracket_pattern = r'\[\["(.*?)"\|"((?:relative://|file://))?(/.*?):(\d+):(\d+):\d+:(\d+)"\]\]'
            transform_func = self.create_bracket_reference_replacer(self.db_path, self.code_path)
            message = re.sub(bracket_pattern, transform_func, issue["message"])

            # Find extra refs for context expansion
            extra_lines_pattern = r'\[\[".*?"\|"((?:relative://|file://)?)(/.*?):(\d+):\d+:\d+:\d+"\]\]'
            extra_lines = re.findall(extra_lines_pattern, issue["message"])
            functions = [current_function]

            if extra_lines:
                code, functions = self.append_extra_functions(
                    extra_lines, function_tree_file, src_zip_path, code, current_function
                )

            prompt = self.build_prompt_by_template(issue, message, snippet, code)

            # Save raw input to the LLM
            self.save_raw_input_data(prompt, function_tree_file, current_function, results_folder, issue_id)

            # Send to LLM
            messages, content = llm_analyzer.run_llm_security_analysis(
                prompt,
                function_tree_file,
                current_function,
                functions,
                self.db_path
            )
            gpt_result = self.format_llm_messages(messages)
            final_file = Path(results_folder) / f"{issue_id}_final.json"
            write_file_ascii(str(final_file), gpt_result)

            # Check status code in LLM content
            status = self.determine_issue_status(content)
            if status == "true":
                real_issues.append(issue_id)
                status = "True Positive"
            elif status == "false":
                false_issues.append(issue_id)
                status = "False Positive"
            else:
                more_data.append(issue_id)
                status = "LLM needs More Data"

            # Log issue status
            logger.info("Issue ID: %s, LLM decision: → %s", issue_id, status)

        logger.info("")
        logger.info("Issue type: %s", issue_type)
        logger.info("Total issues: %d", len(issues_of_type))
        logger.info("True Positive: %d", len(real_issues))
        logger.info("False Positive: %d", len(false_issues))
        logger.info("LLM needs More Data: %d", len(more_data))
        logger.info("")

    def run(self) -> None:
        """
        Main analysis routine:
        1. Initializes the LLM.
        2. Finds all CodeQL DBs for the given language.
        3. Parses each DB's issues.csv, aggregates them by issue type.
        4. Asks the LLM for each issue's snippet context, saving final results
           in various directory structures.
        
        Raises:
            CodeQLError: If database files cannot be accessed or read.
            VulnhallaError: If directory creation or file writing fails.
            LLMError: If LLM initialization or analysis fails.
        """
        # Validate configuration before starting
        if self.config is None:
            validate_and_exit_on_error()
        
        llm_analyzer = LLMAnalyzer()
        llm_analyzer.init_llm_client(config=self.config)

        dbs_folder = str(Path("output/databases") / self.lang)

        # Gather issues from all DBs
        issues_statistics = self.collect_issues_from_databases(dbs_folder)

        total_issues = 0
        for issue_type in issues_statistics:
            total_issues += len(issues_statistics[issue_type])
        logger.info("Total issues found: %d", total_issues)
        logger.info("")

        # Process all issues, type by type
        for issue_type in issues_statistics.keys():
            self.process_issue_type(issue_type, issues_statistics[issue_type], llm_analyzer)

if __name__ == '__main__':
    # Initialize logging
    from src.utils.logger import setup_logging
    setup_logging()
    
    # Loads configuration from .env file
    # Or use: analyzer = IssueAnalyzer(lang="c", config={...})
    analyzer = IssueAnalyzer(lang="c")
    analyzer.run()

