#!/usr/bin/env python3
"""
Compile and run CodeQL queries on CodeQL databases for a specific language.

Requires that CodeQL is installed or available under the CODEQL path.
By default, it compiles all .ql files under 'data/queries/<LANG>/tools' and
'data/queries/<LANG>/issues', then runs them on each CodeQL database located
in 'output/databases/<LANG>'.

Example:
    python src/codeql/run_codeql_queries.py
"""

import subprocess
from pathlib import Path
from typing import List, Optional

# Make sure your common_functions module is in your PYTHONPATH or same folder
from src.utils.common_functions import get_all_dbs
from src.utils.config import get_codeql_path
from src.utils.logger import get_logger
from src.utils.exceptions import CodeQLError, CodeQLConfigError, CodeQLExecutionError

logger = get_logger(__name__)


# Default locations/values
DEFAULT_CODEQL = get_codeql_path()
DEFAULT_LANG = "c"  # Mapped to data/queries/cpp for some tasks


def pre_compile_ql(file_name: str, threads: int, codeql_bin: str) -> None:
    """
    Pre-compile a single .ql file using CodeQL.

    Args:
        file_name (str): The path to the .ql query file.
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query compilation fails.
    """
    qlx_path = Path(str(file_name) + "x")
    if not qlx_path.exists():
        try:
            subprocess.run(
                [
                    codeql_bin,
                    "query",
                    "compile",
                    file_name,
                    f'--threads={threads}',
                    "--precompile"
                ],
                check=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except FileNotFoundError as e:
            raise CodeQLConfigError(
                f"CodeQL executable not found: {codeql_bin}. "
                "Please check your CODEQL_PATH configuration."
            ) from e
        except subprocess.CalledProcessError as e:
            raise CodeQLExecutionError(
                f"Failed to compile query {file_name}: CodeQL returned exit code {e.returncode}"
            ) from e


def compile_all_queries(queries_folder: str, threads: int, codeql_bin: str) -> None:
    """
    Recursively pre-compile all .ql files in a folder.

    Args:
        queries_folder (str): Directory containing .ql files (and possibly subdirectories).
        threads (int): Number of threads to use during compilation.
        codeql_bin (str): Full path to the 'codeql' executable.
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query compilation fails.
    """
    queries_folder_path = Path(queries_folder)
    for file_path in queries_folder_path.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() == ".ql":
            pre_compile_ql(str(file_path), threads, codeql_bin)


def run_one_query(
    query_file: str,
    curr_db: str,
    output_bqrs: str,
    output_csv: str,
    threads: int,
    codeql_bin: str
) -> None:
    """
    Execute a single CodeQL query on a specific database and export the results.

    Args:
        query_file (str): The path to the .ql file to run.
        curr_db (str): The path to the CodeQL database on which to run queries.
        output_bqrs (str): Where to write the intermediate BQRS output.
        output_csv (str): Where to write the CSV representation of the results.
        threads (int): Number of threads to use during query execution.
        codeql_bin (str): Full path to the 'codeql' executable.
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query execution or BQRS decoding fails.
    """
    # Run the query
    try:
        subprocess.run(
            [
                codeql_bin, "query", "run", query_file,
                f'--database={curr_db}',
                f'--output={output_bqrs}',
                f'--threads={threads}'
            ],
            check=True,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except FileNotFoundError as e:
        raise CodeQLConfigError(
            f"CodeQL executable not found: {codeql_bin}. "
            "Please check your CODEQL_PATH configuration."
        ) from e
    except subprocess.CalledProcessError as e:
        raise CodeQLExecutionError(
            f"Failed to run query {query_file} on database {curr_db}: "
            f"CodeQL returned exit code {e.returncode}"
        ) from e

    # Decode BQRS to CSV
    try:
        subprocess.run(
            [
                codeql_bin, "bqrs", "decode", output_bqrs,
                '--format=csv', f'--output={output_csv}'
            ],
            check=True,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError as e:
        raise CodeQLExecutionError(
            f"Failed to decode BQRS file {output_bqrs} to CSV: "
            f"CodeQL returned exit code {e.returncode}"
        ) from e


def run_queries_on_db(
    curr_db: str,
    tools_folder: str,
    queries_folder: str,
    threads: int,
    codeql_bin: str,
    timeout: int = 300
) -> None:
    """
    Execute all tool queries in 'tools_folder' individually on a given database,
    then run 'database analyze' with all queries in 'queries_folder'.

    Args:
        curr_db (str): The path to the CodeQL database.
        tools_folder (str): Folder containing individual .ql files to run.
        queries_folder (str): Folder containing .ql queries for database analysis.
        threads (int): Number of threads to use during query execution.
        codeql_bin (str): Full path to the 'codeql' executable.
        timeout (int, optional): Timeout in seconds for the 'database analyze' command.
            Defaults to 300.
    
    Raises:
        CodeQLConfigError: If CodeQL executable not found.
        CodeQLExecutionError: If query execution or database analysis fails.
    """
    # 1) Run each .ql in tools_folder individually
    tools_folder_path = Path(tools_folder)
    if tools_folder_path.is_dir():
        for file_path in tools_folder_path.iterdir():
            if file_path.is_file() and file_path.suffix.lower() == ".ql":
                file_stem = file_path.stem
                run_one_query(
                    str(file_path),
                    curr_db,
                    str(Path(curr_db) / f"{file_stem}.bqrs"),
                    str(Path(curr_db) / f"{file_stem}.csv"),
                    threads,
                    codeql_bin
                )
    else:
        logger.warning("Tools folder '%s' not found. Skipping individual queries.", tools_folder)

    # 2) Run the entire queries folder in one go using database analyze
    queries_folder_path = Path(queries_folder)
    if queries_folder_path.is_dir():
        try:
            subprocess.run(
                [
                    codeql_bin,
                    "database",
                    "analyze",
                    curr_db,
                    queries_folder,
                    f'--timeout={timeout}',
                    '--format=csv',
                    f'--output={str(Path(curr_db) / "issues.csv")}',
                    f'--threads={threads}'
                ],
                check=True,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except FileNotFoundError as e:
            raise CodeQLConfigError(
                f"CodeQL executable not found: {codeql_bin}. "
                "Please check your CODEQL_PATH configuration."
            ) from e
        except subprocess.CalledProcessError as e:
            raise CodeQLExecutionError(
                f"Failed to analyze database {curr_db} with queries from {queries_folder}: "
                f"CodeQL returned exit code {e.returncode}"
            ) from e
    else:
        logger.warning("Queries folder '%s' not found. Skipping database analysis.", queries_folder)


def compile_and_run_codeql_queries(
    codeql_bin: str = DEFAULT_CODEQL,
    lang: str = DEFAULT_LANG,
    threads: int = 16,
    timeout: int = 300,
    *,
    dbs_dir: str
) -> None:
    """
    Compile and run CodeQL queries on CodeQL databases for a specific language.

    1. Pre-compile all .ql files in the tools and queries folders.
    2. Enumerate all CodeQL DBs for the given language.
    3. Run each DB against both the 'tools' and 'issues' queries folders.

    Args:
        codeql_bin (str, optional): Full path to the 'codeql' executable. Defaults to DEFAULT_CODEQL.
        lang (str, optional): Language code. Defaults to 'c' (which maps to data/queries/cpp).
        threads (int, optional): Number of threads for compilation/execution. Defaults to 16.
        timeout (int, optional): Timeout in seconds for database analysis. Defaults to 300.
        dbs_dir (str): The path to the CodeQL databases.
        
    Raises:
        CodeQLConfigError: If CodeQL executable not found (from compilation or query execution).
        CodeQLExecutionError: If query compilation or execution fails.
    """
    # Setup paths
    queries_subfolder = "cpp" if lang == "c" else lang
    queries_folder = str(Path("data/queries") / queries_subfolder / "issues")
    tools_folder = str(Path("data/queries") / queries_subfolder / "tools")

    # Step 1: Pre-compile all queries
    compile_all_queries(tools_folder, threads, codeql_bin)
    compile_all_queries(queries_folder, threads, codeql_bin)

    # Step 2: Run queries
    # Validate database directory exists and is accessible
    dbs_folder_path = Path(dbs_dir)
    if not dbs_folder_path.exists():
        logger.warning("Database folder '%s' does not exist. No databases to process.", dbs_dir)
        logger.warning("Make sure databases were downloaded and extracted successfully.")
        return
    
    if not dbs_folder_path.is_dir():
        logger.warning("Database path '%s' is not a directory. No databases to process.", dbs_dir)
        return
    
    # List what's in the folder for debugging
    try:
        contents = list(dbs_folder_path.iterdir())
        if len(contents) == 0:
            logger.warning("Database folder '%s' is empty. No databases to process.", dbs_dir)
            return
        logger.debug("Found %d item(s) in database folder: %s", len(contents), [str(c) for c in contents])
    except OSError as e:
        logger.warning("Cannot access database folder '%s': %s. No databases to process.", dbs_dir, e)
        return
        
    actual_dbs = get_all_dbs(dbs_dir)

    if len(actual_dbs) == 0:
        logger.warning("No valid databases found in '%s'. Expected structure: <dbs_folder>/<repo_name>/<db_name>/codeql-database.yml", dbs_dir)
        logger.warning("Make sure databases were downloaded and extracted successfully.")
        return

    for curr_db in actual_dbs:
        # Check if database folder is empty
        curr_db_path = Path(curr_db)
        if curr_db_path.is_dir():
            try:
                if len(list(curr_db_path.iterdir())) == 0:
                    logger.warning("Database folder '%s' is empty. Skipping queries.", curr_db)
                    continue
            except OSError:
                logger.warning("Cannot access database folder '%s'. Skipping.", curr_db)
                continue
        
        # If issues.csv was not generated yet, or FunctionTree.csv missing, run
        if (not (curr_db_path / "FunctionTree.csv").exists() or
                not (curr_db_path / "issues.csv").exists()):
            logger.info("Processing DB: %s", curr_db)
            run_queries_on_db(
                curr_db,
                tools_folder,
                queries_folder,
                threads,
                codeql_bin,
                timeout
            )
        else:
            logger.info("Output files already exist for this DB, skipping...")

    logger.info("✅ done!")


def main_cli() -> None:
    """
    CLI entry point for running codeql queries with defaults.
    """
    compile_and_run_codeql_queries(
        codeql_bin=DEFAULT_CODEQL,
        lang=DEFAULT_LANG,
        threads=16,
        timeout=300,
        dbs_dir="output/databases/c"
    )


if __name__ == '__main__':
    # Initialize logging
    from src.utils.logger import setup_logging
    setup_logging()
    
    main_cli()
