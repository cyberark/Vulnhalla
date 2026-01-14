#!/usr/bin/env python3
"""
Fetch repositories and their CodeQL databases from GitHub.

Downloads a specific repository's CodeQL database.

Example CLI usage:
    python fetch_repos.py myOrgName/myRepoName
"""

from pathlib import Path
import sys
import json
import time
import zipfile
import requests
from typing import Any, Dict, List
from pySmartDL import SmartDL

from src.utils.common_functions import read_file, write_file_text, get_all_dbs
from src.utils.config import get_github_token
from src.utils.logger import get_logger
from src.utils.exceptions import CodeQLError, CodeQLConfigError

logger = get_logger(__name__)

LANG: str = "c"


def fetch_repos_from_github_api(url: str) -> Dict[str, Any]:
    """
    Make a GET request to GitHub's API with optional rate-limit handling.

    Args:
        url (str): The URL to be requested.

    Returns:
        Dict[str, Any]: JSON response from the GitHub API as a Python dict.
    
    Raises:
        CodeQLConfigError: On 4xx client errors (invalid token, permissions, etc.).
        CodeQLError: On server errors or other unexpected errors.
    """
    headers: Dict[str, str] = {}
    token = get_github_token()
    if token:
        headers["Authorization"] = f'token {token}'

    try:
        response = requests.get(url, headers=headers)
        # Check for HTTP errors
        try:
            response.raise_for_status()
        except requests.HTTPError as http_err:
            status = response.status_code
            # Request/config problem
            if 400 <= status < 500:
                error_msg = f"GitHub API returned {status} for {url}"
                if status == 401:
                    error_msg += ". Please check your GitHub token - it may be invalid or expired."
                elif status == 403:
                    error_msg += ". Please check your GitHub token permissions."
                else:
                    error_msg += ". Please check your request parameters."
                raise CodeQLConfigError(error_msg) from http_err
            # CodeQLError
            raise CodeQLError(f"GitHub API returned {status} for {url}") from http_err
        
        remaining_requests = response.headers.get("X-RateLimit-Remaining")
        reset_time = response.headers.get("X-RateLimit-Reset")

        # Approaching the rate limit, wait until reset
        if remaining_requests and reset_time and int(remaining_requests) < 7:
            logger.warning("Remaining requests: %s", remaining_requests)
            logger.warning(
                "Rate limit resets at: %s",
                time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(reset_time)))
            )
            wait_time = int(reset_time) - int(time.time())
            if wait_time > 0:
                logger.warning("Waiting for %.2f minutes until the rate limit resets.", wait_time / 60)
                time.sleep(wait_time + 1)
            if int(remaining_requests) == 0:
                return fetch_repos_from_github_api(url)

        return response.json()
    
    except CodeQLConfigError:
        raise
    except requests.RequestException as e:
        # Network errors
        raise CodeQLError(f"Network error while accessing GitHub API: {e}") from e
    except (ValueError, json.JSONDecodeError) as e:
        # Invalid JSON response
        raise CodeQLError(f"Invalid response from GitHub API: {e}") from e


def parse_github_search_result(url: str) -> List[Dict[str, Any]]:
    """
    Retrieve repository information from GitHub search results.

    Args:
        url (str): The GitHub API search endpoint URL.

    Returns:
        List[Dict[str, Any]]: A list of repository metadata dictionaries.
    
    Raises:
        CodeQLConfigError: If GitHub API returns 4xx (invalid token, permissions, etc.).
        CodeQLError: If GitHub API returns 5xx or other errors.
    """
    page = fetch_repos_from_github_api(url)
    repos = []
    for item in page.get("items", []):
        repos.append(
            {
                "html_url": item["html_url"],
                "repo_name": item["full_name"],
                "forks": item["forks"],
                "stars": item["watchers"],
            }
        )
    return repos


def validate_rate_limit(threads: int) -> None:
    """
    Check the GitHub rate limit and, if necessary, pause execution
    until the rate limit resets.

    Args:
        threads (int): Number of download threads planned; used to estimate
            how many requests might be made.
    
    Raises:
        CodeQLError: If network error occurs while checking rate limit.
    """
    try:
        rate_limit = requests.get("https://api.github.com/rate_limit").json()
    except requests.RequestException as e:
        raise CodeQLError(f"Network error while checking GitHub rate limit: {e}") from e
    except (ValueError, json.JSONDecodeError) as e:
        raise CodeQLError(f"Invalid response from GitHub rate limit API: {e}") from e
    
    remaining_requests = rate_limit["resources"]["core"]["remaining"]
    reset_time = rate_limit["resources"]["core"]["reset"]
    if int(remaining_requests) < threads + 3:
        logger.warning("Remaining requests: %s", remaining_requests)
        logger.warning(
            "Rate limit resets at: %s",
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(reset_time)))
        )
        wait_time = int(reset_time) - int(time.time()) + 120
        if wait_time > 0:
            logger.warning("Waiting for %.2f minutes until the rate limit resets.", wait_time / 60)
            time.sleep(wait_time)


def custom_download(url: str, local_filename: str, max_attempts: int = 5, attempt: int = 1, force_full_download: bool = False) -> None:
    """
    Download a file from GitHub (with optional resume and retry logic).

    Args:
        url: Direct download URL.
        local_filename: Destination path on disk.
        max_attempts: Maximum number of retry attempts.
        attempt: Current attempt (used internally).
        force_full_download: If True, download from beginning even if file exists (skip Range header).
    
    Raises:
        CodeQLError: If download fails after all retry attempts, or on non-retryable errors.
        CodeQLConfigError: On 4xx client errors that indicate configuration issues (e.g., invalid token).
    """
    # Check if file exists and validate it
    local_file_path = Path(local_filename)
    file_size = 0
    if local_file_path.exists() and not force_full_download:
        file_size = local_file_path.stat().st_size
        
        # Validate if existing file is a valid ZIP
        if file_size > 0:
            try:
                with zipfile.ZipFile(str(local_file_path), "r") as zip_ref:
                    zip_ref.testzip()  # Test if ZIP is valid
            except (zipfile.BadZipFile, zipfile.LargeZipFile):
                # File is corrupted, delete it and start again
                logger.warning("Existing file %s is corrupted. Deleting and starting fresh.", local_filename)
                try:
                    local_file_path.unlink()
                    file_size = 0
                except (PermissionError, OSError) as e:
                    raise CodeQLError(f"Failed to delete corrupted file {local_filename}: {e}") from e

    # Set up headers
    headers = {"Accept": "application/zip"}
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"
    if file_size > 0 and not force_full_download:
        headers["Range"] = f"bytes={file_size}-"

    start_time = time.time()

    try:
        with requests.get(url, headers=headers, stream=True, timeout=300) as response:
            # Check for 416 Range Not Satisfiable error
            status = response.status_code
            if status == 416:
                logger.warning("Received 416 error (Range Not Satisfiable) - file may have changed on server")
                logger.info("Will retry download from beginning (full download)")
                
                # Retry from beginning with force_full_download=True to skip Range header
                if attempt < max_attempts:
                    backoff_time = min(2 ** attempt, 60)
                    logger.info("Retrying download from beginning in %.1f seconds...", backoff_time)
                    time.sleep(backoff_time)
                    return custom_download(url, local_filename, max_attempts, attempt + 1, force_full_download=True)
                else:
                    raise CodeQLError(
                        f"Failed to download {url} after {max_attempts} attempts. "
                        "416 error suggests file on server may have changed."
                    )
            
            # HTTP errors handling
            try:
                response.raise_for_status()
            except requests.HTTPError as http_err:
                status = http_err.response.status_code if http_err.response else None
                # Request/config problem 
                if status is not None and 400 <= status < 500:
                    raise CodeQLConfigError(
                        f"GitHub returned {status} while downloading {url}. "
                        "Please check your GitHub token / permissions."
                    ) from http_err
                # Handle level below
                raise

            total_size = int(response.headers.get("content-length", 0)) + file_size
            logger.debug("File size: %d bytes (%.2f MB)", total_size, total_size / 1_000_000)

            mode = "ab" if (file_size > 0 and not force_full_download) else "wb"
            with local_file_path.open(mode) as file:
                downloaded_size = file_size
                last_update = time.time()

                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue

                    file.write(chunk)
                    downloaded_size += len(chunk)

                    current_time = time.time()
                    if current_time - last_update >= 0.1 or downloaded_size == total_size:
                        progress = (downloaded_size / total_size) * 100 if total_size > 0 else 0
                        elapsed = current_time - start_time
                        speed = downloaded_size / elapsed if elapsed > 0 else 0

                        downloaded_mb = downloaded_size / 1_000_000
                        total_mb = total_size / 1_000_000
                        speed_mb = speed / 1_000_000

                        bar_length = 20
                        filled = int(bar_length * progress / 100)
                        bar = "█" * filled + "░" * (bar_length - filled)

                        print(
                            f"\rDownloading: [{bar}] {progress:.1f}% | "
                            f"{downloaded_mb:.2f}/{total_mb:.2f} MB | {speed_mb:.2f} MB/s",
                            end="",
                            flush=True,
                        )
                        last_update = current_time

                print()

        time_taken = time.time() - start_time
        logger.debug("File downloaded successfully as %s", local_filename)
        logger.info("Download completed in %.2f minutes.", time_taken / 60)

    except requests.RequestException as e:
        # Network errors
        if attempt >= max_attempts:
            raise CodeQLError(f"Failed to download {url} after {max_attempts} attempts") from e

        backoff_time = min(2 ** attempt, 60)
        logger.warning(
            "Network error during download (attempt %d/%d): %s. Retrying in %.1f seconds...",
            attempt,
            max_attempts,
            e,
            backoff_time,
        )
        time.sleep(backoff_time)
        return custom_download(
            url,
            local_filename,
            max_attempts=max_attempts,
            attempt=attempt + 1,
        )

    except (IOError, OSError) as e:
        # Disk write errors
        raise CodeQLError(f"Failed to write downloaded content to {local_filename}: {e}") from e
    except CodeQLConfigError:
        raise
    except Exception as e:
        raise CodeQLError(f"Unexpected error during download of {url}: {e}") from e


def multi_thread_db_download(url: str, repo_name: str, threads: int = 2) -> str:
    """
    Download a CodeQL DB .zip file with multiple threads (if no token),
    or via custom_download (if using a token).

    Args:
        url (str): The direct download URL.
        repo_name (str): The repository name used for constructing the .zip path.
        threads (int, optional): Number of threads for parallel download. Defaults to 2.

    Returns:
        str: The local file system path to the downloaded .zip.
    
    Raises:
        CodeQLError: If directory creation fails or download fails.
        CodeQLConfigError: On 4xx client errors during download (if using token).
    """
    dest_dir = Path("output/zip_dbs") / LANG
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise CodeQLError(f"Permission denied creating download directory: {dest_dir}") from e
    except OSError as e:
        raise CodeQLError(f"OS error creating download directory: {dest_dir}") from e
    dest = dest_dir / f"{repo_name}.zip"

    request_args = {"headers": {"Accept": "application/zip"}}

    token = get_github_token()
    if token:
        custom_download(url, str(dest))
        return str(dest)

    validate_rate_limit(threads)
    downloader = SmartDL(
        url, str(dest), request_args=request_args, threads=threads, progress_bar=False, verify=True
    )
    downloader.start()
    return downloader.get_dest()


def unzip_file(zip_path: str, extract_to: str) -> None:
    """
    Unzip the specified .zip file into the target directory.

    Args:
        zip_path (str): The path to the .zip file.
        extract_to (str): Directory path where files will be extracted.
    
    Raises:
        CodeQLError: If ZIP file is invalid, corrupted, or extraction fails.
    """
    extract_to_path = Path(extract_to)
    try:
        extract_to_path.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise CodeQLError(f"Permission denied creating extraction directory: {extract_to}") from e
    except OSError as e:
        raise CodeQLError(f"OS error creating extraction directory: {extract_to}") from e
    
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(str(extract_to_path))
    except zipfile.BadZipFile as e:
        raise CodeQLError(f"Invalid or corrupted ZIP file: {zip_path}") from e
    except zipfile.LargeZipFile as e:
        raise CodeQLError(f"ZIP file too large to extract: {zip_path}") from e
    except PermissionError as e:
        raise CodeQLError(f"Permission denied extracting ZIP file: {zip_path}") from e
    except OSError as e:
        raise CodeQLError(f"OS error extracting ZIP file: {zip_path}") from e


def filter_repos_by_db_and_lang(repos: List[Dict[str, Any]], lang: str) -> List[Dict[str, Any]]:
    """
    For each repo, fetch available CodeQL databases from the GitHub API.

    Args:
        repos (List[Dict[str, Any]]): A list of repository info dictionaries.
        lang (str): The language of interest (e.g., "c", "cpp").

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing DB info
            for the matching language.
    
    Raises:
        CodeQLConfigError: If GitHub API returns 4xx (invalid token, permissions, etc.).
        CodeQLError: If GitHub API returns 5xx or other errors.
    """
    repos_db = []
    # If language is 'c', the GH DB often has it as 'cpp'
    gh_lang = "cpp" if lang == "c" else lang

    for repo in repos:
        try:
            db_info = fetch_repos_from_github_api(
                f"https://api.github.com/repos/{repo['repo_name']}/code-scanning/codeql/databases"
            )
        except (CodeQLConfigError, CodeQLError):
            raise
        except Exception as e:
            raise CodeQLError(f"Unexpected error while fetching databases for {repo['repo_name']}: {e}") from e
        
        # db_info might be a list or empty list
        if not isinstance(db_info, list):
            # Check if it's an error response from GitHub API
            if isinstance(db_info, dict):
                error_msg = db_info.get("message") or db_info.get("error", "Unknown error")
                if "message" in db_info or "error" in db_info:
                    raise CodeQLError(
                        f"GitHub API error for {repo['repo_name']}: {error_msg}"
                    )
            # If it's not a dict with error, log warning and continue
            logger.warning(
                "Unexpected response format for %s databases: %s (type: %s)",
                repo['repo_name'],
                db_info,
                type(db_info).__name__
            )
            continue
            
        for db in db_info:
            if "language" in db and db["language"] == gh_lang:
                # Validate required fields exist
                if "url" not in db:
                    logger.warning("Database entry missing 'url' field for %s, skipping", repo['repo_name'])
                    continue
                repos_db.append(
                    {
                        "repo_name": repo["repo_name"],
                        "html_url": repo["html_url"],
                        "content_type": db.get("content_type", "application/zip"),
                        "size": db.get("size", 0),
                        "db_url": db["url"],
                        "forks": repo["forks"],
                        "stars": repo["stars"],
                    }
                )
    return repos_db


def search_top_matching_repos(max_repos: int, lang: str) -> List[Dict[str, Any]]:
    """
    Gather a list of repositories (sorted by stars) and retrieve
    their CodeQL DB info for the specified language.

    Args:
        max_repos (int): Number of repositories to stop after collecting.
        lang (str): The programming language for which to search
            (e.g., "c" or "cpp").

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing each repo's DB info.
    
    Raises:
        CodeQLConfigError: If GitHub API returns 4xx (invalid token, permissions, etc.).
        CodeQLError: If GitHub API returns 5xx or other errors.
    """
    repos_db: List[Dict[str, Any]] = []
    curr_page = 1

    while len(repos_db) < max_repos:
        # Search for top-starred repos by language
        search_url = (
            f"https://api.github.com/search/repositories"
            f"?q=language:{lang}&sort=stars&order=desc&page={curr_page}"
        )
        all_repos = parse_github_search_result(search_url)

        db_in_page = filter_repos_by_db_and_lang(all_repos, lang)
        repos_db += db_in_page

        curr_page += 1

    return repos_db[:max_repos]


def download_and_extract_db(repo: Dict[str, Any], threads: int, extract_folder: str) -> str:
    """
    Handle the download and extraction of a single repository's CodeQL DB.

    Args:
        repo (Dict[str, Any]): The repository DB info dictionary.
        threads (int): Number of threads for multi-threaded download.
        extract_folder (str): Where to extract the DB files.
    
    Returns:
        str: Path to the directory containing downloaded database.
        
    Raises:
        CodeQLError: If download, extraction, or folder rename fails.
        CodeQLConfigError: On 4xx client errors during download (e.g., invalid token).
    """
    org_name, repo_name = repo["repo_name"].split("/")
    logger.info("Downloading repo %s/%s", org_name, repo_name)
    zip_path = multi_thread_db_download(repo["db_url"], repo_name, threads)
    db_path = Path(extract_folder) / repo_name
    unzip_file(zip_path, str(db_path))
    time.sleep(1)  # Let file system sync

    # Rename the extracted folder if needed (with retry for Windows file locking)
    source_path = None
    target_path = db_path / repo_name
    codeql_db_path = db_path / "codeql_db"
    lang_path = db_path / LANG

    if codeql_db_path.exists():
        source_path = codeql_db_path
    elif lang_path.exists():
        source_path = lang_path

    if source_path and not target_path.exists():
        # Retry rename with delays (Windows may lock files temporarily)
        for attempt in range(3):
            try:
                time.sleep(0.5 * (attempt + 1))  # Increasing delay: 0.5s, 1s, 1.5s
                source_path.rename(target_path)
                break
            except (PermissionError, OSError) as e:
                if attempt == 2:
                    error_msg = (
                        f"Could not rename {source_path} to {target_path}. "
                        "The folder may be locked. Please close any IDEs, File Explorer, "
                        "or antivirus that might be accessing this folder, then run the script again."
                    )
                    raise CodeQLError(error_msg) from e

    if target_path.exists():
        return str(target_path)
    return str(db_path)


def download_db_by_name(repo_name: str, lang: str, threads: int) -> str:
    """
    Download the CodeQL database for a single repository.

    Args:
        repo_name (str): The repository in 'org/repo' format.
        lang (str): The language to pass to GH DB detection (e.g., 'c').
        threads (int): Number of threads to use for download.
    
    Returns:
        str: Path to the directory containing downloaded database.

    Raises:
        CodeQLConfigError: If GitHub API returns 4xx (invalid token, permissions, etc.) 
            during database lookup or download.
        CodeQLError: If GitHub API returns 5xx, download fails, or other errors occur.
    
    Note:
        If no database is found for the specified language, a warning is logged
        and the function returns without raising an error.
    """
    # Build a minimal repo dict to be processed
    repo = {"stars": 0, "forks": 0, "repo_name": repo_name, "html_url": ""}
    repo_db = filter_repos_by_db_and_lang([repo], lang)
    if not repo_db:
        logger.warning("No %s DB found for %s", lang, repo_name)
        return []
    return download_and_extract_db(repo_db[0], threads, str(Path("output/databases") / lang))


def fetch_codeql_dbs(
    lang: str = "c",
    threads: int = 4,
    repo_name: str = None
) -> str:
    """
    Fetch and download CodeQL databases for GitHub repositories.

    Args:
        lang (str, optional): The programming language. Defaults to "c".
        threads (int, optional): Number of threads for multi-threaded download. Defaults to 4.
        repo_name (str, optional): Downloads this repository's DB.
            Format: "org/repo". Defaults to None.
    
    Returns:
        str: Path to the directory containing downloaded database.
    
    Raises:
        CodeQLError: If directory creation, download, or extraction fails.
        CodeQLConfigError: On 4xx client errors (invalid token, permissions, etc.).
    """
    # Ensure needed directories exist
    db_folder_path = Path("output/databases") / lang
    try:
        db_folder_path.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise CodeQLError(f"Permission denied creating database directory: {db_folder_path}") from e
    except OSError as e:
        raise CodeQLError(f"OS error creating database directory: {db_folder_path}") from e

    zip_folder_path = Path("output/zip_dbs") / lang
    try:
        zip_folder_path.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise CodeQLError(f"Permission denied creating ZIP directory: {zip_folder_path}") from e
    except OSError as e:
        raise CodeQLError(f"OS error creating ZIP directory: {zip_folder_path}") from e
    
    return download_db_by_name(repo_name, lang, threads)


def main_cli() -> None:
    """
    CLI entry point. Downloads a specific repository's CodeQL database.
    Requires an argument 'org/repo' to specify which repository to fetch.
    """
    logger.info("Current lang: %s", LANG)

    if len(sys.argv) == 1:
        raise CodeQLError("No arguments provided")
    else:
        # If a single arg is provided, assume it's an 'org/repo' to fetch
        if "/" in sys.argv[1]:
            fetch_codeql_dbs(lang=LANG, threads=4, repo_name=sys.argv[1])
        else:
            logger.error("Usage:\n  python fetch_repos.py\n  or\n  python fetch_repos.py orgName/repoName")


if __name__ == "__main__":
    main_cli()
