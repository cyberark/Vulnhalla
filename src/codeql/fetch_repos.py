#!/usr/bin/env python3
"""
Fetch repositories and their CodeQL databases from GitHub.

Allows either:
  1) Bulk retrieval of repositories by language, or
  2) Downloading a specific repository's CodeQL database.

Example CLI usage:
    python fetch_repos.py
    # Or
    python fetch_repos.py myOrgName/myRepoName
"""

import os
import sys
import json
import time
import zipfile
import requests
from typing import Any, Dict, List
from pySmartDL import SmartDL

# Import from your local common_functions where needed
from src.utils.common_functions import read_file, write_file_text
from src.utils.config import get_github_token
from src.utils.logger import get_logger

logger = get_logger(__name__)

LANG: str = "c"


def fetch_repos_from_github_api(url: str) -> Dict[str, Any]:
    """
    Make a GET request to GitHub's API with optional rate-limit handling.

    Args:
        url (str): The URL to be requested.

    Returns:
        Dict[str, Any]: JSON response from the GitHub API as a Python dict.
    """
    headers: Dict[str, str] = {}
    token = get_github_token()
    if token:
        headers["Authorization"] = f'token {token}'

    response = requests.get(url, headers=headers)
    remaining_requests = response.headers.get("X-RateLimit-Remaining")
    reset_time = response.headers.get("X-RateLimit-Reset")

    # If approaching the rate limit, wait until reset
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


def parse_github_search_result(url: str) -> List[Dict[str, Any]]:
    """
    Retrieve repository information from GitHub search results.

    Args:
        url (str): The GitHub API search endpoint URL.

    Returns:
        List[Dict[str, Any]]: A list of repository metadata dictionaries.
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
    """
    rate_limit = requests.get("https://api.github.com/rate_limit").json()
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


def custom_download(url: str, local_filename: str) -> None:
    """
    Download a file from GitHub (with optional resume).

    Args:
        url (str): The direct download URL.
        local_filename (str): The path where the file will be saved.
    """
    file_size = 0
    if os.path.exists(local_filename):
        file_size = os.path.getsize(local_filename)

    headers = {"Accept": "application/zip"}
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"
    if file_size > 0:
        headers["Range"] = f"bytes={file_size}-"

    start_time = time.time()

    try:
        with requests.get(url, headers=headers, stream=True) as response:
            total_size = int(response.headers.get("content-length", 0)) + file_size
            logger.debug("File size: %d KB (%.2f MB)", total_size, total_size / 1_000_000)

            mode = "ab" if file_size > 0 else "wb"
            with open(local_filename, mode) as file:
                downloaded_size = file_size
                last_update = time.time()
                
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        file.write(chunk)
                        downloaded_size += len(chunk)
                        
                        # Update progress every 0.1 seconds
                        current_time = time.time()
                        if current_time - last_update >= 0.1 or downloaded_size == total_size:
                            progress = (downloaded_size / total_size) * 100 if total_size > 0 else 0
                            elapsed = current_time - start_time
                            speed = downloaded_size / elapsed if elapsed > 0 else 0
                            
                            # Format sizes
                            downloaded_mb = downloaded_size / 1_000_000
                            total_mb = total_size / 1_000_000
                            speed_mb = speed / 1_000_000
                            
                            # Create progress bar (20 characters)
                            bar_length = 20
                            filled = int(bar_length * progress / 100)
                            bar = "█" * filled + "░" * (bar_length - filled)
                            
                            # Print progress with bar, percentage, size, and speed
                            print(f"\rDownloading: [{bar}] {progress:.1f}% | {downloaded_mb:.2f}/{total_mb:.2f} MB | {speed_mb:.2f} MB/s", end="", flush=True)
                            last_update = current_time
                
                # Print newline after completion
                print()

        end_time = time.time()
        time_taken = end_time - start_time
        logger.info("File downloaded successfully as %s", local_filename)
        logger.info("Download completed in %.2f minutes.", time_taken / 60)
    except Exception as e:
        logger.warning("Download interrupted: %s. Retrying...", e)
        custom_download(url, local_filename)


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
    """
    dest_dir = os.path.join("output/zip_dbs", LANG)
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, repo_name + ".zip")

    request_args = {"headers": {"Accept": "application/zip"}}

    token = get_github_token()
    if token:
        custom_download(url, dest)
        return dest

    validate_rate_limit(threads)
    downloader = SmartDL(
        url, dest, request_args=request_args, threads=threads, progress_bar=False, verify=False
    )
    downloader.start()
    return downloader.get_dest()


def unzip_file(zip_path: str, extract_to: str) -> None:
    """
    Unzip the specified .zip file into the target directory.

    Args:
        zip_path (str): The path to the .zip file.
        extract_to (str): Directory path where files will be extracted.
    """
    os.makedirs(extract_to, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)


def filter_repos_by_db_and_lang(repos: List[Dict[str, Any]], lang: str) -> List[Dict[str, Any]]:
    """
    For each repo, fetch available CodeQL databases from the GitHub API.

    Args:
        repos (List[Dict[str, Any]]): A list of repository info dictionaries.
        lang (str): The language of interest (e.g., "c", "cpp").

    Returns:
        List[Dict[str, Any]]: A list of dictionaries containing DB info
            for the matching language.
    """
    repos_db = []
    # If language is 'c', the GH DB often has it as 'cpp'
    gh_lang = "cpp" if lang == "c" else lang

    for repo in repos:
        db_info = fetch_repos_from_github_api(
            f"https://api.github.com/repos/{repo['repo_name']}/code-scanning/codeql/databases"
        )
        for db in db_info:
            if "language" in db and db["language"] == gh_lang:
                repos_db.append(
                    {
                        "repo_name": repo["repo_name"],
                        "html_url": repo["html_url"],
                        "content_type": db["content_type"],
                        "size": db["size"],
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


def download_and_extract_db(repo: Dict[str, Any], threads: int, extract_folder: str) -> None:
    """
    Handle the download and extraction of a single repository's CodeQL DB.

    Args:
        repo (Dict[str, Any]): The repository DB info dictionary.
        threads (int): Number of threads for multi-threaded download.
        extract_folder (str): Where to extract the DB files.
    """
    org_name, repo_name = repo["repo_name"].split("/")
    logger.info("Downloading repo %s/%s", org_name, repo_name)
    zip_path = multi_thread_db_download(repo["db_url"], repo_name, threads)

    db_path = os.path.join(extract_folder, repo_name)
    unzip_file(zip_path, db_path)
    time.sleep(1)  # Let file system sync

    # Rename the extracted folder if needed (with retry for Windows file locking)
    source_path = None
    target_path = os.path.join(db_path, repo_name)
    
    if os.path.exists(os.path.join(db_path, "codeql_db")):
        source_path = os.path.join(db_path, "codeql_db")
    elif os.path.exists(os.path.join(db_path, LANG)):
        source_path = os.path.join(db_path, LANG)
    
    if source_path and not os.path.exists(target_path):
        # Retry rename with delays (Windows may lock files temporarily)
        for attempt in range(3):
            try:
                time.sleep(0.5 * (attempt + 1))  # Increasing delay: 0.5s, 1s, 1.5s
                os.rename(source_path, target_path)
                break
            except (PermissionError, OSError):
                if attempt == 2:  # Last attempt failed
                    logger.error("❌ Error: Could not rename %s", source_path)
                    logger.error("   The folder may be locked. Please close any IDEs, File Explorer, or antivirus")
                    logger.error("   that might be accessing this folder, then run the script again.")
                    sys.exit(1)

def download_db_by_name(repo_name: str, lang: str, threads: int) -> None:
    """
    Download the CodeQL database for a single repository.

    Args:
        repo_name (str): The repository in 'org/repo' format.
        lang (str): The language to pass to GH DB detection (e.g., 'c').
        threads (int): Number of threads to use for download.
    """
    # Build a minimal repo dict to be processed
    repo = {"stars": 0, "forks": 0, "repo_name": repo_name, "html_url": ""}
    repo_db = filter_repos_by_db_and_lang([repo], lang)
    if not repo_db:
        logger.warning("No %s DB found for %s", lang, repo_name)
        return
    download_and_extract_db(repo_db[0], threads, os.path.join("output/databases", lang))


def fetch_codeql_dbs(
    lang: str = "c",
    max_repos: int = 100,
    threads: int = 4,
    single_repo: str = None,
    backup_file: str = "repos_db.json"
) -> None:
    """
    Fetch and download CodeQL databases for GitHub repositories.

    If `single_repo` is provided (e.g. 'org/repo'), only that DB is downloaded.
    Otherwise, fetch the top repositories for `lang` and retrieve their DBs.

    Args:
        lang (str, optional): The programming language. Defaults to "c".
        max_repos (int, optional): Max number of top-starred repos to fetch. Defaults to 100.
        threads (int, optional): Number of threads for multi-threaded download. Defaults to 4.
        single_repo (str, optional): If provided, downloads only this repo's DB.
            Format: "org/repo". Defaults to None.
        backup_file (str, optional): Path to the JSON file used to store repo data
            between downloads. Defaults to "repos_db.json".
    """
    # Ensure needed directories exist
    db_folder = os.path.join("output/databases", lang)
    os.makedirs(db_folder, exist_ok=True)
    zip_folder = os.path.join("output/zip_dbs", lang)
    os.makedirs(zip_folder, exist_ok=True)

    if single_repo:
        # Download only that specific repository
        download_db_by_name(single_repo, lang, threads)
        return

    # Otherwise fetch top repos for this language
    logger.info("Fetching up to %d top %s repos with DBs on GitHub.", max_repos, lang)
    repos_db = search_top_matching_repos(max_repos, lang)
    write_file_text(backup_file, json.dumps(repos_db))

    for i, repo_info in enumerate(repos_db):
        logger.info("Downloading repo %d/%d: %s", i + 1, len(repos_db), repo_info['repo_name'])
        download_and_extract_db(repo_info, threads, db_folder)

        # Update the backup file in case of error or partial completion
        remaining = repos_db[i + 1 :]
        write_file_text(backup_file, json.dumps(remaining))

    if os.path.exists(backup_file):
        os.unlink(backup_file)


def main_cli() -> None:
    """
    CLI entry point. If no arguments, fetch top LANG repos.
    If an argument 'org/repo' is provided, fetch just that DB.
    """
    logger.info("Current lang: %s", LANG)

    if len(sys.argv) == 1:
        # No arguments, do the "bulk fetch"
        fetch_codeql_dbs(lang=LANG, max_repos=100, threads=4)
    else:
        # If a single arg is provided, assume it's an 'org/repo' to fetch
        if "/" in sys.argv[1]:
            fetch_codeql_dbs(lang=LANG, threads=4, single_repo=sys.argv[1])
        else:
            logger.error("Usage:\n  python fetch_repos.py\n  or\n  python fetch_repos.py orgName/repoName")


if __name__ == "__main__":
    main_cli()
