"""
Common utility functions for Vulnhalla.

This module provides reusable helpers for file and path handling,
working with CodeQL database directories, and other small I/O utilities
that are shared across multiple parts of the project.
"""

from pathlib import Path
import zipfile
import yaml
from typing import Any, Dict, List 

from src.utils.exceptions import VulnhallaError, CodeQLError


def read_file(file_name: str) -> str:
    """
    Read text from a file (UTF-8).

    Args:
        file_name (str): The path to the file to be read.

    Returns:
        str: The contents of the file, decoded as UTF-8.
    
    Raises:
        VulnhallaError: If file cannot be read (not found, permission denied, encoding error).
    """
    try:
        with Path(file_name).open("r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError as e:
        raise VulnhallaError(f"File not found: {file_name}") from e
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied reading file: {file_name}") from e
    except UnicodeDecodeError as e:
        raise VulnhallaError(f"Failed to decode file as UTF-8: {file_name}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while reading file: {file_name}") from e


def write_file_text(file_name: str, data: str) -> None:
    """
    Write text data to a file (UTF-8).

    Args:
        file_name (str): The path to the file to be written.
        data (str): The string data to write to the file.
    
    Raises:
        VulnhallaError: If file cannot be written (permission denied, disk full, etc.).
    """
    try:
        with Path(file_name).open("w", encoding="utf-8") as f:
            f.write(data)
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied writing file: {file_name}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while writing file: {file_name}") from e


def write_file_ascii(file_name: str, data: str) -> None:
    """
    Write data to a file in ASCII mode (ignores errors).
    Useful for contexts similar to the original 'wb' approach
    where non-ASCII characters are simply dropped.

    Args:
        file_name (str): The path to the file to be written.
        data (str): The string data to write (non-ASCII chars ignored).
    
    Raises:
        VulnhallaError: If file cannot be written (permission denied, disk full, etc.).
    """
    try:
        with Path(file_name).open("wb") as f:
            f.write(data.encode("ascii", "ignore"))
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied writing file: {file_name}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while writing file: {file_name}") from e


def get_all_dbs(dbs_folder: str) -> List[str]:
    """
    Return a list of all CodeQL database paths under `dbs_folder`.

    Args:
        dbs_folder (str): The folder containing CodeQL databases.

    Returns:
        List[str]: A list of file-system paths pointing to valid CodeQL databases.
    
    Raises:
        CodeQLError: If database folder cannot be accessed (permission denied, not found, etc.).
    """
    if not Path(dbs_folder).exists():
        return []
    if (Path(dbs_folder) / "codeql-database.yml").exists():
        return [dbs_folder]

    try:
        dbs_path = []
        for path in Path(dbs_folder).rglob('codeql-database.yml'):
            db_path = path.parent
            dbs_path.append(str(db_path))
        return dbs_path
    except PermissionError as e:
        raise CodeQLError(f"Permission denied accessing database folder: {dbs_folder}") from e
    except OSError as e:
        raise CodeQLError(f"OS error while accessing database folder: {dbs_folder}") from e


def read_file_lines_from_zip(zip_path: str, file_path_in_zip: str) -> str:
    """
    Read text from a single file within a ZIP archive (UTF-8).

    Args:
        zip_path (str): The path to the ZIP file.
        file_path_in_zip (str): The internal path within the ZIP to the file.

    Returns:
        str: The contents of the file (as UTF-8) located within the ZIP.
    
    Raises:
        CodeQLError: If ZIP file cannot be read or file not found in archive.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            with zip_ref.open(file_path_in_zip) as file:
                return file.read().decode('utf-8')
    except zipfile.BadZipFile as e:
        raise CodeQLError(f"Invalid or corrupted ZIP file: {zip_path}") from e
    except KeyError as e:
        raise CodeQLError(f"File '{file_path_in_zip}' not found in ZIP archive: {zip_path}") from e
    except PermissionError as e:
        raise CodeQLError(f"Permission denied reading ZIP file: {zip_path}") from e
    except OSError as e:
        raise CodeQLError(f"OS error while reading ZIP file: {zip_path}") from e


def read_yml(file_path: str) -> Dict[str, Any]:
    """
    Read and parse a YAML file, returning its data as a Python dictionary.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        Dict[str, Any]: The YAML data as a dictionary.
    
    Raises:
        VulnhallaError: If file cannot be read or YAML parsing fails.
    """
    try:
        with Path(file_path).open('r', encoding="utf-8") as file:
            return yaml.safe_load(file)
    except FileNotFoundError as e:
        raise VulnhallaError(f"YAML file not found: {file_path}") from e
    except PermissionError as e:
        raise VulnhallaError(f"Permission denied reading YAML file: {file_path}") from e
    except yaml.YAMLError as e:
        raise VulnhallaError(f"Failed to parse YAML file: {file_path}") from e
    except OSError as e:
        raise VulnhallaError(f"OS error while reading YAML file: {file_path}") from e