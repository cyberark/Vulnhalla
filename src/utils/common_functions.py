"""
Common utility functions for Vulnhalla.

This module provides reusable helpers for file and path handling,
working with CodeQL database directories, and other small I/O utilities
that are shared across multiple parts of the project.
"""

import os
import zipfile
import yaml
from typing import List, Dict


def read_file(file_name: str) -> str:
    """
    Read text from a file (UTF-8).

    Args:
        file_name (str): The path to the file to be read.

    Returns:
        str: The contents of the file, decoded as UTF-8.
    """
    with open(file_name, "r", encoding="utf-8") as f:
        return f.read()


def write_file_text(file_name: str, data: str) -> None:
    """
    Write text data to a file (UTF-8).

    Args:
        file_name (str): The path to the file to be written.
        data (str): The string data to write to the file.
    """
    with open(file_name, "w", encoding="utf-8") as f:
        f.write(data)


def write_file_ascii(file_name: str, data: str) -> None:
    """
    Write data to a file in ASCII mode (ignores errors).
    Useful for contexts similar to the original 'wb' approach
    where non-ASCII characters are simply dropped.

    Args:
        file_name (str): The path to the file to be written.
        data (str): The string data to write (non-ASCII chars ignored).
    """
    with open(file_name, "wb") as f:
        f.write(data.encode("ascii", "ignore"))


def get_all_dbs(dbs_folder: str) -> List[str]:
    """
    Return a list of all CodeQL database paths under `dbs_folder`.

    Args:
        dbs_folder (str): The folder containing CodeQL databases.

    Returns:
        List[str]: A list of file-system paths pointing to valid CodeQL databases.
    """
    dbs_path = []
    for folder in os.listdir(dbs_folder):
        folder_path = os.path.join(dbs_folder, folder)
        if os.path.isdir(folder_path):
            for sub_folder in os.listdir(folder_path):
                curr_db_path = os.path.join(folder_path, sub_folder)
                if os.path.exists(os.path.join(curr_db_path, "codeql-database.yml")):
                    dbs_path.append(curr_db_path)
    return dbs_path


def read_file_lines_from_zip(zip_path: str, file_path_in_zip: str) -> str:
    """
    Read text from a single file within a ZIP archive (UTF-8).

    Args:
        zip_path (str): The path to the ZIP file.
        file_path_in_zip (str): The internal path within the ZIP to the file.

    Returns:
        str: The contents of the file (as UTF-8) located within the ZIP.
    """
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        with zip_ref.open(file_path_in_zip) as file:
            return file.read().decode('utf-8')


def read_yml(file_path: str) -> Dict:
    """
    Read and parse a YAML file, returning its data as a Python dictionary.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        Dict: The YAML data as a dictionary.
    """
    with open(file_path, 'r', encoding="utf-8") as file:
        return yaml.safe_load(file)