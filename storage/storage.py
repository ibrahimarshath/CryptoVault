"""
storage/storage.py -- Generic JSON File I/O
==========================================

Centralises all file reading/writing so every module uses the same
safe, consistent I/O helpers.

Features
--------
  * Creates parent directories automatically
  * Atomic write: writes to a temp file first, then renames, so a crash
    mid-write does not corrupt the existing file.
  * Returns a default value if the file does not exist yet.
"""

import os
import json
import tempfile
from typing import Any


def load_json(path: str, default: Any = None) -> Any:
    """
    Load and parse a JSON file.

    Parameters
    ----------
    path    : str -- Absolute or relative path to the JSON file.
    default : Any -- Value to return if the file does not exist yet.
                    Defaults to None.

    Returns
    -------
    Parsed JSON object (dict, list, etc.) or the default value.
    """
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path: str, data: Any, indent: int = 2) -> None:
    """
    Serialise data to JSON and write to path atomically.

    Parameters
    ----------
    path   : str -- Destination file path.
    data   : Any -- JSON-serialisable object.
    indent : int -- Pretty-print indentation (default 2).

    The write is atomic: data goes to a temp file in the same directory
    first, then the temp file is renamed to the target path.  If the
    process crashes mid-write, the original file is not corrupted.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    dir_name = os.path.dirname(os.path.abspath(path))
    # Write to a temp file in the same directory
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
        # Atomic rename (on the same filesystem, rename is atomic on POSIX;
        # on Windows, os.replace() overwrites atomically)
        os.replace(tmp_path, path)
    except Exception:
        # Clean up temp file on failure
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
