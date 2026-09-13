import os
import shutil
from pathlib import Path
from typing import Optional

def find_tshark() -> Optional[str]:
    """Find tshark binary from env, PATH, or standard installation paths.
    
    Returns:
        Absolute path to tshark executable, or None if not found.
    """
    # 1. Check explicit environment variable
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    # 2. Check system PATH
    which_tshark = shutil.which("tshark")
    if which_tshark:
        return which_tshark

    # 3. Check common OS locations
    common_paths = [
        # Windows standard locations
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        # Linux standard locations
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        # macOS standard locations
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
    ]

    for p in common_paths:
        if os.path.isfile(p):
            return p

    return None

def is_tshark_available() -> bool:
    """Return True if tshark binary is discovered."""
    return find_tshark() is not None
