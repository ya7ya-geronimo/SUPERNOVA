"""
SUPERNOVA Vulnerability Scanner
Main Configuration File
"""

# Scanner Information
SCANNER_NAME = "SUPERNOVA"
VERSION = "1.0"
AUTHOR = "Yehya Taher"

# Default Timeout (seconds)
DEFAULT_TIMEOUT = 3

# Thread Settings
MAX_THREADS = 100

# Default Scan Type
DEFAULT_SCAN_TYPE = "full"

# Output Settings
OUTPUT_FOLDER = "reports"
OUTPUT_FORMAT = "txt"   # txt, json, html

# Logging
LOGGING_ENABLED = True
LOG_FILE = "logs/supernova.log"

# Debug Mode
DEBUG = False
