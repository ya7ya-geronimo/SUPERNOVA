## Directory Structure
- **`__init__.py`**: Exposes the package API.
- **`network_checks.py`**: Contains Layer 4 / Transport protocol checks (FTP, SMB, Telnet, RDP).
- **`web_checks.py`**: Contains Application layer web checks (HTTP, Headers).
- **`runner.py`**: The dynamic discovery and execution engine.

---

## 1. `checks/runner.py`
This is the heart of the checks module. It finds checks and runs them.

### `CheckRunner` Class

#### `__init__(self)`
Initializes the runner by creating an empty list `self.checks` and immediately calling `_load_checks()` to populate it.

#### `_load_checks(self)`
**Purpose**: To dynamically discover and import check modules without manual registration.
**Logic**:
1.  **Path Resolution**: key steps:
    ```python
    current_dir = os.path.dirname(__file__)
    check_files = glob.glob(os.path.join(current_dir, '*_checks.py'))
    ```
    This finds all files ending in `_checks.py` in the same directory as `runner.py`.
2.  **Iterative Import**:
    -   Iterates through each found file.
    -   **Exclusion**: Explicitly skips `verify_checks.py` to prevent running tests as checks.
    -   **Module Name**: Converts filename `network_checks.py` -> `checks.network_checks`.
3.  **Registration**:
    -   Imports the module using `importlib`.
    -   Inspects the module for **functions** (not classes) that start with `check_`.
    -   Calls `self.register_check(func)` for each match.

#### `register_check(self, check_func)`
Simply appends the function object to `self.checks`.

#### `run_all(self, target: str) -> List[Dict]`
**Purpose**: Executes all loaded checks against a specific target IP/Hostname.
**Logic**:
1.  Iterates through `self.checks`.
2.  **Error Handling**: Wraps execution in a `try...except` block to prevent one broken check from stopping the whole scan.
3.  **Result Standardization**:
    -   Calls `check(target)`.
    -   Injects `check_name` into the result dictionary if the check didn't provide it (uses the function name).
    -   Collects all results into a list.

---

## 2. `checks/network_checks.py`
Contains checks for low-level network services.

### `check_ftp(target, port=21)`
**Goal**: Detect Anonymous FTP Login.
1.  **Socket Creation**: Creates a TCP socket with a 3-second timeout.
2.  **Connection**: `s.connect_ex` returns `0` if successful. If non-zero, it returns "Closed".
3.  **Banner Grab**: Attempts to read the initial welcome message from the server.
4.  **Vulnerability Logic**:
    -   Sends `USER anonymous`.
    -   Sends `PASS anonymous@`.
    -   **Key Check**: Checks if the server response contains code `"230"` (User logged in).
    -   If yes, marks `vulnerable=True`.
5.  **Cleanup**: Uses `finally` block to ensure `s.close()` is called.

### `check_smb(target, port=445)`
**Goal**: Detect SMB Guest Access.
**Library**: Uses `pysmb` (`smb.SMBConnection`).
1.  **Connection**:
    ```python
    conn = SMBConnection(username="", password="", ... use_ntlm_v2=True)
    ```
    Configures a connection attempt with **empty credentials**.
2.  **Vulnerability Logic**:
    -   `conn.connect()` attempts the handshake.
    -   If connected, it tries `conn.listShares()`.
    -   **Key Check**: If `listShares` succeeds without authentication error, it means Guest access is enabled.
    -   Marks `vulnerable=True`.
3.  **Cleanup**: Closes the SMB connection in `finally`.

### `check_telnet(target, port=23)`
**Goal**: Detect Telnet Service.
1.  **Logic**: Telnet is inherently insecure (cleartext).
2.  **Vulnerability**: If the port (23) is **Open**, it is automatically marked `vulnerable=True` with description "Cleartext protocol".

### `check_rdp(target, port=3389)`
**Goal**: Detect RDP Service.
1.  **Logic**: Checks if port 3389 is open.
2.  **Vulnerability**: Currently flags as "Open" with a warning to check for NLA (Network Level Authentication). Does not flag potentially vulnerable unless further handshake logic is implemented.

---

## 3. `checks/web_checks.py`
Contains checks for HTTP/HTTPS services.

### `check_http(target, port=80)`
**Goal**: Detect Unencrypted HTTP.
1.  **Connection**: Connects to port 80 (or custom).
2.  **Request**: Sends a raw HTTP GET request:
    ```
    GET / HTTP/1.1
    Host: <target>
    Connection: close
    ```
3.  **Analysis**:
    -   Parses headers to find `Server`.
    -   **Vulnerability Logic**: Checks if `ssl` is False (implied by this simple socket check) or port is 80.
    -   Marks `vulnerable=True` and adds "Unencrypted HTTP service detected".

### `check_security_headers(target, port=80)`
**Goal**: specific check for missing HTTP Security Headers.
1.  **Target Headers**:
    -   `X-Content-Type-Options`
    -   `X-Frame-Options`
    -   `Strict-Transport-Security`
    -   `Content-Security-Policy`
2.  **Logic**:
    -   Sends a `HEAD` request (lightweight compared to GET).
    -   Iterates through response headers.
    -   Compares present headers against the required list.
    -   **Vulnerability**: If any are missing, marks `vulnerable=True` and lists missing headers.

---

## 4. `checks/__init__.py`
**Purpose**: Package interface.
-   Imports specific check functions from `network_checks` and `web_checks`.
-   Imports `CheckRunner` from `runner`.
-   **`__all__`**: Defines what is exported when someone runs `from checks import *`. This keeps the namespace clean.

## 5. `main.py`
**Purpose**: CLI Entry Point.
-   Uses `argparse` to accept a `target` argument.
-   Instantiates `CheckRunner`.
-   Calls `runner.run_all(target)`.
-   Prints formatted results to the console.

---

## Key Design Principles Used
1.  **Scalability**: The dynamic loader (`glob` in `runner.py`) means you can add `checks/cve_checks.py` and it will work instantly.
2.  **Reliability**: Every network interaction is wrapped in `try...except...finally` to ensure resources (sockets) are released.
3.  **Modularity**: Checks are grouped by domain (Network vs Web) rather than one huge file or too many tiny files.
4.  **Graceful Degradation**: The `pysmb` library is imported with a `try/except` guard and a `HAS_PYSMB` flag. If pysmb is not installed, only the SMB check is skipped — FTP, Telnet, RDP, and all other checks continue to work normally. This prevents a single missing dependency from breaking the entire checks module.

---

## Bug Fixes Applied (v2)
- **pysmb Import Guard**: The top-level `from smb.SMBConnection import SMBConnection` was crashing the entire `network_checks.py` module if pysmb was missing, taking down ALL checks (FTP, Telnet, RDP). Now wrapped in `try/except`.
- **`__init__.py` Guard**: Protected `check_smb` import so the package loads even without pysmb.
- **Socket Cleanup**: All check functions use `finally` blocks with null-safe socket closing to prevent resource leaks.

