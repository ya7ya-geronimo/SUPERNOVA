import socket

try:
    from smb.SMBConnection import SMBConnection
    HAS_PYSMB = True
except ImportError:
    HAS_PYSMB = False

def check_ftp(target: str, port: int = 21) -> dict:
    """
    Checks for anonymous FTP login and grabs the banner.
    """
    result = {
        "service": "FTP",
        "port": port,
        "status": "Closed",
        "vulnerable": False,
        "description": "Port is closed"
    }

    s = None
    try:
        # 1. Connect and Grab Banner
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        code = s.connect_ex((target, port))
        
        if code != 0:
            return result
        
        result["status"] = "Open"
        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            result["banner"] = banner
        except:
            result["banner"] = "No banner"

        # 2. Check Anonymous Login
        s.sendall(b"USER anonymous\r\n")
        response_user = s.recv(1024).decode('utf-8', errors='ignore')
        
        s.sendall(b"PASS anonymous@\r\n")
        response_pass = s.recv(1024).decode('utf-8', errors='ignore')
        
        if "230" in response_pass:  # 230 User logged in, proceed.
            result["vulnerable"] = True
            result["description"] = "Anonymous FTP login allowed (Code 230)."
        else:
            result["description"] = "Anonymous login disabled."

    except Exception as e:
        result["error"] = str(e)
        result["description"] = f"Error during check: {e}"
    finally:
        if s:
            s.close()

    return result

def check_smb(target: str, port: int = 445) -> dict:
    """
    Checks if SMB port is open.
    """
    result = {
        "service": "SMB",
        "port": port,
        "status": "Closed",
        "description": "Port is closed"
    }
    
    if not HAS_PYSMB:
        result["status"] = "Skipped"
        result["description"] = "pysmb library not installed. Run: pip install pysmb"
        return result
    
    conn = None
    try:
        # Pysmb requires a client name and server name (can be IP)
        client_name = "VulnScanner"
        server_name = target 
        
        # Connect with an empty username and password for Guest
        conn = SMBConnection(
            username="",
            password="",
            my_name=client_name,
            remote_name=server_name,
            domain="",
            use_ntlm_v2=True,
            is_direct_tcp=True
        )
        
        # Connect to port 445 (standard SMB over TCP)
        connected = conn.connect(target, port, timeout=3)
        
        if connected:
            result["status"] = "Open"
            
            # Now checking if we are authenticated as Guest
            try:
                # Listing shares is a good way to verify access
                shares = conn.listShares(timeout=3)
                result["vulnerable"] = True
                result["description"] = f"SMB Guest access allowed. Found {len(shares)} shares."
            except Exception:
                result["description"] = "SMB Open, but Guest access denied."
        
        else:
            result["status"] = "Closed"

    except Exception as e:
        # If connection fails, it might be closed or firewall
        result["error"] = str(e)
        result["description"] = f"Error connecting to SMB: {e}"
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

    return result

def check_telnet(target: str, port: int = 23) -> dict:
    """
    Checks for Telnet service and grabs banner.
    Telnet is inherently insecure (cleartext).
    """
    result = {
        "service": "Telnet",
        "port": port,
        "status": "Closed",
        "vulnerable": False,
        "description": "Port is closed"
    }

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        code = s.connect_ex((target, port))
        
        if code == 0:
            result["status"] = "Open"
            result["vulnerable"] = True # Telnet is always a risk
            result["description"] = "Telnet service detected (Cleartext protocol)."
            
            try:
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                result["banner"] = banner
            except:
                pass

    except Exception as e:
        result["error"] = str(e)
    finally:
        if s:
            s.close()
        
    return result

def check_rdp(target: str, port: int = 3389) -> dict:
    """
    Checks if RDP port is open and attempts a basic handshake.
    """
    result = {
        "service": "RDP",
        "port": port,
        "status": "Closed",
        "description": "Port is closed"
    }

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        code = s.connect_ex((target, port))
        
        if code == 0:
            result["status"] = "Open"
            # Simple check: RDP usually requires checking for protocol support
            # which is complex. For now, we report open port and potential
            # banner if sent (RDP doesn't always send banner on connect).
            # A full RDP handshake (like BlueKeep check) requires a lot of bytes.
            result["description"] = "RDP port is open. Ensure NLA is enabled."

    except Exception as e:
        result["error"] = str(e)
    finally:
        if s:
            s.close()
        
    return result
