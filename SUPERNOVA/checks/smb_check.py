import socket

try:
    from smb.SMBConnection import SMBConnection
    HAS_PYSMB = True
except ImportError:
    HAS_PYSMB = False

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

            conn.close()
        
        else:
            result["status"] = "Closed"

    except Exception as e:
        # If connection fails, it might be closed or firewall
        result["error"] = str(e)
        result["description"] = f"Error connecting to SMB: {e}"

    return result