"""
Basic Vulnerability Patterns
"""

VULN_PATTERNS = {

    "FTP Anonymous Login":
        {
            "port": 21,
            "risk": "Medium",
            "description": "FTP allows anonymous login"
        },

    "SSH Open":
        {
            "port": 22,
            "risk": "Info",
            "description": "SSH service detected"
        },

    "Telnet Open":
        {
            "port": 23,
            "risk": "High",
            "description": "Telnet is insecure protocol"
        },

    "SMB Open":
        {
            "port": 445,
            "risk": "High",
            "description": "SMB exposed"
        },

    "RDP Open":
        {
            "port": 3389,
            "risk": "Medium",
            "description": "RDP exposed"
        }

}
