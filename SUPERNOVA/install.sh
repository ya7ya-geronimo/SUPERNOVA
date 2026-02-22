#!/bin/bash
# ==========================================
# SUPERNOVA Setup & Installation Script
# ==========================================

# 1. Root Privilege Check
# Ensure the script is executed with administrative (root) privileges to allow system modifications.
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (use sudo bash install.sh)"
  exit
fi

echo "[*] Cleaning Windows CRLF formats..."
# 2. Format Cleanup
# Remove hidden Windows carriage return (\r) characters from the Python script
# This prevents the "bad interpreter" error when running on Linux systems.
sed -i 's/\r$//' main.py

echo "[*] Installing SUPERNOVA Scanner..."

# 3. Execution Permissions
# Grant execute permissions to the main Python script so it can run as a standalone program.
chmod +x main.py

# 4. Global Command Link (Symlink)
# Get the absolute path of the current directory, then create a symbolic link in /usr/local/bin.
# This allows the tool to be executed globally just by typing 'supernova' in any terminal.
TOOL_DIR=$(pwd)
ln -sf "$TOOL_DIR/main.py" /usr/local/bin/supernova

echo "[+] Installation complete!"
echo "[+] You can now run the tool from anywhere by typing: supernova"
