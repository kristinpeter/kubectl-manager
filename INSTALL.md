# Installation Guide - kubectl Manager

Complete installation instructions for kubectl Manager on different platforms.

## 🚀 Quick Install (Recommended)

```bash
git clone https://github.com/your-username/kubectl-manager.git
cd kubectl-manager
./install.sh
```

The install script will:
- Check Python 3 installation
- Install required dependencies
- Set up bash completion (optional)
- Create convenience aliases
- Test basic functionality

## System Requirements

### Minimum Requirements
- **Python**: 3.6 or higher
- **Operating System**: Linux, macOS, or Windows
- **Network**: Internet access for downloading kubectl versions
- **Disk Space**: ~100MB per kubectl version (typical: 200-500MB total)

### Dependencies
- **Python standard library** (included with Python)
- **requests** library (for HTTP downloads)

## Installation Methods

### Method 1: Download Script (Recommended)

#### Linux / macOS
```bash
# 1. Create directory and navigate
mkdir kubectl-manager && cd kubectl-manager

# 2. Download kubectl-manager.py
curl -O https://raw.githubusercontent.com/your-repo/kubectl-manager/main/kubectl-manager.py

# 3. Make executable
chmod +x kubectl-manager.py

# 4. Install Python dependencies
pip3 install requests

# 5. Test installation
./kubectl-manager.py --help
```

#### Windows (PowerShell)
```powershell
# 1. Create directory and navigate
New-Item -ItemType Directory -Name kubectl-manager
Set-Location kubectl-manager

# 2. Download kubectl-manager.py
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-repo/kubectl-manager/main/kubectl-manager.py" -OutFile "kubectl-manager.py"

# 3. Install Python dependencies
pip install requests

# 4. Test installation
python kubectl-manager.py --help
```

### Method 2: Git Clone
```bash
# Clone repository
git clone https://github.com/your-repo/kubectl-manager.git
cd kubectl-manager

# Make executable (Linux/macOS only)
chmod +x kubectl-manager.py

# Install dependencies
pip3 install requests

# Test
./kubectl-manager.py --help
```

### Method 3: Manual Setup
1. Download `kubectl-manager.py` to your desired directory
2. Install Python requests: `pip install requests`
3. Make executable: `chmod +x kubectl-manager.py` (Linux/macOS)
4. Run: `./kubectl-manager.py` or `python kubectl-manager.py`

## Platform-Specific Instructions

### Ubuntu / Debian
```bash
# Install Python and pip (if not installed)
sudo apt update
sudo apt install python3 python3-pip

# Create directory
mkdir ~/kubectl-manager && cd ~/kubectl-manager

# Download script
wget https://raw.githubusercontent.com/your-repo/kubectl-manager/main/kubectl-manager.py
chmod +x kubectl-manager.py

# Install dependencies
pip3 install --user requests

# Test
./kubectl-manager.py
```

### CentOS / RHEL / Fedora
```bash
# Install Python and pip
sudo yum install python3 python3-pip  # CentOS/RHEL
# or
sudo dnf install python3 python3-pip  # Fedora

# Setup
mkdir ~/kubectl-manager && cd ~/kubectl-manager
curl -O https://raw.githubusercontent.com/your-repo/kubectl-manager/main/kubectl-manager.py
chmod +x kubectl-manager.py

# Dependencies
pip3 install --user requests

# Test
./kubectl-manager.py
```

### macOS
```bash
# Install Python (if using system Python or Homebrew)
# System Python should work, or:
brew install python3

# Setup
mkdir ~/kubectl-manager && cd ~/kubectl-manager
curl -O https://raw.githubusercontent.com/your-repo/kubectl-manager/main/kubectl-manager.py
chmod +x kubectl-manager.py

# Dependencies
pip3 install requests

# Test
./kubectl-manager.py
```

### Windows

#### Using Python from python.org
```cmd
:: Install Python 3.x from python.org first

:: Create directory
mkdir kubectl-manager
cd kubectl-manager

:: Download (use browser or PowerShell Invoke-WebRequest as shown above)

:: Install dependencies
pip install requests

:: Test
python kubectl-manager.py
```

#### Using Windows Subsystem for Linux (WSL)
```bash
# Use Linux instructions within WSL
mkdir ~/kubectl-manager && cd ~/kubectl-manager
wget https://raw.githubusercontent.com/your-repo/kubectl-manager/main/kubectl-manager.py
chmod +x kubectl-manager.py
pip3 install requests
./kubectl-manager.py
```

## Verification

### Test Basic Functionality
```bash
# Check script runs
./kubectl-manager.py --help

# Test version fetching (requires internet)
./kubectl-manager.py versions list

# Test interactive mode
./kubectl-manager.py
# Should show main menu
```

### Expected Output
```
🚀 kubectl Manager - Multi-version kubectl and cluster management

┌─ kubectl Manager ─────────────────────┐
│ No active configuration               │
│                                       │
│ 1. Manage kubectl versions            │
│ 2. Manage cluster configs            │
│ 3. Switch version + config           │
│ 4. Run kubectl command               │
│ 5. Status & health check             │
│ 6. Exit                              │
└───────────────────────────────────────┘
```

## Post-Installation Setup

### 1. First Run
```bash
./kubectl-manager.py
```
This creates the required directory structure:
```
your-directory/
├── kubectl-manager.py
├── bin/                  # Created automatically
├── configs/              # Created automatically
├── .kubectl-manager/     # Created automatically
└── kubectl              # Symlink created when first used
```

### 2. Install Your First kubectl Version
```bash
# Install latest stable version
./kubectl-manager.py versions install 1.30.0

# Or check available versions first
./kubectl-manager.py versions list
```

### 3. Add Your First Cluster
```bash
# Interactive method
./kubectl-manager.py
> Select option 2 (Manage cluster configs)
> Select option 2 (Add cluster)

# Command line method
./kubectl-manager.py configs add mycluster ~/.kube/config
```

## Optional: System-Wide Installation

### Linux / macOS
```bash
# Install to system location (requires sudo)
sudo mkdir -p /opt/kubectl-manager
sudo cp kubectl-manager.py /opt/kubectl-manager/
sudo chmod +x /opt/kubectl-manager/kubectl-manager.py

# Create system-wide symlink
sudo ln -s /opt/kubectl-manager/kubectl-manager.py /usr/local/bin/kubectl-manager

# Now available system-wide
kubectl-manager --help
```

### Add to PATH
```bash
# Add to ~/.bashrc, ~/.zshrc, or ~/.profile
export PATH="$PATH:/path/to/kubectl-manager"

# Or create alias
alias kubectl-manager="/path/to/kubectl-manager/kubectl-manager.py"
alias km="/path/to/kubectl-manager/kubectl-manager.py"  # Short alias
```

## Troubleshooting Installation

### Common Issues

#### "python3: command not found"
```bash
# Install Python 3
# Ubuntu/Debian: sudo apt install python3
# CentOS/RHEL: sudo yum install python3  
# macOS: brew install python3
# Windows: Download from python.org
```

#### "No module named 'requests'"
```bash
# Install requests library
pip3 install requests

# If pip3 not found, try:
python3 -m pip install requests

# On some systems:
sudo apt install python3-requests  # Ubuntu/Debian
sudo yum install python3-requests  # CentOS/RHEL
```

#### "Permission denied"
```bash
# Make script executable (Linux/macOS)
chmod +x kubectl-manager.py

# Or run with Python explicitly
python3 kubectl-manager.py
```

#### "urllib.error.URLError" when fetching versions
```bash
# Check internet connectivity
ping api.github.com

# Check firewall/proxy settings
# May need to configure HTTP_PROXY/HTTPS_PROXY environment variables
```

#### Windows: "kubectl-manager.py is not recognized"
```cmd
:: Run with Python explicitly
python kubectl-manager.py

:: Or add Python to PATH and use
python kubectl-manager.py
```

### Verification Commands
```bash
# Check Python version
python3 --version

# Check requests library
python3 -c "import requests; print('requests OK')"

# Check script permissions
ls -la kubectl-manager.py

# Test network connectivity
curl -I https://api.github.com/repos/kubernetes/kubernetes/releases
```

## Uninstallation

To remove kubectl Manager:

### Complete Removal
```bash
# Remove all data
rm -rf /path/to/kubectl-manager/

# If installed system-wide
sudo rm /usr/local/bin/kubectl-manager
sudo rm -rf /opt/kubectl-manager
```

### Keep Downloaded kubectl Binaries
```bash
# Backup kubectl versions before removal
cp -r bin/ ~/kubectl-binaries-backup/

# Then remove kubectl-manager
rm kubectl-manager.py
rm -rf .kubectl-manager/ configs/
```

## Next Steps

After successful installation:
1. **Read the [README.md](README.md)** for feature overview
2. **Check the [USER_MANUAL.md](USER_MANUAL.md)** for detailed usage
3. **Import your first cluster** with `./kubectl-manager.py configs add`
4. **Start using kubectl** with automatic version management

---

**🎉 Installation Complete! 🎉**

Your kubectl Manager is ready to help you manage multiple kubectl versions and Kubernetes clusters efficiently.