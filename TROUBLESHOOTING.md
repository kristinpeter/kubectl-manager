# Troubleshooting Guide - kubectl Manager

Complete troubleshooting guide for common issues and solutions.

## Common Issues and Solutions

### 1. Installation and Setup Issues

#### "python3: command not found" or "python: command not found"
**Problem**: Python is not installed or not in PATH  
**Solution**:
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install python3

# CentOS/RHEL
sudo yum install python3

# macOS with Homebrew
brew install python3

# Windows
# Download Python from python.org and install
# Make sure "Add Python to PATH" is checked during installation
```

#### "No module named 'requests'"
**Problem**: Required Python library not installed  
**Solution**:
```bash
# Install requests library
pip3 install requests

# If pip3 not available
python3 -m pip install requests

# On some Linux systems
sudo apt install python3-requests    # Ubuntu/Debian
sudo yum install python3-requests    # CentOS/RHEL
```

#### "Permission denied" when running script
**Problem**: Script not executable  
**Solution**:
```bash
# Linux/macOS - make script executable
chmod +x kubectl-manager.py

# Alternative: run with Python explicitly
python3 kubectl-manager.py

# Windows: always use
python kubectl-manager.py
```

### 2. Network and Download Issues

#### "urllib.error.URLError" or "Failed to fetch versions"
**Problem**: Network connectivity issues  
**Solution**:
```bash
# Test connectivity
ping api.github.com
curl -I https://api.github.com/repos/kubernetes/kubernetes/releases

# Check proxy settings (if behind corporate firewall)
export HTTP_PROXY=http://your-proxy:port
export HTTPS_PROXY=https://your-proxy:port

# Test manual download
curl -I https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl
```

#### "SSL certificate verify failed"
**Problem**: SSL/TLS certificate issues  
**Solution**:
```bash
# Update certificates (Linux)
sudo apt update && sudo apt install ca-certificates  # Ubuntu/Debian
sudo yum update ca-certificates                      # CentOS/RHEL

# macOS
brew install ca-certificates

# Temporary workaround (NOT recommended for production)
export PYTHONHTTPSVERIFY=0
```

#### Downloads fail or are corrupted
**Problem**: Network interruption or proxy interference  
**Solution**:
```bash
# Clear download cache
rm -rf .kubectl-manager/cache/

# Check available disk space
df -h

# Test manual kubectl download
wget https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl
# or
curl -LO https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl
```

### 3. Cluster Connection Issues

#### "Cluster version detection failed"
**Problem**: Cannot connect to Kubernetes cluster  
**Diagnosis**:
```bash
# Test kubeconfig manually
kubectl --kubeconfig=/path/to/config cluster-info
kubectl --kubeconfig=/path/to/config version

# Check if kubectl is available
which kubectl
kubectl version --client
```

**Solutions**:
```bash
# Option 1: Fix connectivity
# - Check VPN connection
# - Verify kubeconfig is correct and current
# - Test network access to cluster

# Option 2: Add cluster manually with unknown version
./kubectl-manager.py configs add mycluster /path/to/config
# Then install desired kubectl version manually
./kubectl-manager.py versions install 1.30.0
./kubectl-manager.py use mycluster --kubectl 1.30.0
```

#### "Authentication failed" or "Unauthorized"
**Problem**: Kubeconfig authentication is invalid  
**Solution**:
```bash
# Check kubeconfig validity
kubectl --kubeconfig=/path/to/config auth can-i get pods

# Common fixes:
# 1. Refresh authentication tokens
# 2. Update expired certificates
# 3. Verify service account permissions
# 4. Check if cluster endpoint URL is correct

# Test with verbose output
kubectl --kubeconfig=/path/to/config get pods -v=8
```

#### "Connection timeout" or "Connection refused"
**Problem**: Network connectivity to cluster  
**Solution**:
```bash
# Check cluster endpoint
kubectl --kubeconfig=/path/to/config config view --minify

# Test connectivity to cluster endpoint
# Extract server URL from kubeconfig and test
curl -k https://your-cluster-endpoint:6443/healthz

# Check firewall rules
# Verify VPN/proxy settings
# Confirm cluster is running
```

### 4. kubectl Version Issues

#### "kubectl not found" after installation
**Problem**: Downloaded kubectl binary not executable or in PATH  
**Diagnosis**:
```bash
# Check if binary exists
ls -la bin/kubectl-*

# Check permissions
ls -la bin/kubectl-1.30.0
```

**Solution**:
```bash
# Fix permissions
chmod +x bin/kubectl-*

# Test binary directly
./bin/kubectl-1.30.0 version --client

# Check symlink (Linux/macOS)
ls -la kubectl
```

#### "Version skew" warnings
**Problem**: kubectl and cluster versions are not compatible  
**Understanding**:
- kubectl supports ±1 minor version from cluster
- Example: Cluster v1.30.x works with kubectl v1.29.x, v1.30.x, v1.31.x

**Solution**:
```bash
# Install compatible kubectl version
./kubectl-manager.py versions install 1.30.0

# Switch to compatible version
./kubectl-manager.py use mycluster --kubectl 1.30.0

# Or let tool auto-select
./kubectl-manager.py use mycluster
```

#### "No space left on device" during kubectl download
**Problem**: Insufficient disk space  
**Solution**:
```bash
# Check available space
df -h

# Clean old kubectl versions
./kubectl-manager.py versions list
# Manually remove old versions from bin/
rm bin/kubectl-1.28.0 bin/kubectl-1.27.0

# Or clean entire tool and restart
rm -rf bin/ .kubectl-manager/cache/
```

### 5. Configuration Issues

#### "Config file corrupted" or JSON errors
**Problem**: Configuration file is malformed  
**Solution**:
```bash
# Check config file
cat .kubectl-manager/config.json

# Validate JSON
python3 -m json.tool .kubectl-manager/config.json

# Reset configuration (loses settings but keeps binaries/configs)
rm .kubectl-manager/config.json
./kubectl-manager.py  # Will recreate with defaults

# Full reset (WARNING: loses everything)
rm -rf .kubectl-manager/ configs/ bin/
./kubectl-manager.py  # Start fresh
```

#### "Kubeconfig not found" errors  
**Problem**: Kubeconfig file moved or deleted  
**Solution**:
```bash
# Check if file exists
ls -la configs/

# Verify config references
cat .kubectl-manager/config.json | grep config_file

# Re-add missing cluster
./kubectl-manager.py configs add clustername /new/path/to/config

# Or remove broken cluster reference
# Edit .kubectl-manager/config.json manually or reset
```

### 6. Platform-Specific Issues

#### Linux: "No such file or directory" when running kubectl
**Problem**: Missing dynamic library dependencies  
**Solution**:
```bash
# Check binary dependencies
ldd bin/kubectl-1.30.0

# Install missing libraries (usually glibc)
sudo apt install libc6  # Ubuntu/Debian
sudo yum install glibc  # CentOS/RHEL

# For older systems, try static binary
# Download kubectl-static version instead
```

#### macOS: "kubectl cannot be opened because the developer cannot be verified"
**Problem**: macOS Gatekeeper security  
**Solution**:
```bash
# Option 1: Allow in Security & Privacy settings
# System Preferences → Security & Privacy → Allow anyway

# Option 2: Remove quarantine attribute
xattr -d com.apple.quarantine bin/kubectl-1.30.0

# Option 3: Build from source or use Homebrew kubectl
```

#### Windows: kubectl.exe fails to run
**Problem**: Windows-specific execution issues  
**Solution**:
```cmd
:: Check if .exe files are being downloaded
dir bin\

:: Verify Windows Defender isn't blocking
:: Add directory to Windows Defender exclusions

:: Test manual download
curl -LO https://dl.k8s.io/release/v1.30.0/bin/windows/amd64/kubectl.exe
```

### 7. Performance Issues

#### Slow version fetching
**Problem**: GitHub API rate limiting or slow network  
**Solution**:
```bash
# Check rate limit status
curl -I https://api.github.com/repos/kubernetes/kubernetes/releases

# Use cached results
# Tool caches for 1 hour by default

# Manual cache refresh
rm .kubectl-manager/cache/available_versions.json
./kubectl-manager.py versions list
```

#### Large disk usage
**Problem**: Too many kubectl versions downloaded  
**Solution**:
```bash
# Check disk usage
du -h bin/

# Remove unused versions
./kubectl-manager.py versions installed
# Remove manually:
rm bin/kubectl-1.28.0  # etc.

# Keep only versions actually used by clusters
./kubectl-manager.py clusters list
```

## Debug Mode and Logging

### Enable Verbose Output
```bash
# Run with Python for more detailed errors
python3 -u ./kubectl-manager.py status

# Check Python stack traces
python3 -c "import traceback; traceback.print_exc()"
```

### Manual Testing
```bash
# Test GitHub API access
curl -s https://api.github.com/repos/kubernetes/kubernetes/releases | head

# Test kubectl download URL
curl -I https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl

# Test kubectl execution
./bin/kubectl-1.30.0 version --client

# Test kubeconfig
kubectl --kubeconfig=configs/cluster.yaml cluster-info
```

### Configuration Inspection
```bash
# View current configuration
cat .kubectl-manager/config.json | python3 -m json.tool

# Check file permissions
ls -la configs/ bin/ .kubectl-manager/

# Verify directory structure
find . -type d -name ".kubectl-manager" -o -name "bin" -o -name "configs"
```

## Getting Help

### Diagnostic Information to Collect
When reporting issues, include:

```bash
# System information
uname -a
python3 --version
pip3 list | grep requests

# kubectl-manager information
./kubectl-manager.py --help
./kubectl-manager.py status
./kubectl-manager.py clusters list
./kubectl-manager.py versions installed

# Configuration
cat .kubectl-manager/config.json | python3 -m json.tool

# Directory structure
ls -la
ls -la bin/ configs/ .kubectl-manager/

# Error messages (run with python for full traceback)
python3 ./kubectl-manager.py <failing-command>
```

### Common Error Messages and Meanings

| Error Message | Meaning | Solution |
|---------------|---------|----------|
| `urllib.error.URLError` | Network connectivity issue | Check internet connection, proxy settings |
| `json.JSONDecodeError` | Invalid JSON in config or API response | Reset configuration or check network |
| `FileNotFoundError` | Missing file (binary, config, etc.) | Re-download or re-add missing resources |
| `PermissionError` | File permission issues | Fix file permissions with `chmod` |
| `subprocess.CalledProcessError` | kubectl command failed | Check kubectl binary and kubeconfig |
| `KeyError` in config | Missing configuration keys | Reset configuration |
| `ConnectionRefusedError` | Cluster unreachable | Check cluster connectivity and kubeconfig |

### Reset Everything (Nuclear Option)
If all else fails, completely reset:
```bash
# Backup first (optional)
tar -czf kubectl-manager-backup.tar.gz .kubectl-manager/ configs/ bin/

# Complete reset
rm -rf .kubectl-manager/ configs/ bin/ kubectl

# Start fresh
./kubectl-manager.py
```

---

For additional help, check the [README.md](README.md) and [USER_MANUAL.md](USER_MANUAL.md),
or create an issue with the diagnostic information above.
