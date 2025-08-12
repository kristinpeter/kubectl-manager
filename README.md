# kubectl Manager

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)](https://github.com/kristinpeter/kubectl-manager)

A security-hardened command-line tool for managing multiple kubectl versions and Kubernetes cluster
configurations with automatic version detection, compatibility checking, and zero-setup direct kubectl usage.

## 🚀 Features

- **🔄 Multi-version kubectl management** - Install and use multiple kubectl versions simultaneously
- **🎯 Automatic cluster version detection** - Auto-detects Kubernetes cluster versions from kubeconfig
- **⚡ Smart compatibility matching** - Automatically pairs clusters with optimal kubectl versions
- **📦 Auto-download functionality** - Downloads compatible kubectl when needed
- **🔀 Easy switching** - Switch between different kubectl versions and clusters with one command
- **🖥️ Interactive & CLI modes** - Both menu-driven and command-line interfaces
- **🌍 Cross-platform support** - Works on Linux, macOS, and Windows
- **⌨️ Bash completion** - Full tab completion support
- **🎯 Zero-setup kubectl usage** - Direct `./kubectl` usage without manual configuration
- **🔒 Security hardened** - SHA256 verification, CVE checking, and secure subprocess isolation
- **🛡️ Supply chain security** - Cryptographic verification of all downloaded kubectl binaries
- **🔍 Vulnerability management** - Real-time CVE checking with severity-based blocking
- **🧹 Intelligent cleanup** - Automated pruning of old and vulnerable kubectl versions
- **🩺 System diagnostics** - Comprehensive security and health monitoring

## 📥 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/kristinpeter/kubectl-manager.git
cd kubectl-manager

# Run the installer (sets up completion and creates first directories)
./install.sh

# Start using immediately
./kubectl-manager.py
```

### Manual Install

```bash
# Clone and make executable
git clone https://github.com/kristinpeter/kubectl-manager.git
cd kubectl-manager
chmod +x kubectl-manager.py

# Install Python dependency
pip3 install requests

# Optional: Setup bash completion
./setup-completion.sh
```

## ⚡ Quick Start

### 1. Import Your First Cluster
```bash
# Import kubeconfig (auto-detects cluster version and downloads compatible kubectl)
./kubectl-manager.py configs add production ~/.kube/config
```

### 2. Start Using kubectl
```bash
# Switch to cluster (kubectl is now ready to use directly)
./kubectl-manager.py use production

# Use kubectl directly - no extra setup needed!
./kubectl get pods
./kubectl get nodes
./kubectl apply -f deployment.yaml
```

### 3. Manage Multiple Clusters
```bash
# Add more clusters
./kubectl-manager.py configs add staging ~/.kube/staging.yaml
./kubectl-manager.py configs add development ~/.kube/dev.yaml

# Switch between them instantly
./kubectl-manager.py use staging    # Auto-selects kubectl v1.31.0
./kubectl get pods                  # Uses staging cluster

./kubectl-manager.py use production # Auto-selects kubectl v1.30.0  
./kubectl get pods                  # Uses production cluster
```

## 📋 Command Reference

### Core Commands
```bash
./kubectl-manager.py                       # Interactive mode (beginner-friendly)
./kubectl-manager.py status                # Show current configuration
./kubectl-manager.py help                  # Comprehensive help with examples
```

### Cluster Management
```bash
./kubectl-manager.py configs add <name> <kubeconfig-path>  # Import cluster
./kubectl-manager.py clusters list                         # List all clusters
./kubectl-manager.py use <cluster-name>                    # Switch to cluster
./kubectl-manager.py use <cluster> --kubectl 1.30.0       # Override kubectl version
```

### Version Management
```bash
./kubectl-manager.py versions list         # Browse available kubectl versions
./kubectl-manager.py versions installed    # Show installed versions
./kubectl-manager.py versions install 1.31.0  # Install specific version
```

### kubectl Usage
```bash
./kubectl-manager.py run get pods          # Run through manager
./kubectl get pods                         # Direct usage (after 'use' command)
```

## 🎯 Key Benefits

### Perfect Compatibility
- **Automatic Detection**: Connects to your cluster and detects Kubernetes version
- **Smart Matching**: Downloads the optimal kubectl version (same minor version)
- **Zero Version Skew**: Eliminates kubectl/cluster compatibility issues

### Zero-Setup kubectl Usage
```bash
./kubectl-manager.py use my-cluster        # One-time switch
./kubectl get pods                         # Works immediately!
./kubectl apply -f app.yaml                # No --kubeconfig needed
./kubectl logs deployment/app              # All kubectl commands work
```

### Multi-Cluster Workflow
```bash
# Morning: Check production
./kubectl-manager.py use prod && ./kubectl get pods --all-namespaces

# Deploy to staging
./kubectl-manager.py use staging && ./kubectl apply -f release.yaml

# Debug development
./kubectl-manager.py use dev && ./kubectl logs -f deployment/api
```

## 🔧 Advanced Usage

### Bash Completion
```bash
# Setup completion (included in install.sh)
./setup-completion.sh

# Use tab completion
./kubectl-manager.py <TAB><TAB>            # Shows all commands
./kubectl-manager.py use <TAB><TAB>        # Shows your clusters
./kubectl-manager.py run get <TAB><TAB>    # Shows kubectl resources
```

### Aliases (Auto-created by install.sh)
```bash
km status                                  # Short alias
kubectl-manager clusters list             # Full alias
```

### Compatibility Matrix
The tool automatically handles kubectl/cluster compatibility:

| Cluster Version | Compatible kubectl | Recommended |
|---|---|---|
| v1.28.x | 1.27.x, 1.28.x, 1.29.x | **1.28.x** ⭐ |
| v1.29.x | 1.28.x, 1.29.x, 1.30.x | **1.29.x** ⭐ |
| v1.30.x | 1.29.x, 1.30.x, 1.31.x | **1.30.x** ⭐ |
| v1.31.x | 1.30.x, 1.31.x, 1.32.x | **1.31.x** ⭐ |

## 📁 Directory Structure

After first use, kubectl-manager creates:
```
kubectl-manager/
├── kubectl-manager.py          # Main script
├── bin/                       # kubectl binaries (auto-created)
│   ├── kubectl-1.30.0
│   └── kubectl-1.31.0
├── configs/                   # kubeconfig files (auto-created)
│   ├── production.yaml
│   └── staging.yaml
├── .kubectl-manager/          # Tool metadata (auto-created)
│   └── config.json
└── kubectl                    # Smart wrapper (auto-created)
```

## 🔍 Examples

### Import and Auto-Setup
```bash
$ ./kubectl-manager.py configs add my-cluster ~/my-cluster.yaml
🔍 Importing cluster configuration 'my-cluster'...
📡 Connecting to detect cluster version...
✅ Cluster version detected: v1.31.2
💡 Recommended kubectl version: v1.31.8
📦 kubectl v1.31.8 not found locally
🚀 Installing kubectl v1.31.8...
████████████████████████████████ 100%
✅ kubectl v1.31.8 installed successfully
✅ Cluster 'my-cluster' added successfully
🎯 Paired with kubectl v1.31.8
```

### Status Overview
```bash
$ ./kubectl-manager.py status
┌─ Current Configuration ────────────────────────────────────┐
│ kubectl: v1.31.8 ✅                                       │
│ Cluster: my-cluster (v1.31.2) ✅                          │
│ Compatibility: Perfect match ⭐                            │
└────────────────────────────────────────────────────────────┘
```

### Cluster Overview
```bash
$ ./kubectl-manager.py clusters list
┌─ Installed Clusters ────────────────────────────────────────┐
│ 🟢 production    v1.30.8    kubectl v1.30.15  ✅ Ready     │
│ 🟢 staging       v1.31.2    kubectl v1.31.8   ✅ Ready     │
│ 🟢 development   v1.32.1    kubectl v1.32.3   ✅ Ready     │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Security Features

kubectl-manager implements comprehensive security measures to protect your system:

### Input Validation & Sanitization
- **Command injection prevention** - All kubectl arguments are validated and sanitized
- **Path traversal protection** - Blocks malicious file paths and directory traversal
- **Argument length limits** - Prevents buffer overflow attacks
- **Command whitelist** - Only allows legitimate kubectl subcommands

### Secure Downloads
- **TLS 1.2+ enforcement** - Modern encryption standards required
- **Certificate verification** - Full SSL/TLS certificate validation
- **File integrity checks** - Downloaded binaries are verified for size and format
- **Secure cipher suites** - Strong encryption algorithms only

### Process Security
- **Subprocess isolation** - kubectl runs in restricted environment
- **Timeout protection** - Prevents hanging processes
- **Environment sanitization** - Minimal environment variables passed

### Security Testing & Validation ✅
**17/17 tests passing** - Comprehensive test suite validates:
- **Input sanitization** - Command injection prevention, malicious input blocking
- **Path traversal protection** - Directory traversal attack prevention
- **Environment security** - Secure subprocess execution with variable filtering
- **SSL/TLS validation** - Certificate verification, TLS 1.2+ enforcement
- **Cryptographic verification** - SHA256 checksum validation against official K8s releases
- **Performance** - Sub-millisecond validation, instant diagnostics

**Quick Test**: `./run_optimized_tests.sh basic` (requires Podman)
**Full Suite**: `./run_optimized_tests.sh all`

## 🛠️ Requirements

- **Python 3.6+**
- **Internet connection** (for downloading kubectl versions)
- **kubectl** (for cluster version detection - can be any version)
- **requests** library (`pip install requests`)

## 📖 Documentation

- **[User Manual](USER_MANUAL.md)** - Comprehensive usage guide
- **[Installation Guide](INSTALL.md)** - Detailed installation instructions  
- **[Quick Reference](QUICK_REFERENCE.md)** - Command cheat sheet
- **[Troubleshooting](TROUBLESHOOTING.md)** - Common issues and solutions

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/kristinpeter/kubectl-manager.git
cd kubectl-manager
pip3 install requests
./kubectl-manager.py --help
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⭐ Support

- **🐛 Issues**: [Report bugs](https://github.com/kristinpeter/kubectl-manager/issues)
- **💡 Feature requests**: [Request features](https://github.com/kristinpeter/kubectl-manager/issues)
- **📖 Documentation**: Check the [docs](https://github.com/kristinpeter/kubectl-manager#documentation) section
- **💬 Discussions**: [GitHub Discussions](https://github.com/kristinpeter/kubectl-manager/discussions)

## 🎉 Why kubectl Manager?

**Before kubectl Manager:**
```bash
# Manual kubectl version management
curl -LO https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl
chmod +x kubectl && sudo mv kubectl /usr/local/bin/kubectl-1.30.0

# Manual kubeconfig management  
kubectl --kubeconfig=~/.kube/prod-config get pods
kubectl --kubeconfig=~/.kube/staging-config get pods

# Manual compatibility tracking
# "Does kubectl 1.28 work with my 1.30 cluster?" 🤔
```

**With kubectl Manager:**
```bash
# Automatic everything
./kubectl-manager.py configs add prod ~/.kube/prod-config     # Auto-detects, downloads, configures
./kubectl-manager.py use prod                                 # Switch to production  
./kubectl get pods                                            # Just works! ✨
```

---

**⚡ Get started in 30 seconds:**
```bash
git clone https://github.com/kristinpeter/kubectl-manager.git && cd kubectl-manager && ./install.sh
```
