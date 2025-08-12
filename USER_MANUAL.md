# kubectl Manager - User Manual

Complete guide to using kubectl Manager for managing multiple kubectl versions and Kubernetes clusters.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Interactive Mode Guide](#interactive-mode-guide)
3. [Command Line Usage](#command-line-usage)
4. [Workflow Examples](#workflow-examples)
5. [Advanced Features](#advanced-features)
6. [Best Practices](#best-practices)

## Getting Started

### Initial Setup
```bash
# 1. Make script executable
chmod +x kubectl-manager.py

# 2. Install Python dependencies
pip install requests

# 3. Run for first time (creates directory structure)
./kubectl-manager.py
```

The tool automatically creates the following directory structure:
```
your-directory/
├── kubectl-manager.py     # Main script
├── bin/                  # kubectl binaries (auto-created)
├── configs/              # kubeconfig files (auto-created)
├── .kubectl-manager/     # Tool metadata (auto-created)
└── kubectl              # Symlink to active kubectl (auto-created)
```

## Interactive Mode Guide

### Main Menu
```bash
./kubectl-manager.py
```

```
┌─ kubectl Manager ─────────────────────┐
│ Current: kubectl v1.30.0 → production │  
│                                       │
│ 1. Manage kubectl versions            │
│ 2. Manage cluster configs            │
│ 3. Switch version + config           │
│ 4. Run kubectl command               │
│ 5. Status & health check             │
│ 6. Exit                              │
└───────────────────────────────────────┘
```

### Menu Option 1: Manage kubectl Versions
- **List available versions** - Shows latest kubectl versions from GitHub
- **List installed versions** - Shows locally downloaded kubectl binaries
- **Install version** - Downloads and installs specific kubectl version

Example flow:
```
Select option [1-6]: 1

--- kubectl Versions ---
1. List available versions
2. List installed versions  
3. Install version
4. Back to main menu

Select option [1-4]: 1

📋 Latest available kubectl versions:
  1. v1.32.0
  2. v1.31.8
  3. v1.30.15
  [... more versions]

Select option [1-4]: 3
Enter version to install (e.g., 1.29.0): 1.31.8

📥 Downloading kubectl v1.31.8 for linux/amd64...
████████████████████████████████ 100% (45.2MB/45.2MB)
✅ kubectl v1.31.8 installed successfully
```

### Menu Option 2: Manage Cluster Configs
- **List clusters** - Shows all imported clusters with compatibility status
- **Add cluster** - Import new kubeconfig with automatic setup
- **Remove cluster** - Delete cluster configuration

Example flow:
```
Select option [1-6]: 2

--- Cluster Configs ---
1. List clusters
2. Add cluster
3. Remove cluster
4. Back to main menu

Select option [1-4]: 2
Cluster name: staging
Kubeconfig path: ~/Downloads/staging-cluster.yaml

🔍 Importing cluster configuration 'staging'...
📡 Connecting to detect cluster version...
✅ Cluster version detected: v1.31.2
💡 Recommended kubectl version: v1.31.8
✅ kubectl v1.31.8 already installed
✅ Cluster 'staging' added successfully
🎯 Paired with kubectl v1.31.8
🚀 Ready to use: ./kubectl-manager.py use staging
```

### Menu Option 3: Switch Version + Config
Quick switching between configured clusters:

```
Select option [1-6]: 3

--- Switch Configuration ---
Available clusters:
  1. production (kubectl v1.30.15)
  2. staging (kubectl v1.31.8)  
  3. development (kubectl v1.32.0)

Select cluster number: 2
✅ Switched to kubectl v1.31.8 → staging
```

### Menu Option 4: Run kubectl Command
Execute kubectl commands with active configuration:

```
Select option [1-6]: 4
Enter kubectl command (without 'kubectl'): get pods

NAME                   READY   STATUS    RESTARTS   AGE
nginx-deployment-abc   1/1     Running   0          2d
api-server-def         2/2     Running   1          1d
```

### Menu Option 5: Status & Health Check
Shows current configuration and compatibility:

```
Select option [1-6]: 5

┌─ Current Configuration ────────────────────────────────────┐
│ kubectl: v1.31.8 ✅                                       │
│ Cluster: staging (v1.31.2) ✅                             │
│ Compatibility: Perfect match ⭐                            │
└────────────────────────────────────────────────────────────┘
```

## Command Line Usage

### Quick Commands
```bash
# Show current status
./kubectl-manager.py status

# Switch to cluster (auto-selects optimal kubectl)
./kubectl-manager.py use production

# Run kubectl commands
./kubectl-manager.py run get pods
./kubectl-manager.py run apply -f deployment.yaml

# Install kubectl version
./kubectl-manager.py versions install 1.30.0

# Add cluster
./kubectl-manager.py configs add dev ~/kubeconfigs/dev.yaml

# List everything
./kubectl-manager.py versions installed
./kubectl-manager.py clusters list
```

### Full Command Reference

#### Version Management
```bash
./kubectl-manager.py versions list                    # Available versions online
./kubectl-manager.py versions installed               # Local versions  
./kubectl-manager.py versions install 1.29.0          # Install version
```

#### Cluster Management
```bash
./kubectl-manager.py configs list                     # List clusters
./kubectl-manager.py configs add <name> <path>        # Add cluster
./kubectl-manager.py clusters list                    # Alias for configs list
```

#### Usage Commands
```bash  
./kubectl-manager.py use <cluster-name>               # Switch to cluster
./kubectl-manager.py use <cluster> --kubectl <version> # Override kubectl version
./kubectl-manager.py run <kubectl-args>               # Run kubectl command
./kubectl-manager.py status                           # Show current config
```

## Workflow Examples

### Scenario 1: New Team Member Setup
```bash
# 1. Get kubectl-manager
git clone <repo> && cd kubectl-manager
chmod +x kubectl-manager.py

# 2. Add company clusters
./kubectl-manager.py configs add production ~/company/prod.yaml
./kubectl-manager.py configs add staging ~/company/staging.yaml  
./kubectl-manager.py configs add development ~/company/dev.yaml

# Each import automatically:
# - Detects cluster Kubernetes version
# - Downloads optimal kubectl version
# - Sets up ready-to-use configuration

# 3. Start working
./kubectl-manager.py use production
./kubectl-manager.py run get nodes
```

### Scenario 2: Managing Multiple Client Clusters
```bash
# Add client clusters with different Kubernetes versions
./kubectl-manager.py configs add client-a ~/clients/client-a.yaml
# ✅ Cluster version: v1.28.5 → kubectl v1.28.12 (auto-downloaded)

./kubectl-manager.py configs add client-b ~/clients/client-b.yaml  
# ✅ Cluster version: v1.30.8 → kubectl v1.30.15 (auto-downloaded)

./kubectl-manager.py configs add client-c ~/clients/client-c.yaml
# ✅ Cluster version: v1.31.2 → kubectl v1.31.8 (auto-downloaded)

# Switch between clients seamlessly
./kubectl-manager.py use client-a
./kubectl-manager.py run get pods -n kube-system

./kubectl-manager.py use client-b  
./kubectl-manager.py run describe deployment app

# Check compatibility overview
./kubectl-manager.py clusters list
# ┌─ Installed Clusters ────────────────────────────────────────┐
# │ 🟢 client-a      v1.28.5    kubectl v1.28.12  ✅ Ready     │
# │ 🟢 client-b      v1.30.8    kubectl v1.30.15  ✅ Ready     │  
# │ 🟢 client-c      v1.31.2    kubectl v1.31.8   ✅ Ready     │
# └─────────────────────────────────────────────────────────────┘
```

### Scenario 3: Development Workflow
```bash
# Morning routine - check all environments
./kubectl-manager.py use production && ./kubectl-manager.py run get pods --all-namespaces | grep -v Running
./kubectl-manager.py use staging && ./kubectl-manager.py run get pods -n staging | head
./kubectl-manager.py use development && ./kubectl-manager.py run get events --sort-by='.lastTimestamp'

# Deploy to staging
./kubectl-manager.py use staging
./kubectl-manager.py run apply -f k8s/staging/
./kubectl-manager.py run rollout status deployment/api

# Test in development  
./kubectl-manager.py use development
./kubectl-manager.py run port-forward service/api 8080:80 &
# Test application...
./kubectl-manager.py run logs -f deployment/api

# Quick status check
./kubectl-manager.py status
```

### Scenario 4: Cluster Upgrade Workflow
```bash
# Before upgrade - document current setup
./kubectl-manager.py clusters list > cluster-status-before.txt

# After cluster upgrade to v1.32.x
./kubectl-manager.py configs add production-new ~/new-prod-config.yaml
# 📡 Connecting to detect cluster version...
# ✅ Cluster version detected: v1.32.1
# 💡 Recommended kubectl version: v1.32.3
# 📦 kubectl v1.32.3 not found locally
# 🚀 Installing kubectl v1.32.3... ✅

# Test new configuration
./kubectl-manager.py use production-new
./kubectl-manager.py run get nodes
./kubectl-manager.py run cluster-info

# Switch traffic when ready
./kubectl-manager.py configs remove production-old
```

## Advanced Features

### Automatic Version Detection
When adding a cluster, the tool:
1. **Connects to cluster** using provided kubeconfig
2. **Queries Kubernetes version** via `kubectl version --output=json`
3. **Calculates optimal kubectl** following compatibility matrix
4. **Downloads if needed** and pairs cluster with kubectl version

```bash
./kubectl-manager.py configs add example ~/example.yaml

# Behind the scenes:
# 1. Parse kubeconfig → Extract server URL, auth
# 2. Connect: kubectl --kubeconfig=temp.yaml version --output=json
# 3. Extract: serverVersion.gitVersion = "v1.30.8"  
# 4. Calculate: optimal = "1.30.15" (latest patch in 1.30.x)
# 5. Download: kubectl-1.30.15 if not exists
# 6. Pair: example cluster → kubectl-1.30.15
```

### Smart Compatibility Matrix
```
Cluster Version    Compatible kubectl Versions    Recommended
v1.28.x           1.27.x, 1.28.x, 1.29.x        1.28.latest ⭐
v1.29.x           1.28.x, 1.29.x, 1.30.x        1.29.latest ⭐  
v1.30.x           1.29.x, 1.30.x, 1.31.x        1.30.latest ⭐
v1.31.x           1.30.x, 1.31.x, 1.32.x        1.31.latest ⭐
```

### Override Auto-Selection
```bash
# Use different kubectl version than recommended
./kubectl-manager.py use production --kubectl 1.29.0
# ⚠️  Warning: kubectl v1.29.0 with cluster v1.30.8 (version skew)
# Continue? [y/N]: y
# ✅ Switched to kubectl v1.29.0 → production
```

### Multi-Context Support
If kubeconfig has multiple contexts, they're all preserved:
```bash
./kubectl-manager.py configs add multi-env ~/multi-context.yaml
# Imports entire kubeconfig with all contexts intact

./kubectl-manager.py use multi-env
./kubectl-manager.py run config get-contexts
./kubectl-manager.py run config use-context different-env
```

### Platform Support
Automatically detects platform and downloads correct binary:
- **Linux**: amd64, arm64
- **macOS**: amd64, arm64 (Apple Silicon)  
- **Windows**: amd64

```bash
# On Apple Silicon Mac:
./kubectl-manager.py versions install 1.30.0
# 📥 Downloading kubectl v1.30.0 for darwin/arm64...

# On Linux x86_64:  
./kubectl-manager.py versions install 1.30.0
# 📥 Downloading kubectl v1.30.0 for linux/amd64...
```

## Best Practices

### 1. Organize by Environment/Client
```bash
# Use clear, descriptive cluster names
./kubectl-manager.py configs add prod-east ~/k8s/production-east.yaml
./kubectl-manager.py configs add prod-west ~/k8s/production-west.yaml
./kubectl-manager.py configs add staging-v2 ~/k8s/staging-v2.yaml

# Not recommended: cryptic names
./kubectl-manager.py configs add k8s1 ~/k8s1.yaml  # unclear
```

### 2. Create Shell Aliases
```bash
# Add to ~/.bashrc or ~/.zshrc
alias km="./kubectl-manager.py"
alias k="./kubectl-manager.py run"

# Usage becomes much shorter:
km use production
k get pods
k apply -f deployment.yaml
```

### 3. Regular Maintenance
```bash
# Weekly: check for kubectl updates
./kubectl-manager.py versions list | head -5

# Monthly: validate cluster connectivity  
./kubectl-manager.py clusters list

# After cluster upgrades: refresh cluster info
./kubectl-manager.py configs add cluster-new ~/updated-config.yaml
./kubectl-manager.py configs remove cluster-old
```

### 4. Team Sharing
```bash
# Export configuration for team sharing
cp -r .kubectl-manager team-kubectl-setup/
tar -czf team-setup.tar.gz team-kubectl-setup/

# Team member setup:
tar -xzf team-setup.tar.gz
cp team-kubectl-setup/.kubectl-manager/* .kubectl-manager/
# Add their own kubeconfigs...
```

### 5. Backup Strategy
```bash
# Backup configurations
tar -czf kubectl-manager-backup-$(date +%Y%m%d).tar.gz \
    .kubectl-manager/ configs/

# Restore if needed
tar -xzf kubectl-manager-backup-20241201.tar.gz
```

### 6. Security Considerations
```bash
# Kubeconfig files contain sensitive authentication data
chmod 600 configs/*.yaml

# Don't commit kubeconfigs to version control
echo "configs/" >> .gitignore
echo ".kubectl-manager/" >> .gitignore

# Use separate kubeconfigs for different environments
# Don't mix production and development in same file
```

---

This user manual covers all essential kubectl-manager functionality. For additional help, run `./kubectl-manager.py --help` or check the troubleshooting section in README.md.