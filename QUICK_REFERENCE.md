# kubectl Manager - Quick Reference

## 🚀 Quick Start
```bash
# 1. Setup completion (optional)
./setup-completion.sh

# 2. Import your first cluster
./kubectl-manager.py configs add mycluster ~/.kube/config

# 3. Use the cluster (auto-downloads compatible kubectl)
./kubectl-manager.py use mycluster

# 4. Use kubectl directly
./kubectl get pods
```

## 📋 Essential Commands

| Command | Description |
|---------|-------------|
| `./kubectl-manager.py` | Interactive menu (beginner-friendly) |
| `./kubectl-manager.py help` | Detailed help with examples |
| `./kubectl-manager.py status` | Show current configuration |

## 🔧 Cluster Management

| Command | Description |
|---------|-------------|
| `configs add <name> <path>` | Import kubeconfig file |
| `clusters list` | List all imported clusters |
| `use <cluster>` | Switch to cluster (auto kubectl version) |
| `use <cluster> --kubectl 1.30.0` | Switch with specific kubectl version |

## 📦 Version Management  

| Command | Description |
|---------|-------------|
| `versions list` | Browse available kubectl versions |
| `versions installed` | Show locally installed versions |
| `versions install 1.31.0` | Install specific kubectl version |

## ⚡ Quick Usage

| Command | Description |
|---------|-------------|
| `run get pods` | Run kubectl through manager |
| `./kubectl get pods` | Direct kubectl (after `use` command) |

## 🎯 Aliases (after setup-completion.sh)

| Alias | Same As |
|-------|---------|
| `km` | `./kubectl-manager.py` |
| `kubectl-manager` | `./kubectl-manager.py` |

## 💡 Pro Tips

1. **Tab Completion**: Use `<TAB><TAB>` for command completion
2. **Status Check**: Run `status` to see current cluster + kubectl version  
3. **Perfect Match**: Tool auto-selects optimal kubectl version for each cluster
4. **Zero Setup**: After `use`, kubectl works immediately without extra steps
5. **Multiple Clusters**: Switch between clusters instantly with `use`

## 🔄 Typical Workflow

```bash
# Morning setup
km use production        # Switch to production
./kubectl get pods       # Check production pods

# Deploy to staging  
km use staging          # Switch to staging  
./kubectl apply -f app.yaml

# Debug development
km use dev              # Switch to development
./kubectl logs pod-name

# Check everything is healthy
km status               # Current configuration
km clusters list        # All cluster status
```

## 🆘 Help

| Command | Description |
|---------|-------------|
| `--help` | Built-in command help |
| `help` | Comprehensive help with examples |
| `status` | Current configuration and compatibility |

---
**💡 Tip**: Use tab completion for all commands: `km <TAB><TAB>`