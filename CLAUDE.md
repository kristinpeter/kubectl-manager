# kubectl-manager Project Memory

## Project Overview
A security-hardened tool for managing multiple kubectl versions and Kubernetes cluster configurations with automatic version detection and compatibility checking.

## Build & Test Commands
- `python3 kubectl-manager.py --help` - Test basic functionality and show help
- `python3 kubectl-manager.py` - Run interactive mode
- `./install.sh` - Run installer and setup completion
- `shellcheck *.sh` - Lint all shell scripts
- `python3 -m py_compile kubectl-manager.py` - Check Python syntax
- `python3 -m pylint kubectl-manager.py` - Code quality check (if pylint available)

## Code Style & Standards
- **Security-first approach** - Always validate and sanitize all user inputs
- **Comprehensive error handling** - Provide user-friendly error messages with actionable advice
- **User experience** - Use emojis in output for better visual feedback (✅ ❌ 🔍 📦 🚀)
- **Python style** - Follow PEP 8, use type hints where helpful
- **Documentation** - All functions should have clear docstrings
- **Defensive programming** - Assume inputs are malicious, validate everything

## Architecture & Design Patterns
- **Single-file design** - Keep main functionality in kubectl-manager.py for portability
- **Directory structure**:
  - `bin/` - Downloaded kubectl binaries (kubectl-X.X.X)
  - `configs/` - Imported kubeconfig files (cluster-name.yaml)
  - `.kubectl-manager/` - Tool metadata and cache
- **Configuration** - JSON-based config in `.kubectl-manager/config.json`
- **Version management** - Semantic version sorting with pre-release handling
- **Security layers** - Input validation, secure downloads, process isolation

## Security Requirements (Critical)
- **Input validation** - All user inputs must be validated before use
- **Command injection prevention** - Sanitize all arguments passed to subprocess
- **Path traversal protection** - Block dangerous file paths (../, /etc/, etc.)
- **Secure downloads** - Use TLS 1.2+, verify certificates, check file integrity
- **Subprocess isolation** - Run kubectl with minimal environment and timeouts
- **File permissions** - Set secure permissions on created files (0o600 for configs)

## Common Workflows
- Adding clusters: `configs add <name> <kubeconfig-path>` (auto-detects version, downloads kubectl)
- Switching contexts: `use <cluster-name>` (creates kubectl wrapper script)
- Version management: `versions install <version>` (secure download with validation)
- Status checking: `status` (shows compatibility and current config)

## Testing Approach
- Test with various cluster versions (1.28.x - 1.32.x)
- Verify security input validation with malicious inputs
- Test cross-platform compatibility (Linux, macOS, Windows)
- Validate SSL/TLS security during downloads

## Important Notes
- Never commit secrets or kubeconfig credentials
- Always maintain backward compatibility for config.json format
- Keep download URLs pointing to official Kubernetes releases only
- Maintain comprehensive error messages for troubleshooting