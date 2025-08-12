# kubectl-manager Project Memory

## Project Overview
A security-hardened tool for managing multiple kubectl versions and Kubernetes cluster configurations with automatic version detection and compatibility checking.

## Build & Test Commands
- `python3 kubectl-manager.py --help` - Test basic functionality and show help
- `python3 kubectl-manager.py` - Run interactive mode
- `python3 kubectl-manager.py diagnose` - Run comprehensive security diagnostics
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
- **Command injection prevention** - Sanitize all arguments passed to subprocess with flag-aware validation
- **Path traversal protection** - Block dangerous file paths (../, /etc/, etc.) with safe directory restrictions
- **Secure downloads** - Use TLS 1.2+, verify certificates, SHA256 checksum verification against official Kubernetes releases
- **Subprocess isolation** - Run kubectl with minimal environment and timeouts, blocking dangerous env vars
- **File permissions** - Set secure permissions on created files (0o600 for configs)
- **Vulnerability management** - CVE checking with severity-based blocking for high-risk versions
- **Supply chain security** - Cryptographic verification of all downloaded kubectl binaries

## Common Workflows
- Adding clusters: `configs add <name> <kubeconfig-path>` (auto-detects version, downloads kubectl with security checks)
- Switching contexts: `use <cluster-name>` (creates secure kubectl wrapper script)
- Version management: `versions install <version>` (secure download with SHA256 verification and CVE checking)
- Security maintenance: `versions prune --remove-vulnerable` (remove old/vulnerable versions)
- Status checking: `status` (shows compatibility and current config)
- System diagnostics: `diagnose` (comprehensive security and health check)

## Testing Approach
- Test with various cluster versions (1.28.x - 1.32.x)
- Verify security input validation with malicious inputs and path traversal attempts
- Test cross-platform compatibility (Linux, macOS, Windows)
- Validate SSL/TLS security during downloads
- Test SHA256 verification against official Kubernetes checksums
- Verify CVE database integration and vulnerability blocking
- Test secure environment isolation and dangerous variable blocking
- Validate wrapper modes and path safety restrictions

## Important Notes
- Never commit secrets or kubeconfig credentials
- Always maintain backward compatibility for config.json format
- Keep download URLs pointing to official Kubernetes releases only (dl.k8s.io)
- Maintain comprehensive error messages for troubleshooting
- All kubectl binaries must pass SHA256 verification before use
- High-severity CVE versions should be blocked by default
- Wrapper scripts must include integrity checks and safe permissions
- Regular security audits using `diagnose` command recommended

## Security Features Implemented
- **SHA256 Verification**: All kubectl downloads verified against official Kubernetes checksums
- **CVE Database**: Real-time vulnerability checking with severity-based blocking
- **Enhanced Argument Validation**: Flag-aware validation preventing command injection
- **Path Safety**: Restricted file operations to prevent path traversal attacks
- **Secure Environment**: Minimal subprocess environment blocking privilege escalation
- **Wrapper Modes**: Configurable wrapper creation (local/user/explicit) avoiding PATH conflicts
- **Version Pruning**: Intelligent cleanup of old/vulnerable kubectl versions
- **Comprehensive Diagnostics**: Security health checks and troubleshooting