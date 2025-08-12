# kubectl-manager Project Memory

## Project Overview
A security-hardened tool for managing multiple kubectl versions and Kubernetes cluster configurations with automatic version detection and compatibility checking.

## Build & Test Commands
- `python3 kubectl-manager.py --help` - Test basic functionality and show help
- `python3 kubectl-manager.py` - Run interactive mode
- `python3 kubectl-manager.py diagnose` - Run comprehensive security diagnostics
- `./install.sh` - Run installer and setup completion

## Comprehensive Testing (Containerized)
- `./run_optimized_tests.sh all` - Run complete test suite in Podman container
- `./run_optimized_tests.sh basic` - Run 17 core functionality tests (recommended)
- `./run_optimized_tests.sh security` - Security analysis with bandit
- `./run_optimized_tests.sh performance` - Performance benchmarks
- `python3 -m pytest test_basic.py -v` - Direct test execution

## Code Quality & Analysis
- `shellcheck *.sh` - Lint all shell scripts
- `python3 -m py_compile kubectl-manager.py` - Check Python syntax
- `black kubectl-manager.py` - Format code to PEP 8 standards
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

## Testing Approach & Results
### Test Coverage (17/17 tests passing ✅)
- **Core functionality**: Manager initialization, directory creation, configuration loading
- **Security validation**: Input sanitization, path traversal protection, command injection prevention
- **Version management**: Semantic sorting, validation, CVE checking
- **Platform compatibility**: Linux, macOS, Windows detection and binary selection
- **SSL/TLS security**: Secure context creation, certificate verification, TLS 1.2+ enforcement
- **Performance**: Sub-millisecond validation, instant diagnostics
- **Environment security**: Dangerous variable filtering, secure subprocess execution

### Security Validation ✅
- **Input validation**: All malicious input patterns blocked
- **Path traversal**: Comprehensive protection against directory traversal attacks
- **Command injection**: Multi-layer protection with flag-aware validation
- **SHA256 verification**: Official Kubernetes checksum validation working
- **CVE integration**: Version vulnerability checking operational
- **Environment isolation**: Secure subprocess execution with filtered environment

### Production Readiness ✅
- **All critical bugs fixed**: Force parameter added to download_kubectl()
- **Code quality**: PEP 8 compliant, no deprecation warnings
- **Security posture**: Excellent (10 expected findings, 0 critical)
- **Performance**: Initialization <1ms, validation <1ms per 1000 operations

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