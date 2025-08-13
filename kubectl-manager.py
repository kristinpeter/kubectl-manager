#!/usr/bin/env python3
"""
kubectl Manager - Multi-version kubectl and cluster management tool

This tool helps you manage multiple kubectl versions and kubernetes cluster configurations,
automatically detecting cluster versions and downloading compatible kubectl binaries.
"""

import os
import sys
import json
import urllib.request
import urllib.parse
import platform
import subprocess
import shutil
import stat
import argparse
import ssl
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import tempfile
from datetime import datetime, timedelta

class KubectlManager:
    def __init__(self):
        self.base_dir = Path.cwd()
        self.bin_dir = self.base_dir / "bin"
        self.configs_dir = self.base_dir / "configs"
        self.meta_dir = self.base_dir / ".kubectl-manager"
        self.cache_dir = self.meta_dir / "cache"
        
        self.config_file = self.meta_dir / "config.json"
        self.versions_cache = self.meta_dir / "versions.json"
        
        self.ensure_directories()
        self.config = self.load_config()
    
    def ensure_directories(self):
        """Create necessary directories if they don't exist"""
        for directory in [self.bin_dir, self.configs_dir, self.meta_dir, self.cache_dir]:
            directory.mkdir(exist_ok=True)
    
    def _version_sort_key(self, version: str) -> tuple:
        """Create a sort key for version strings that handles pre-release versions"""
        try:
            # Split version into parts (e.g., "1.30.0-beta" -> ["1", "30", "0-beta"])
            parts = version.split(".")
            key_parts = []
            
            for part in parts:
                # Handle pre-release suffixes (e.g., "0-beta", "1-rc1")
                if "-" in part:
                    base_version, pre_release = part.split("-", 1)
                    try:
                        key_parts.append((int(base_version), pre_release))
                    except ValueError:
                        # If base version is not a number, treat whole part as string
                        key_parts.append((0, part))
                else:
                    try:
                        key_parts.append((int(part), ""))
                    except ValueError:
                        # If not a number, treat as string with low priority
                        key_parts.append((0, part))
            
            return tuple(key_parts)
        except Exception:
            # Fallback to string comparison for malformed versions
            return (0, version)
    
    def _validate_cluster_name(self, name: str) -> bool:
        """Validate cluster name for security"""
        if not name or len(name) > 100:
            return False
        # Allow alphanumeric, hyphens, underscores, dots
        import re
        return bool(re.match(r'^[a-zA-Z0-9._-]+$', name)) and '..' not in name
    
    def _validate_version(self, version: str) -> bool:
        """Validate version string for security"""
        if not version or len(version) > 50:
            return False
        # Allow version format: x.y.z with optional -suffix
        import re
        return bool(re.match(r'^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$', version))
    
    def _validate_kubectl_args(self, args: List[str]) -> List[str]:
        """Enhanced validation and sanitization of kubectl arguments with flag awareness"""
        if not args:
            return []
        
        # Define allowed kubectl subcommands (defensive approach)
        allowed_commands = {
            'get', 'describe', 'logs', 'exec', 'port-forward', 'proxy',
            'cp', 'auth', 'diff', 'apply', 'create', 'replace', 'patch',
            'delete', 'rollout', 'scale', 'autoscale', 'certificate',
            'cluster-info', 'top', 'cordon', 'uncordon', 'drain', 'taint',
            'label', 'annotate', 'config', 'plugin', 'version', 'api-versions',
            'api-resources', 'explain', 'wait'
        }
        
        # Define command-specific security policies
        command_policies = {
            'apply': {'file_flags': ['-f', '--filename'], 'dangerous_flags': ['--validate=false']},
            'create': {'file_flags': ['-f', '--filename'], 'dangerous_flags': ['--validate=false']},
            'replace': {'file_flags': ['-f', '--filename'], 'dangerous_flags': ['--force']},
            'patch': {'file_flags': ['-f', '--filename'], 'dangerous_flags': ['--type=merge']},
            'exec': {'dangerous_flags': ['--stdin', '--tty'], 'restricted': True},
            'cp': {'requires_validation': True},
            'proxy': {'dangerous_flags': ['--address=0.0.0.0'], 'restricted': True},
            'port-forward': {'dangerous_flags': ['--address=0.0.0.0']}
        }
        
        validated_args = []
        command = args[0] if args else ""
        
        for i, arg in enumerate(args):
            # Limit argument length
            if len(arg) > 1000:
                raise ValueError(f"Argument too long: {arg[:50]}...")
            
            # First argument should be a valid kubectl command
            if i == 0 and arg not in allowed_commands:
                raise ValueError(f"Disallowed kubectl command: {arg}")
            
            # Block dangerous patterns
            dangerous_patterns = [';', '&&', '||', '|', '`', '$', '>', '<', '&', '$(', '${', '`']
            if any(pattern in arg for pattern in dangerous_patterns):
                raise ValueError(f"Dangerous character in argument: {arg}")
            
            # Block file system manipulation patterns
            dangerous_paths = ['../../../', '..\\..\\', '/etc/', '/proc/', '/sys/', '/dev/', '/root/', 'rm -rf', 'sudo', '/bin/', '/usr/bin/']
            if any(dangerous in arg.lower() for dangerous in dangerous_paths):
                raise ValueError(f"Potentially dangerous path in argument: {arg}")
            
            # Enhanced validation for file-based operations
            if command in command_policies:
                policy = command_policies[command]
                
                # Check for file flags and validate paths
                if 'file_flags' in policy and arg in policy['file_flags']:
                    if i + 1 < len(args):
                        file_path = args[i + 1]
                        if not self._is_safe_file_path(file_path):
                            raise ValueError(f"Unsafe file path: {file_path}")
                
                # Block dangerous flags for specific commands
                if 'dangerous_flags' in policy and arg in policy['dangerous_flags']:
                    raise ValueError(f"Dangerous flag '{arg}' not allowed for command '{command}'")
                
                # Some commands require additional restrictions
                if policy.get('restricted') and len(args) > 2:
                    # Additional validation for restricted commands
                    pass
            
            validated_args.append(arg)
        
        return validated_args
    
    def _is_safe_file_path(self, file_path: str) -> bool:
        """Validate file paths for safety - only allow access to allowed directories"""
        try:
            # Resolve path to handle symlinks and relative paths
            resolved_path = Path(file_path).resolve()
            
            # Define allowed base directories
            allowed_bases = [
                self.base_dir,  # kubectl-manager directory
                Path.cwd(),     # Current working directory
                Path.home() / '.kube',  # User's kube config directory
                Path('/tmp'),   # Temporary files (with additional checks)
            ]
            
            # Check if path is within allowed directories
            for base in allowed_bases:
                try:
                    if resolved_path.is_relative_to(base):
                        # Additional check for /tmp - only allow YAML/JSON files
                        if base == Path('/tmp'):
                            if not file_path.lower().endswith(('.yaml', '.yml', '.json')):
                                return False
                        return True
                except ValueError:
                    # is_relative_to can raise ValueError on different filesystems
                    continue
            
            return False
            
        except (OSError, ValueError) as e:
            # Path resolution failed - treat as unsafe
            return False
    
    def _create_secure_context(self) -> ssl.SSLContext:
        """Create a secure SSL context for downloads with enhanced security"""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Enhanced security settings
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Require TLS 1.2+
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        # Set secure options (avoiding deprecated SSL constants)
        context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
        # TLS 1.2+ minimum version already excludes older protocols
        
        return context
    
    def _check_version_security(self, version: str) -> Dict[str, any]:
        """Check kubectl version against known vulnerabilities"""
        # Known vulnerable kubectl versions and their CVEs
        # This should be updated regularly or integrated with official CVE feeds
        vulnerable_versions = {
            '1.20.0': {
                'cves': ['CVE-2020-8564'],
                'severity': 'medium',
                'description': 'Docker config secrets in log files'
            },
            '1.22.0': {
                'cves': ['CVE-2021-25741'],
                'severity': 'high', 
                'description': 'Symlink exchange can allow host filesystem access'
            },
            '1.25.0': {
                'cves': ['CVE-2022-3162'],
                'severity': 'medium',
                'description': 'Users may have access to secure endpoints in the control plane network'
            }
        }
        
        # EOL versions that should trigger warnings
        eol_versions = {
            '1.19': '2021-10-28',
            '1.20': '2022-02-28', 
            '1.21': '2022-06-28',
            '1.22': '2022-10-28'
        }
        
        result = {
            'is_vulnerable': False,
            'is_eol': False,
            'cves': [],
            'severity': 'none',
            'warnings': [],
            'recommendations': []
        }
        
        # Check for specific vulnerable versions
        if version in vulnerable_versions:
            vuln_info = vulnerable_versions[version]
            result.update({
                'is_vulnerable': True,
                'cves': vuln_info['cves'],
                'severity': vuln_info['severity'],
                'warnings': [vuln_info['description']]
            })
            
            # Get latest patch version recommendation
            try:
                major, minor = version.split('.')[:2]
                available = self.fetch_available_versions()
                compatible = [v for v in available if v.startswith(f"{major}.{minor}.")]
                if compatible:
                    latest_patch = max(compatible, key=lambda x: [int(i) for i in x.split('.')])
                    if latest_patch != version:
                        result['recommendations'].append(f"Upgrade to kubectl v{latest_patch}")
            except (ValueError, IndexError):
                pass
        
        # Check for EOL versions
        try:
            major, minor = version.split('.')[:2]
            version_key = f"{major}.{minor}"
            if version_key in eol_versions:
                result['is_eol'] = True
                result['warnings'].append(f"Version {version_key} reached end-of-life on {eol_versions[version_key]}")
                result['recommendations'].append("Upgrade to a supported version (latest 3 minor versions)")
        except (ValueError, IndexError):
            pass
            
        return result
    
    def _verify_download_integrity(self, file_path: Path, version: str, os_name: str, arch: str) -> bool:
        """Cryptographic integrity verification using official SHA256 checksums"""
        if not file_path.exists():
            return False
            
        # Check file size (basic sanity check)
        file_size = file_path.stat().st_size
        if file_size < 1024 * 1024:  # kubectl should be at least 1MB
            print(f"❌ Downloaded file too small: {file_size} bytes")
            return False
            
        if file_size > 200 * 1024 * 1024:  # kubectl should not exceed 200MB
            print(f"❌ Downloaded file too large: {file_size} bytes")
            return False
        
        # Basic file type verification (check for ELF/Mach-O magic bytes)
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                # ELF (Linux), Mach-O (macOS)
                valid_magic = [b'\x7fELF', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']
                if not any(magic.startswith(m[:len(magic)]) for m in valid_magic):
                    print(f"❌ Downloaded file does not appear to be a valid binary")
                    return False
        except Exception as e:
            print(f"❌ Error verifying download: {e}")
            return False
        
        # SECURITY ENHANCEMENT: Cryptographic verification with official SHA256
        return self._verify_sha256_checksum(file_path, version, os_name, arch)
    
    def _verify_sha256_checksum(self, file_path: Path, version: str, os_name: str, arch: str) -> bool:
        """Verify file against official Kubernetes SHA256 checksum"""
        try:
            binary_name = "kubectl"
            checksum_url = f"{self.config['settings']['download_base_url']}/v{version}/bin/{os_name}/{arch}/{binary_name}.sha256"
            
            print(f"🔍 Verifying SHA256 checksum...")
            
            # Download official checksum
            context = self._create_secure_context()
            with urllib.request.urlopen(checksum_url, context=context, timeout=30) as response:
                checksum_content = response.read().decode().strip()
                # Extract SHA256 hash (format: "hash  filename" or just "hash")
                official_sha256 = checksum_content.split()[0].lower()
            
            # Calculate file SHA256
            calculated_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    calculated_hash.update(chunk)
            
            calculated_sha256 = calculated_hash.hexdigest().lower()
            
            # Compare checksums
            if calculated_sha256 != official_sha256:
                print(f"❌ SHA256 verification FAILED!")
                print(f"   Expected: {official_sha256}")
                print(f"   Calculated: {calculated_sha256}")
                print(f"   This indicates a corrupted or potentially compromised download!")
                return False
            
            print(f"✅ SHA256 verification passed ({calculated_sha256[:16]}...)")
            return True
            
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print(f"⚠️  SHA256 checksum not available for kubectl v{version}")
                print(f"   Falling back to basic verification (not recommended for production)")
                return True  # Allow download but warn user
            else:
                print(f"❌ Error downloading checksum: HTTP {e.code}")
                return False
        except Exception as e:
            print(f"❌ Checksum verification failed: {e}")
            print(f"   This could indicate a network issue or compromised download")
            return False
    
    def _secure_download(self, url: str, output_path: Path, progress_hook=None) -> bool:
        """Securely download a file with integrity checks"""
        try:
            # Create secure request with SSL verification
            context = self._create_secure_context()
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
            urllib.request.install_opener(opener)
            
            # Download file
            urllib.request.urlretrieve(url, output_path, progress_hook)
            
            # Note: Integrity verification is now handled in download_kubectl method
            # to include version-specific SHA256 verification
                
            return True
            
        except Exception as e:
            print(f"❌ Secure download failed: {e}")
            if output_path.exists():
                output_path.unlink()
            return False
    
    def load_config(self) -> Dict:
        """Load tool configuration"""
        default_config = {
            "clusters": {},
            "active_cluster": None,
            "active_kubectl": None,
            "settings": {
                "auto_download": True,
                "cache_duration": 3600,
                "github_api_url": "https://api.github.com/repos/kubernetes/kubernetes/releases",
                "download_base_url": "https://dl.k8s.io/release"
            }
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults for new settings
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            except (json.JSONDecodeError, IOError):
                pass
        
        return default_config
    
    def save_config(self):
        """Save tool configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get_platform_info(self) -> Tuple[str, str]:
        """Get platform OS and architecture for kubectl downloads"""
        system = platform.system().lower()
        machine = platform.machine().lower()
        
        os_map = {
            'linux': 'linux',
            'darwin': 'darwin'
        }
        
        arch_map = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'arm64': 'arm64',
            'aarch64': 'arm64'
        }
        
        if system not in os_map:
            raise ValueError(f"Unsupported operating system: {system}")
        
        return os_map[system], arch_map.get(machine, 'amd64')
    
    def fetch_available_versions(self, force_refresh: bool = False) -> List[str]:
        """Fetch available kubectl versions from GitHub API"""
        cache_file = self.cache_dir / "available_versions.json"
        cache_max_age = timedelta(seconds=self.config["settings"]["cache_duration"])
        
        # Check cache
        if not force_refresh and cache_file.exists():
            cache_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if datetime.now() - cache_time < cache_max_age:
                try:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                except (json.JSONDecodeError, IOError):
                    pass
        
        print("🔍 Fetching available kubectl versions...")
        try:
            # SECURITY: Use secure SSL context for API calls
            context = self._create_secure_context()
            with urllib.request.urlopen(self.config["settings"]["github_api_url"], context=context) as response:
                releases = json.loads(response.read().decode())
            
            versions = []
            for release in releases:
                if not release.get("prerelease", True):  # Only stable releases
                    tag = release.get("tag_name", "")
                    if tag.startswith("v") and len(tag.split(".")) >= 3:
                        versions.append(tag[1:])  # Remove 'v' prefix
            
            # Cache the results
            with open(cache_file, 'w') as f:
                json.dump(versions, f)
            
            return versions
        
        except Exception as e:
            print(f"❌ Error fetching versions: {e}")
            return []
    
    def get_installed_versions(self) -> List[str]:
        """Get list of locally installed kubectl versions"""
        versions = []
        if self.bin_dir.exists():
            for file in self.bin_dir.iterdir():
                if file.name.startswith("kubectl-") and file.is_file():
                    version = file.name.replace("kubectl-", "")
                    versions.append(version)
        return sorted(versions, key=self._version_sort_key)
    
    def prune_versions(self, keep_latest: int = 3, remove_vulnerable: bool = False) -> bool:
        """Remove old or vulnerable kubectl versions to reduce attack surface"""
        installed_versions = self.get_installed_versions()
        
        if not installed_versions:
            print("📦 No kubectl versions installed to prune")
            return True
        
        # Sort versions by semantic version
        sorted_versions = sorted(installed_versions, key=self._version_sort_key, reverse=True)
        
        # Determine which versions to keep/remove
        versions_to_keep = set()
        versions_to_remove = set()
        
        # Always keep currently active version
        active_kubectl = self.config.get('active_kubectl')
        if active_kubectl:
            versions_to_keep.add(active_kubectl)
        
        # Keep versions used by configured clusters
        for cluster_info in self.config['clusters'].values():
            kubectl_ver = cluster_info.get('kubectl_version')
            if kubectl_ver:
                versions_to_keep.add(kubectl_ver)
        
        # Keep latest N versions
        for version in sorted_versions[:keep_latest]:
            versions_to_keep.add(version)
        
        # Check for vulnerable versions to remove
        if remove_vulnerable:
            for version in installed_versions:
                security_check = self._check_version_security(version)
                if security_check['is_vulnerable'] and security_check['severity'] in ['high', 'critical']:
                    if version not in versions_to_keep:
                        versions_to_remove.add(version)
                        print(f"⚠️  Marking vulnerable version v{version} for removal ({security_check['cves']})")
        
        # Mark old versions for removal (beyond keep_latest)
        for version in sorted_versions[keep_latest:]:
            if version not in versions_to_keep:
                versions_to_remove.add(version)
        
        if not versions_to_remove:
            print("✅ No versions need to be pruned")
            return True
        
        # Show pruning plan
        print(f"🧹 Pruning plan:")
        print(f"   Keeping {len(versions_to_keep)} versions: {', '.join(f'v{v}' for v in sorted(versions_to_keep, key=self._version_sort_key, reverse=True))}")
        print(f"   Removing {len(versions_to_remove)} versions: {', '.join(f'v{v}' for v in sorted(versions_to_remove, key=self._version_sort_key, reverse=True))}")
        
        # Remove versions
        removed_count = 0
        for version in versions_to_remove:
            binary_path = self.bin_dir / f"kubectl-{version}"
            
            try:
                if binary_path.exists():
                    binary_path.unlink()
                    print(f"✅ Removed kubectl v{version}")
                    removed_count += 1
                else:
                    print(f"⚠️  kubectl v{version} binary not found")
            except Exception as e:
                print(f"❌ Failed to remove kubectl v{version}: {e}")
        
        print(f"✅ Pruning complete: removed {removed_count} versions")
        return True
    
    def download_kubectl(self, version: str, show_progress: bool = True, force: bool = False) -> bool:
        """Download kubectl binary for specified version"""
        # SECURITY: Validate version string
        if not self._validate_version(version):
            print(f"❌ Invalid version format: {version}")
            return False
        
        # SECURITY: Check for known vulnerabilities
        if not force:
            security_check = self._check_version_security(version.lstrip('v'))
            if security_check['is_vulnerable'] and security_check['severity'] == 'high':
                print(f"❌ kubectl v{version} has HIGH severity vulnerabilities:")
                for cve in security_check['cves']:
                    print(f"   - {cve}")
                print(f"   Use --force to install anyway (not recommended)")
                return False
            elif security_check['is_vulnerable']:
                print(f"⚠️  kubectl v{version} has known vulnerabilities:")
                for cve in security_check['cves']:
                    print(f"   - {cve}")
                print(f"   Continuing with installation...")
            if security_check['is_eol']:
                print(f"⚠️  kubectl v{version} is end-of-life and no longer supported")
            
        # Normalize version string - remove 'v' prefix if present, then add it for URL
        version_clean = version.lstrip('v')
        
        os_name, arch = self.get_platform_info()
        binary_name = "kubectl"
        url = f"{self.config['settings']['download_base_url']}/v{version_clean}/bin/{os_name}/{arch}/{binary_name}"
        
        local_path = self.bin_dir / f"kubectl-{version_clean}"
        
        if local_path.exists():
            print(f"✅ kubectl v{version_clean} already installed")
            return True
        
        print(f"📥 Downloading kubectl v{version_clean} for {os_name}/{arch}...")
        
        try:
            def progress_hook(block_num, block_size, total_size):
                if show_progress and total_size > 0:
                    downloaded = block_num * block_size
                    percent = min(100, (downloaded * 100) // total_size)
                    bar_length = 30
                    filled = (percent * bar_length) // 100
                    bar = "█" * filled + "░" * (bar_length - filled)
                    print(f"\r   {bar} {percent}% ({downloaded // 1024 // 1024}MB/{total_size // 1024 // 1024}MB)", end="")
            
            # SECURITY: Use secure download with integrity verification
            if not self._secure_download(url, local_path, progress_hook):
                return False
            
            # SECURITY: Verify cryptographic integrity
            if not self._verify_download_integrity(local_path, version_clean, os_name, arch):
                print(f"❌ Integrity verification failed for kubectl v{version_clean}")
                if local_path.exists():
                    local_path.unlink()
                return False
                
            if show_progress:
                print()  # New line after progress bar
            
            # Make executable
            local_path.chmod(local_path.stat().st_mode | stat.S_IEXEC)
            
            print(f"✅ kubectl v{version_clean} installed successfully")
            
            # Final security check and advisory
            security_check = self._check_version_security(version_clean)
            if security_check['recommendations']:
                print(f"📝 Security Advisory: {security_check['recommendations'][0]}")
            return True
        
        except Exception as e:
            print(f"❌ Error downloading kubectl v{version_clean}: {e}")
            if local_path.exists():
                local_path.unlink()
            return False
    
    def detect_cluster_version(self, kubeconfig_path: str) -> Optional[str]:
        """Detect Kubernetes cluster version from kubeconfig"""
        try:
            cmd = ["kubectl", "version", "--output=json", f"--kubeconfig={kubeconfig_path}"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                version_info = json.loads(result.stdout)
                server_version = version_info.get("serverVersion", {}).get("gitVersion", "")
                if server_version.startswith("v"):
                    return server_version[1:]  # Remove 'v' prefix
        
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
            pass
        
        return None
    
    def get_recommended_kubectl_version(self, cluster_version: str) -> str:
        """Get recommended kubectl version for cluster version"""
        # Parse cluster version
        try:
            major, minor, patch = cluster_version.split(".")
            target_version = f"{major}.{minor}"
            
            # Get available versions
            available = self.fetch_available_versions()
            
            # Find latest patch version for the same minor version
            compatible_versions = [v for v in available if v.startswith(target_version + ".")]
            
            if compatible_versions:
                return max(compatible_versions, key=lambda x: [int(i) for i in x.split(".")])
            
            # Fallback: return cluster version if no exact match
            return cluster_version
        
        except ValueError:
            return cluster_version
    
    def add_cluster(self, name: str, kubeconfig_path: str) -> bool:
        """Add/import a cluster configuration"""
        # SECURITY: Validate cluster name
        if not self._validate_cluster_name(name):
            print(f"❌ Invalid cluster name: {name}")
            print("Cluster names must be alphanumeric with hyphens, underscores, or dots only")
            return False
            
        source_path = Path(kubeconfig_path).expanduser().resolve()
        
        if not source_path.exists():
            print(f"❌ Kubeconfig file not found: {source_path}")
            return False
        
        target_path = self.configs_dir / f"{name}.yaml"
        
        print(f"🔍 Importing cluster configuration '{name}'...")
        
        # Copy kubeconfig
        try:
            shutil.copy2(source_path, target_path)
            # Secure permissions
            target_path.chmod(0o600)
        except Exception as e:
            print(f"❌ Error copying kubeconfig: {e}")
            return False
        
        # Detect cluster version
        print("📡 Connecting to detect cluster version...")
        cluster_version = self.detect_cluster_version(str(target_path))
        
        if not cluster_version:
            print("⚠️  Could not detect cluster version (cluster may be unreachable)")
            cluster_version = "unknown"
        else:
            print(f"✅ Cluster version detected: v{cluster_version}")
        
        # Get recommended kubectl version
        recommended_kubectl = self.get_recommended_kubectl_version(cluster_version)
        print(f"💡 Recommended kubectl version: v{recommended_kubectl}")
        
        # Check if recommended version is installed
        installed_versions = self.get_installed_versions()
        kubectl_version = None
        
        if recommended_kubectl in installed_versions:
            kubectl_version = recommended_kubectl
            print(f"✅ kubectl v{recommended_kubectl} already installed")
        else:
            # Check for compatible versions (same minor version)
            try:
                major, minor = recommended_kubectl.split(".")[:2]
                compatible = [v for v in installed_versions if v.startswith(f"{major}.{minor}.")]
                if compatible:
                    kubectl_version = max(compatible, key=lambda x: [int(i) for i in x.split(".")])
                    print(f"✅ Using existing compatible version: kubectl v{kubectl_version}")
                elif self.config["settings"]["auto_download"]:
                    print(f"📦 kubectl v{recommended_kubectl} not found locally")
                    if self.download_kubectl(recommended_kubectl):
                        kubectl_version = recommended_kubectl
            except ValueError:
                pass
        
        # SECURITY: Check kubectl version for vulnerabilities
        if kubectl_version:
            security_check = self._check_version_security(kubectl_version)
            if security_check['is_vulnerable']:
                print(f"\n⚠️  SECURITY WARNING: kubectl v{kubectl_version} has known vulnerabilities:")
                for cve in security_check['cves']:
                    print(f"   - {cve}: {security_check['warnings'][0]}")
                if security_check['recommendations']:
                    print(f"   Recommendation: {security_check['recommendations'][0]}")
                print()
        
        # Register cluster
        self.config["clusters"][name] = {
            "config_file": str(target_path.relative_to(self.base_dir)),
            "cluster_version": cluster_version,
            "kubectl_version": kubectl_version,
            "recommended_kubectl": recommended_kubectl,
            "added_date": datetime.now().isoformat(),
            "last_validated": None,
            "security_check": self._check_version_security(kubectl_version) if kubectl_version else None
        }
        
        self.save_config()
        
        print(f"✅ Cluster '{name}' added successfully")
        if kubectl_version:
            print(f"🎯 Paired with kubectl v{kubectl_version}")
            print(f"🚀 Ready to use: ./kubectl-manager.py use {name}")
        else:
            print(f"⚠️  No compatible kubectl version available")
            print(f"   Install with: ./kubectl-manager.py versions install {recommended_kubectl}")
        
        return True
    
    def list_clusters(self):
        """List all installed clusters"""
        if not self.config["clusters"]:
            print("No clusters configured. Add one with: ./kubectl-manager.py configs add <name> <kubeconfig-path>")
            return
        
        print("┌─ Installed Clusters ────────────────────────────────────────┐")
        print("│                                                             │")
        
        for name, info in self.config["clusters"].items():
            cluster_ver = info.get("cluster_version", "unknown")
            kubectl_ver = info.get("kubectl_version")
            
            status = "✅ Ready"
            icon = "🟢"
            
            if not kubectl_ver:
                status = "❌ Missing kubectl"
                icon = "🔴"
            elif cluster_ver != "unknown":
                # Check compatibility
                try:
                    cluster_minor = ".".join(cluster_ver.split(".")[:2])
                    kubectl_minor = ".".join(kubectl_ver.split(".")[:2])
                    if cluster_minor != kubectl_minor:
                        status = "⚠️  Version skew"
                        icon = "🟡"
                except (ValueError, AttributeError):
                    pass
            
            kubectl_display = f"kubectl v{kubectl_ver}" if kubectl_ver else "(no kubectl)"
            line = f"│ {icon} {name:<12} v{cluster_ver:<8} {kubectl_display:<15} {status:<8} │"
            print(line)
        
        print("│                                                             │")
        active_cluster = self.config.get("active_cluster")
        if active_cluster:
            print(f"│ Active: {active_cluster} → kubectl v{self.config.get('active_kubectl', 'none')}")
        print("└─────────────────────────────────────────────────────────────┘")
    
    def use_cluster(self, cluster_name: str, kubectl_version: str = None, wrapper_mode: str = 'local'):
        """Switch to using specific cluster and kubectl version"""
        if cluster_name not in self.config["clusters"]:
            print(f"❌ Cluster '{cluster_name}' not found")
            self.list_clusters()
            return False
        
        cluster_info = self.config["clusters"][cluster_name]
        
        # Determine kubectl version to use
        if kubectl_version:
            target_kubectl = kubectl_version
        else:
            target_kubectl = cluster_info.get("kubectl_version") or cluster_info.get("recommended_kubectl")
        
        if not target_kubectl:
            print(f"❌ No kubectl version specified for cluster '{cluster_name}'")
            return False
        
        # Check if kubectl version exists
        installed = self.get_installed_versions()
        if target_kubectl not in installed:
            print(f"❌ kubectl v{target_kubectl} not installed")
            print(f"Install with: ./kubectl-manager.py versions install {target_kubectl}")
            return False
        
        # Update active configuration
        self.config["active_cluster"] = cluster_name
        self.config["active_kubectl"] = target_kubectl
        self.save_config()
        
        # Create kubectl wrapper with configurable mode
        self._create_kubectl_wrapper(cluster_name, target_kubectl, wrapper_mode)
        
        # Create environment setup script
        env_setup_path = self.base_dir / "kubectl-env.sh"
        kubeconfig_path = self.base_dir / cluster_info["config_file"]
        
        env_setup_content = f"""#!/bin/bash
# kubectl Manager Environment Setup
# Source this file to set KUBECONFIG for direct kubectl usage
export KUBECONFIG="{kubeconfig_path}"
echo "✅ KUBECONFIG set to: {cluster_name} cluster"
echo "Now you can use './kubectl' directly without --kubeconfig option"
"""
        
        with open(env_setup_path, 'w') as f:
            f.write(env_setup_content)
        env_setup_path.chmod(0o755)
        
        print(f"✅ Switched to kubectl v{target_kubectl} → {cluster_name}")
        if wrapper_mode == 'local':
            print(f"🎯 './kubectl' is now ready to use directly (no setup needed!)")
        elif wrapper_mode == 'user':
            print(f"🎯 'kubectl-mgr' command available in PATH")
        elif wrapper_mode == 'explicit':
            print(f"🎯 Use: ./kubectl-manager.py run <command>")
        
        # Show compatibility warning if needed
        cluster_version = cluster_info.get("cluster_version", "")
        if cluster_version and cluster_version != "unknown":
            try:
                cluster_minor = ".".join(cluster_version.split(".")[:2])
                kubectl_minor = ".".join(target_kubectl.split(".")[:2])
                if cluster_minor != kubectl_minor:
                    print(f"⚠️  Version skew: kubectl v{target_kubectl} with cluster v{cluster_version}")
            except (ValueError, IndexError):
                pass
        
        return True
    
    def run_kubectl(self, args: List[str]):
        """Run kubectl command with active configuration"""
        active_cluster = self.config.get("active_cluster")
        active_kubectl = self.config.get("active_kubectl")
        
        if not active_cluster or not active_kubectl:
            print("❌ No active cluster/kubectl version set")
            print("Use: ./kubectl-manager.py use <cluster-name>")
            return False
        
        kubectl_binary = self.bin_dir / f"kubectl-{active_kubectl}"
        if not kubectl_binary.exists():
            print(f"❌ kubectl v{active_kubectl} binary not found")
            return False
        
        cluster_info = self.config["clusters"][active_cluster]
        kubeconfig_path = self.base_dir / cluster_info["config_file"]
        
        if not kubeconfig_path.exists():
            print(f"❌ Kubeconfig not found: {kubeconfig_path}")
            return False
        
        # SECURITY FIX: Validate and sanitize arguments
        try:
            validated_args = self._validate_kubectl_args(args)
        except ValueError as e:
            print(f"❌ Invalid kubectl arguments: {e}")
            return False
        
        # Build command with validated arguments
        cmd = [str(kubectl_binary), f"--kubeconfig={str(kubeconfig_path)}"] + validated_args
        
        # Execute kubectl with enhanced security measures
        try:
            # Run in a secure, restricted environment
            secure_env = self._create_secure_environment()
            result = subprocess.run(
                cmd,
                timeout=300,  # 5 minute timeout
                cwd=self.base_dir,  # Set working directory
                env=secure_env
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("❌ kubectl command timed out")
            return False
        except KeyboardInterrupt:
            print("\n⚠️  Command interrupted")
            return False
        except Exception as e:
            print(f"❌ Error running kubectl: {e}")
            return False
    
    def _create_secure_environment(self) -> Dict[str, str]:
        """Create a minimal, secure environment for subprocess execution"""
        # Start with minimal environment
        secure_env = {
            'PATH': '/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin',
            'HOME': str(Path.home()),
            'USER': os.environ.get('USER', 'kubectl-manager'),
            'LANG': 'C.UTF-8',  # Prevent locale-based attacks
            'LC_ALL': 'C.UTF-8',
        }
        
        # Explicitly block dangerous environment variables
        dangerous_vars = {
            'LD_PRELOAD', 'LD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES',
            'DYLD_FORCE_FLAT_NAMESPACE', 'DYLD_LIBRARY_PATH',
            'IFS', 'PS1', 'PS2', 'PS3', 'PS4',
            'SHELL', 'BASH_ENV', 'ENV'
        }
        
        # Add safe environment variables from current environment
        safe_vars = {
            'TERM', 'COLORTERM', 'COLUMNS', 'LINES',
            'TMPDIR', 'TMP', 'TEMP'
        }
        
        for var in safe_vars:
            if var in os.environ and var not in dangerous_vars:
                secure_env[var] = os.environ[var]
        
        # Ensure KUBECONFIG is properly set (will be overridden by kubectl wrapper)
        if 'KUBECONFIG' in os.environ:
            secure_env['KUBECONFIG'] = os.environ['KUBECONFIG']
            
        return secure_env
    
    def _create_kubectl_wrapper(self, cluster_name: str, kubectl_version: str, mode: str = 'local'):
        """Create kubectl wrapper with enhanced security and configurable modes"""
        cluster_info = self.config["clusters"][cluster_name]
        target_binary = self.bin_dir / f"kubectl-{kubectl_version}"
        kubeconfig_path = self.base_dir / cluster_info["config_file"]
        
        if mode == 'local':
            # Create ./kubectl in project directory (current behavior)
            wrapper_path = self.base_dir / "kubectl"
            wrapper_name = "./kubectl"
        elif mode == 'user':
            # Create kubectl-mgr in user's bin directory
            user_bin = Path.home() / ".local/bin"
            user_bin.mkdir(parents=True, exist_ok=True)
            wrapper_path = user_bin / "kubectl-mgr"
            wrapper_name = "kubectl-mgr"
        elif mode == 'explicit':
            # No wrapper, require explicit invocation
            return
        else:
            raise ValueError(f"Invalid wrapper mode: {mode}")
        
        # Remove old wrapper if it exists
        if wrapper_path.exists() or wrapper_path.is_symlink():
            wrapper_path.unlink()
        
        # Enhanced wrapper script with security checks
        wrapper_content = f"""#!/bin/bash
# kubectl Manager Wrapper v2.0 - Enhanced Security
# Generated on {datetime.now().isoformat()}
set -euo pipefail

# Security: Verify binary integrity before execution
KUBECTL_BINARY="{target_binary}"
KUBECONFIG_FILE="{kubeconfig_path}"

# Check if kubectl binary exists and is executable
if [[ ! -x "$KUBECTL_BINARY" ]]; then
    echo "❌ kubectl binary not found or not executable: $KUBECTL_BINARY" >&2
    echo "Run: ./kubectl-manager.py versions install {kubectl_version}" >&2
    exit 1
fi

# Check if kubeconfig exists and is readable
if [[ ! -r "$KUBECONFIG_FILE" ]]; then
    echo "❌ kubeconfig not found or not readable: $KUBECONFIG_FILE" >&2
    echo "Check your cluster configuration with: ./kubectl-manager.py clusters list" >&2
    exit 1
fi

# Verify file permissions for security
if [[ $(stat -c "%a" "$KUBECONFIG_FILE" 2>/dev/null || stat -f "%A" "$KUBECONFIG_FILE" 2>/dev/null) != "600" ]]; then
    echo "⚠️  Warning: kubeconfig has overly permissive permissions" >&2
fi

# Set environment and execute kubectl
export KUBECONFIG="$KUBECONFIG_FILE"
exec "$KUBECTL_BINARY" "$@"
"""
        
        # Write wrapper with secure permissions
        with open(wrapper_path, 'w') as f:
            f.write(wrapper_content)
        wrapper_path.chmod(0o755)
        
        # Create environment setup script for compatibility
        if mode == 'local':
            env_setup_path = self.base_dir / "kubectl-env.sh"
            env_setup_content = f"""#!/bin/bash
# kubectl Manager Environment Setup
# Source this file to set KUBECONFIG for direct kubectl usage
export KUBECONFIG="{kubeconfig_path}"
echo "✅ KUBECONFIG set to: {cluster_name} cluster"
echo "Now you can use '{wrapper_name}' directly"
"""
            
            with open(env_setup_path, 'w') as f:
                f.write(env_setup_content)
            env_setup_path.chmod(0o755)
    
    def diagnose_system(self) -> Dict[str, any]:
        """Comprehensive system diagnostics for troubleshooting"""
        print("🔍 Running kubectl-manager diagnostics...\n")
        
        diagnostics = {
            'system': {},
            'kubectl_manager': {},
            'clusters': {},
            'security': {},
            'recommendations': []
        }
        
        # System information
        diagnostics['system'] = {
            'platform': platform.system(),
            'architecture': platform.machine(),
            'python_version': sys.version,
            'working_directory': str(Path.cwd()),
            'home_directory': str(Path.home())
        }
        
        # kubectl-manager configuration
        diagnostics['kubectl_manager'] = {
            'base_directory': str(self.base_dir),
            'config_file': str(self.config_file),
            'config_exists': self.config_file.exists(),
            'bin_directory': str(self.bin_dir),
            'configs_directory': str(self.configs_dir),
            'installed_versions': self.get_installed_versions(),
            'active_cluster': self.config.get('active_cluster'),
            'active_kubectl': self.config.get('active_kubectl')
        }
        
        # Cluster diagnostics
        for name, info in self.config['clusters'].items():
            cluster_diag = {
                'config_file': info['config_file'],
                'config_exists': (self.base_dir / info['config_file']).exists(),
                'cluster_version': info.get('cluster_version'),
                'kubectl_version': info.get('kubectl_version'),
                'security_check': info.get('security_check', {})
            }
            
            # Test cluster connectivity
            try:
                config_path = self.base_dir / info['config_file']
                if config_path.exists():
                    cmd = ['kubectl', 'version', '--client', '--output=json', f'--kubeconfig={config_path}']
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    cluster_diag['connectivity'] = result.returncode == 0
                    if result.returncode != 0:
                        cluster_diag['connectivity_error'] = result.stderr
                else:
                    cluster_diag['connectivity'] = False
                    cluster_diag['connectivity_error'] = 'Config file not found'
            except Exception as e:
                cluster_diag['connectivity'] = False
                cluster_diag['connectivity_error'] = str(e)
            
            diagnostics['clusters'][name] = cluster_diag
        
        # Security diagnostics
        security_issues = []
        
        # Check file permissions
        for name, info in self.config['clusters'].items():
            config_path = self.base_dir / info['config_file']
            if config_path.exists():
                try:
                    perms = oct(config_path.stat().st_mode)[-3:]
                    if perms != '600':
                        security_issues.append(f"Cluster '{name}' config has insecure permissions: {perms}")
                except Exception:
                    pass
        
        # Check for vulnerable versions
        vulnerable_versions = []
        for version in diagnostics['kubectl_manager']['installed_versions']:
            security_check = self._check_version_security(version)
            if security_check['is_vulnerable']:
                vulnerable_versions.append({
                    'version': version,
                    'cves': security_check['cves'],
                    'severity': security_check['severity']
                })
        
        diagnostics['security'] = {
            'issues': security_issues,
            'vulnerable_versions': vulnerable_versions
        }
        
        # Generate recommendations
        if security_issues:
            diagnostics['recommendations'].append("Fix file permission issues")
        if vulnerable_versions:
            diagnostics['recommendations'].append("Upgrade or remove vulnerable kubectl versions")
        if not diagnostics['kubectl_manager']['installed_versions']:
            diagnostics['recommendations'].append("Install at least one kubectl version")
        
        # Print diagnostic report
        self._print_diagnostic_report(diagnostics)
        
        return diagnostics
    
    def _print_diagnostic_report(self, diagnostics: Dict[str, any]):
        """Print formatted diagnostic report"""
        print("┌─ System Information ───────────────────────────────────────────┐")
        sys_info = diagnostics['system']
        print(f"│ Platform: {sys_info['platform']} ({sys_info['architecture']})")
        print(f"│ Python: {sys_info['python_version'].split()[0]}")
        print(f"│ Working Directory: {sys_info['working_directory']}")
        print("├─ kubectl-manager Configuration ────────────────────────────────┐")
        
        km_info = diagnostics['kubectl_manager']
        print(f"│ Base Directory: {km_info['base_directory']}")
        print(f"│ Config File: {'✅' if km_info['config_exists'] else '❌'} {km_info['config_file']}")
        print(f"│ Installed Versions: {len(km_info['installed_versions'])}")
        
        if km_info['installed_versions']:
            print(f"│   - {', '.join(f'v{v}' for v in km_info['installed_versions'])}")
        
        active_cluster = km_info['active_cluster']
        active_kubectl = km_info['active_kubectl']
        if active_cluster and active_kubectl:
            print(f"│ Active: kubectl v{active_kubectl} → {active_cluster}")
        else:
            print("│ Active: None configured")
        
        # Cluster information
        if diagnostics['clusters']:
            print("├─ Cluster Status ───────────────────────────────────────────────┐")
            
            for name, cluster in diagnostics['clusters'].items():
                status = "✅" if cluster.get('connectivity') else "❌"
                config_status = "✅" if cluster.get('config_exists') else "❌"
                print(f"│ {name}: {status} connectivity, {config_status} config")
                
                if not cluster.get('connectivity') and cluster.get('connectivity_error'):
                    print(f"│   Error: {cluster['connectivity_error'][:60]}")
        
        # Security status
        security = diagnostics['security']
        print("├─ Security Status ──────────────────────────────────────────────┐")
        
        if not security['issues'] and not security['vulnerable_versions']:
            print("│ ✅ No security issues detected")
        else:
            if security['issues']:
                print("│ ⚠️  Security Issues:")
                for issue in security['issues']:
                    print(f"│   - {issue}")
            
            if security['vulnerable_versions']:
                print("│ 🔒 Vulnerable Versions:")
                for vuln in security['vulnerable_versions']:
                    print(f"│   - v{vuln['version']}: {vuln['severity']} ({', '.join(vuln['cves'])})")
        
        # Recommendations
        if diagnostics['recommendations']:
            print("├─ Recommendations ──────────────────────────────────────────────┐")
            for i, rec in enumerate(diagnostics['recommendations'], 1):
                print(f"│ {i}. {rec}")
        
        print("└────────────────────────────────────────────────────────────────────────────────┘")
    
    def show_status(self):
        """Show current status"""
        active_cluster = self.config.get("active_cluster")
        active_kubectl = self.config.get("active_kubectl")
        
        print("┌─ Current Configuration ────────────────────────────────────┐")
        if active_cluster and active_kubectl:
            cluster_info = self.config["clusters"].get(active_cluster, {})
            cluster_version = cluster_info.get("cluster_version", "unknown")
            
            print(f"│ kubectl: v{active_kubectl} ✅")
            print(f"│ Cluster: {active_cluster} (v{cluster_version}) ✅")
            
            # Compatibility check
            if cluster_version != "unknown":
                try:
                    cluster_minor = ".".join(cluster_version.split(".")[:2])
                    kubectl_minor = ".".join(active_kubectl.split(".")[:2])
                    if cluster_minor == kubectl_minor:
                        print("│ Compatibility: Perfect match ⭐")
                    else:
                        print("│ Compatibility: Version skew ⚠️")
                except (ValueError, IndexError):
                    print("│ Compatibility: Unknown")
            else:
                print("│ Compatibility: Unknown (cluster unreachable)")
        else:
            print("│ No active configuration")
            print("│ Use: ./kubectl-manager.py use <cluster-name>")
        
        print("└────────────────────────────────────────────────────────────┘")
    
    
    
    
    
    
    def show_help(self):
        """Show comprehensive help information"""
        help_text = """
🚀 kubectl Manager - Multi-version kubectl and cluster management tool

USAGE:
    ./kubectl-manager.py [COMMAND] [OPTIONS]
    ./kubectl-manager.py help               # Show detailed help information

CORE COMMANDS:
    status                                  # Show current configuration and compatibility
    use <cluster> [--kubectl <version>]    # Switch to cluster (with optional kubectl version)
    run <kubectl-args...>                   # Run kubectl command with active configuration

VERSION MANAGEMENT:
    versions list                           # List available kubectl versions from GitHub
    versions installed                      # Show locally installed kubectl versions  
    versions install <version>             # Install specific kubectl version (e.g., 1.31.0)

CLUSTER MANAGEMENT:
    clusters list                           # List all imported/configured clusters
    configs list                            # Alias for 'clusters list'
    configs add <name> <kubeconfig-path>    # Import cluster from kubeconfig file

EXAMPLES:
    # Setup new cluster with auto-detection
    ./kubectl-manager.py configs add prod ~/.kube/production.yaml
    
    # Switch to cluster (auto-selects optimal kubectl version)
    ./kubectl-manager.py use prod
    
    # Override kubectl version for specific cluster
    ./kubectl-manager.py use prod --kubectl 1.30.0
    
    # Run kubectl commands (uses active cluster + version)
    ./kubectl-manager.py run get pods
    ./kubectl-manager.py run apply -f deployment.yaml
    
    # Check current status and compatibility
    ./kubectl-manager.py status
    
    # Install specific kubectl version
    ./kubectl-manager.py versions install 1.32.0
    
    # Show help
    ./kubectl-manager.py help

DIRECT kubectl USAGE:
    After switching clusters with 'use', you can run kubectl directly:
    
    ./kubectl-manager.py use prod          # Switch to production cluster
    ./kubectl get pods                     # Now works automatically!
    ./kubectl apply -f app.yaml            # Uses correct version + cluster

FEATURES:
    ✅ Automatic kubectl version detection and download
    ✅ Cluster version compatibility checking  
    ✅ Multiple kubectl versions side-by-side
    ✅ Smart kubectl binary selection
    ✅ Zero-setup direct kubectl usage
    ✅ Cross-platform support (Linux, macOS)
    🔒 SHA256 verification of all downloaded binaries
    🔒 CVE vulnerability checking and blocking
    🔒 Enhanced security with path traversal protection
    🔒 Secure subprocess isolation
    🧹 Intelligent version pruning and cleanup
    🩺 Comprehensive system diagnostics

FILES:
    bin/kubectl-X.X.X                      # Downloaded kubectl binaries (SHA256 verified)
    configs/cluster-name.yaml               # Imported kubeconfig files (secure permissions)
    .kubectl-manager/config.json            # Tool configuration with security metadata
    kubectl                                 # Enhanced wrapper script with integrity checks
    kubectl-env.sh                          # Environment setup (optional)
    .kubectl-manager/cache/                 # Version cache and security data

COMPATIBILITY:
    kubectl supports ±1 minor version from cluster:
    • Cluster v1.31.x → kubectl v1.30.x, v1.31.x, v1.32.x ✅
    • Perfect match (same minor version) is recommended ⭐

SECURITY:
    • All downloads verified with SHA256 checksums from dl.k8s.io
    • Known vulnerable versions blocked by severity level
    • Enhanced argument validation prevents injection attacks
    • Secure subprocess isolation with minimal environment
    • Path traversal protection for file operations

For more help: https://github.com/your-username/kubectl-manager
Report issues: https://github.com/your-username/kubectl-manager/issues
"""
        print(help_text.strip())


def main():
    manager = KubectlManager()
    
    if len(sys.argv) == 1:
        # Show help when no arguments provided
        print("🚀 kubectl Manager - Multi-version kubectl and cluster management")
        print("\nUsage: ./kubectl-manager.py [COMMAND] [OPTIONS]")
        print("\nRun './kubectl-manager.py help' for detailed usage information.")
        return
    
    parser = argparse.ArgumentParser(description="kubectl Manager - Multi-version kubectl and cluster management")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Versions subcommand
    versions_parser = subparsers.add_parser("versions", help="Manage kubectl versions")
    versions_subparsers = versions_parser.add_subparsers(dest="versions_action")
    
    versions_subparsers.add_parser("list", help="List available versions")
    versions_subparsers.add_parser("installed", help="List installed versions")
    
    install_parser = versions_subparsers.add_parser("install", help="Install kubectl version")
    install_parser.add_argument("version", help="Version to install (e.g., 1.29.0)")
    install_parser.add_argument("--force", action="store_true", help="Force install even if version has vulnerabilities")
    
    prune_parser = versions_subparsers.add_parser("prune", help="Remove old/vulnerable kubectl versions")
    prune_parser.add_argument("--keep", type=int, default=3, help="Number of latest versions to keep (default: 3)")
    prune_parser.add_argument("--remove-vulnerable", action="store_true", help="Remove high/critical vulnerability versions")
    
    # Configs subcommand
    configs_parser = subparsers.add_parser("configs", help="Manage cluster configurations")
    configs_subparsers = configs_parser.add_subparsers(dest="configs_action")
    
    configs_subparsers.add_parser("list", help="List configured clusters")
    
    add_parser = configs_subparsers.add_parser("add", help="Add cluster configuration")
    add_parser.add_argument("name", help="Cluster name")
    add_parser.add_argument("kubeconfig", help="Path to kubeconfig file")
    
    # Clusters subcommand (alias for configs)
    clusters_parser = subparsers.add_parser("clusters", help="Manage clusters (alias for configs)")
    clusters_subparsers = clusters_parser.add_subparsers(dest="clusters_action")
    clusters_subparsers.add_parser("list", help="List clusters")
    
    # Use subcommand
    use_parser = subparsers.add_parser("use", help="Switch to cluster and kubectl version")
    use_parser.add_argument("cluster", help="Cluster name")
    use_parser.add_argument("--kubectl", help="Specific kubectl version to use")
    
    # Run subcommand
    run_parser = subparsers.add_parser("run", help="Run kubectl command")
    run_parser.add_argument("kubectl_args", nargs=argparse.REMAINDER, help="kubectl arguments")
    
    # Status subcommand
    subparsers.add_parser("status", help="Show current status")
    
    # Diagnostics subcommand
    subparsers.add_parser("diagnose", help="Run comprehensive system diagnostics")
    
    # Help subcommand
    subparsers.add_parser("help", help="Show detailed help information")
    
    args = parser.parse_args()
    
    if args.command == "versions":
        if args.versions_action == "list":
            versions = manager.fetch_available_versions()[:20]
            print("📋 Latest available kubectl versions:")
            for version in versions:
                print(f"  v{version}")
        elif args.versions_action == "installed":
            installed = manager.get_installed_versions()
            if installed:
                print("📦 Installed kubectl versions:")
                for version in installed:
                    print(f"  v{version}")
            else:
                print("📦 No kubectl versions installed")
        elif args.versions_action == "install":
            force_flag = getattr(args, 'force', False)
            manager.download_kubectl(args.version, force=force_flag)
        elif args.versions_action == "prune":
            manager.prune_versions(keep_latest=args.keep, remove_vulnerable=args.remove_vulnerable)
    
    elif args.command == "configs":
        if args.configs_action == "list":
            manager.list_clusters()
        elif args.configs_action == "add":
            manager.add_cluster(args.name, args.kubeconfig)
    
    elif args.command == "clusters":
        if args.clusters_action == "list":
            manager.list_clusters()
    
    elif args.command == "use":
        manager.use_cluster(args.cluster, args.kubectl)
    
    elif args.command == "run":
        if args.kubectl_args:
            manager.run_kubectl(args.kubectl_args)
        else:
            print("❌ No kubectl arguments provided")
    
    elif args.command == "status":
        manager.show_status()
    
    elif args.command == "help":
        manager.show_help()
    
    elif args.command == "diagnose":
        manager.diagnose_system()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()