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
        return bool(re.match(r'^[a-zA-Z0-9._-]+$', name))
    
    def _validate_version(self, version: str) -> bool:
        """Validate version string for security"""
        if not version or len(version) > 50:
            return False
        # Allow version format: x.y.z with optional -suffix
        import re
        return bool(re.match(r'^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$', version))
    
    def _validate_kubectl_args(self, args: List[str]) -> List[str]:
        """Validate and sanitize kubectl arguments"""
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
        
        validated_args = []
        for i, arg in enumerate(args):
            # Limit argument length
            if len(arg) > 1000:
                raise ValueError(f"Argument too long: {arg[:50]}...")
            
            # First argument should be a valid kubectl command
            if i == 0 and arg not in allowed_commands:
                raise ValueError(f"Disallowed kubectl command: {arg}")
            
            # Block dangerous patterns
            dangerous_patterns = [';', '&&', '||', '|', '`', '$', '>', '<', '&']
            if any(pattern in arg for pattern in dangerous_patterns):
                raise ValueError(f"Dangerous character in argument: {arg}")
            
            # Block file system manipulation
            if any(dangerous in arg.lower() for dangerous in ['../../../', '..\\..\\', '/etc/', '/proc/', '/sys/', 'rm -rf', 'sudo']):
                raise ValueError(f"Potentially dangerous argument: {arg}")
            
            validated_args.append(arg)
        
        return validated_args
    
    def _create_secure_context(self) -> ssl.SSLContext:
        """Create a secure SSL context for downloads with enhanced security"""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Enhanced security settings
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # Require TLS 1.2+
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE
        
        return context
    
    def _verify_download_integrity(self, file_path: Path, expected_size: int = None) -> bool:
        """Basic integrity verification for downloaded files"""
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
        
        # Basic file type verification (check for ELF/PE/Mach-O magic bytes)
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                # ELF (Linux), PE (Windows), Mach-O (macOS)
                valid_magic = [b'\x7fELF', b'MZ\x90\x00', b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']
                if not any(magic.startswith(m[:len(magic)]) for m in valid_magic):
                    print(f"❌ Downloaded file does not appear to be a valid binary")
                    return False
        except Exception as e:
            print(f"❌ Error verifying download: {e}")
            return False
            
        return True
    
    def _secure_download(self, url: str, output_path: Path, progress_hook=None) -> bool:
        """Securely download a file with integrity checks"""
        try:
            # Create secure request with SSL verification
            context = self._create_secure_context()
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))
            urllib.request.install_opener(opener)
            
            # Download file
            urllib.request.urlretrieve(url, output_path, progress_hook)
            
            # Verify download integrity
            if not self._verify_download_integrity(output_path):
                if output_path.exists():
                    output_path.unlink()
                return False
                
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
            'darwin': 'darwin',
            'windows': 'windows'
        }
        
        arch_map = {
            'x86_64': 'amd64',
            'amd64': 'amd64',
            'arm64': 'arm64',
            'aarch64': 'arm64'
        }
        
        return os_map.get(system, 'linux'), arch_map.get(machine, 'amd64')
    
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
                    # Remove .exe extension on Windows
                    if version.endswith(".exe"):
                        version = version[:-4]
                    versions.append(version)
        return sorted(versions, key=self._version_sort_key)
    
    def download_kubectl(self, version: str, show_progress: bool = True) -> bool:
        """Download kubectl binary for specified version"""
        # SECURITY: Validate version string
        if not self._validate_version(version):
            print(f"❌ Invalid version format: {version}")
            return False
            
        # Normalize version string - remove 'v' prefix if present, then add it for URL
        version_clean = version.lstrip('v')
        
        os_name, arch = self.get_platform_info()
        binary_name = "kubectl.exe" if os_name == "windows" else "kubectl"
        url = f"{self.config['settings']['download_base_url']}/v{version_clean}/bin/{os_name}/{arch}/{binary_name}"
        
        local_path = self.bin_dir / f"kubectl-{version_clean}"
        if os_name == "windows":
            local_path = local_path.with_suffix(".exe")
        
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
                
            if show_progress:
                print()  # New line after progress bar
            
            # Make executable
            local_path.chmod(local_path.stat().st_mode | stat.S_IEXEC)
            
            print(f"✅ kubectl v{version_clean} installed successfully")
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
        
        # Register cluster
        self.config["clusters"][name] = {
            "config_file": str(target_path.relative_to(self.base_dir)),
            "cluster_version": cluster_version,
            "kubectl_version": kubectl_version,
            "recommended_kubectl": recommended_kubectl,
            "added_date": datetime.now().isoformat(),
            "last_validated": None
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
    
    def use_cluster(self, cluster_name: str, kubectl_version: str = None):
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
        
        # Create kubectl wrapper script that automatically sets KUBECONFIG
        kubectl_wrapper_path = self.base_dir / "kubectl"
        target_binary = self.bin_dir / f"kubectl-{target_kubectl}"
        kubeconfig_path = self.base_dir / cluster_info["config_file"]
        
        # Remove old symlink or file
        if kubectl_wrapper_path.exists() or kubectl_wrapper_path.is_symlink():
            kubectl_wrapper_path.unlink()
        
        # Create wrapper script
        wrapper_content = f"""#!/bin/bash
# kubectl Manager Wrapper - Automatically uses correct kubectl version and kubeconfig
export KUBECONFIG="{kubeconfig_path}"
exec "{target_binary}" "$@"
"""
        
        with open(kubectl_wrapper_path, 'w') as f:
            f.write(wrapper_content)
        kubectl_wrapper_path.chmod(0o755)
        
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
        print(f"🎯 './kubectl' is now ready to use directly (no setup needed!)")
        
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
        
        # Execute kubectl with additional security measures
        try:
            # Run in a more restricted environment
            result = subprocess.run(
                cmd,
                timeout=300,  # 5 minute timeout
                cwd=self.base_dir,  # Set working directory
                env={  # Minimal environment
                    'PATH': '/usr/local/bin:/usr/bin:/bin',
                    'HOME': str(Path.home()),
                    'USER': os.environ.get('USER', 'unknown')
                }
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
    
    def interactive_menu(self):
        """Show interactive menu"""
        while True:
            print("\n┌─ kubectl Manager ─────────────────────┐")
            
            active_cluster = self.config.get("active_cluster")
            active_kubectl = self.config.get("active_kubectl")
            
            if active_cluster and active_kubectl:
                print(f"│ Current: kubectl v{active_kubectl} → {active_cluster}")
            else:
                print("│ No active configuration")
            
            print("│                                       │")
            print("│ 1. Manage kubectl versions            │")
            print("│ 2. Manage cluster configs            │")
            print("│ 3. Switch version + config           │")
            print("│ 4. Run kubectl command               │")
            print("│ 5. Status & health check             │")
            print("│ 6. Help & documentation              │")
            print("│ 7. Exit                              │")
            print("└───────────────────────────────────────┘")
            
            try:
                choice = input("\nSelect option [1-7]: ").strip()
                
                if choice == "1":
                    self.versions_menu()
                elif choice == "2":
                    self.configs_menu()
                elif choice == "3":
                    self.switch_menu()
                elif choice == "4":
                    self.run_menu()
                elif choice == "5":
                    self.show_status()
                elif choice == "6":
                    self.show_help()
                elif choice == "7":
                    print("👋 Goodbye!")
                    break
                else:
                    print("Invalid choice. Please select 1-7.")
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
    
    def versions_menu(self):
        """Versions management submenu"""
        print("\n--- kubectl Versions ---")
        print("1. List available versions")
        print("2. List installed versions")
        print("3. Install version")
        print("4. Back to main menu")
        
        choice = input("Select option [1-4]: ").strip()
        
        if choice == "1":
            versions = self.fetch_available_versions()[:20]  # Show top 20
            print("\n📋 Latest available versions:")
            for i, version in enumerate(versions, 1):
                print(f"  {i:2}. v{version}")
                
        elif choice == "2":
            installed = self.get_installed_versions()
            if installed:
                print("\n📦 Installed versions:")
                for version in installed:
                    print(f"  ✅ v{version}")
            else:
                print("\n📦 No kubectl versions installed")
                
        elif choice == "3":
            version = input("Enter version to install (e.g., 1.29.0): ").strip()
            if version:
                self.download_kubectl(version)
    
    def configs_menu(self):
        """Configs management submenu"""
        print("\n--- Cluster Configs ---")
        print("1. List clusters")
        print("2. Add cluster")
        print("3. Remove cluster")
        print("4. Back to main menu")
        
        choice = input("Select option [1-4]: ").strip()
        
        if choice == "1":
            self.list_clusters()
        elif choice == "2":
            name = input("Cluster name: ").strip()
            path = input("Kubeconfig path: ").strip()
            if name and path:
                self.add_cluster(name, path)
        elif choice == "3":
            name = input("Cluster name to remove: ").strip()
            if name and name in self.config["clusters"]:
                del self.config["clusters"][name]
                self.save_config()
                print(f"✅ Removed cluster '{name}'")
            else:
                print("❌ Cluster not found")
    
    def switch_menu(self):
        """Switch cluster/version menu"""
        if not self.config["clusters"]:
            print("❌ No clusters configured")
            return
        
        print("\n--- Switch Configuration ---")
        print("Available clusters:")
        for i, name in enumerate(self.config["clusters"].keys(), 1):
            info = self.config["clusters"][name]
            kubectl_ver = info.get("kubectl_version", "none")
            print(f"  {i}. {name} (kubectl v{kubectl_ver})")
        
        try:
            choice = input("Select cluster number: ").strip()
            cluster_names = list(self.config["clusters"].keys())
            cluster_name = cluster_names[int(choice) - 1]
            self.use_cluster(cluster_name)
        except (ValueError, IndexError):
            print("❌ Invalid selection")
    
    def run_menu(self):
        """Run kubectl command menu"""
        if not self.config.get("active_cluster"):
            print("❌ No active cluster. Use option 3 to select one.")
            return
        
        command = input("Enter kubectl command (without 'kubectl'): ").strip()
        if command:
            args = command.split()
            self.run_kubectl(args)
    
    def show_help(self):
        """Show comprehensive help information"""
        help_text = """
🚀 kubectl Manager - Multi-version kubectl and cluster management tool

USAGE:
    ./kubectl-manager.py [COMMAND] [OPTIONS]
    ./kubectl-manager.py                    # Interactive mode (recommended for beginners)

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
    
    # Interactive mode (beginner-friendly)
    ./kubectl-manager.py

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
    ✅ Cross-platform support (Linux, macOS, Windows)

FILES:
    bin/kubectl-X.X.X                      # Downloaded kubectl binaries
    configs/cluster-name.yaml               # Imported kubeconfig files
    .kubectl-manager/config.json            # Tool configuration
    kubectl                                 # Smart wrapper script for direct usage
    kubectl-env.sh                          # Environment setup (optional)

COMPATIBILITY:
    kubectl supports ±1 minor version from cluster:
    • Cluster v1.31.x → kubectl v1.30.x, v1.31.x, v1.32.x ✅
    • Perfect match (same minor version) is recommended ⭐

For more help: https://github.com/your-username/kubectl-manager
Report issues: https://github.com/your-username/kubectl-manager/issues
"""
        print(help_text.strip())


def main():
    manager = KubectlManager()
    
    if len(sys.argv) == 1:
        # Interactive mode
        print("🚀 kubectl Manager - Multi-version kubectl and cluster management")
        manager.interactive_menu()
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
            manager.download_kubectl(args.version)
    
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
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()