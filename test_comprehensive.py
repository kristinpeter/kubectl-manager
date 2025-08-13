#!/usr/bin/env python3
"""
Comprehensive test suite for kubectl-manager
Tests functionality, security, edge cases, and production scenarios
"""
import pytest
import os
import sys
import tempfile
import shutil
import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import urllib.request
import ssl

# Add the project directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kubectl_manager import KubectlManager

class TestKubectlManagerComprehensive:
    """Comprehensive test suite for kubectl-manager"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests"""
        temp_dir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        os.chdir(temp_dir)
        yield Path(temp_dir)
        os.chdir(old_cwd)
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create manager instance in temp directory"""
        return KubectlManager()
    
    @pytest.fixture
    def mock_github_releases(self):
        """Mock GitHub releases API response"""
        return [
            {"tag_name": "v1.31.2", "prerelease": False},
            {"tag_name": "v1.31.1", "prerelease": False}, 
            {"tag_name": "v1.31.0", "prerelease": False},
            {"tag_name": "v1.30.8", "prerelease": False},
            {"tag_name": "v1.30.7", "prerelease": False},
            {"tag_name": "v1.29.12", "prerelease": False},
            {"tag_name": "v1.32.0-beta.1", "prerelease": True},  # Should be filtered out
        ]

    # === Core Functionality Tests ===
    
    def test_initialization(self, manager):
        """Test manager initialization creates required directories"""
        assert manager.bin_dir.exists()
        assert manager.configs_dir.exists()
        assert manager.meta_dir.exists()
        assert manager.cache_dir.exists()
        assert manager.config_file.exists()
    
    def test_version_sorting(self, manager):
        """Test version sorting handles semantic versioning correctly"""
        versions = ["1.29.1", "1.31.0", "1.30.2", "1.31.2", "1.30.10"]
        sorted_versions = sorted(versions, key=manager._version_sort_key, reverse=True)
        expected = ["1.31.2", "1.31.0", "1.30.10", "1.30.2", "1.29.1"]
        assert sorted_versions == expected
    
    def test_version_sorting_prerelease(self, manager):
        """Test version sorting handles pre-release versions"""
        versions = ["1.31.0", "1.31.0-beta.1", "1.31.0-rc.1", "1.30.8"]
        sorted_versions = sorted(versions, key=manager._version_sort_key, reverse=True)
        # Stable versions should come before pre-release of same version
        assert sorted_versions[0] == "1.31.0"
        assert "1.31.0-beta.1" in sorted_versions
        assert "1.30.8" in sorted_versions
    
    @patch('urllib.request.urlopen')
    def test_fetch_available_versions(self, mock_urlopen, manager, mock_github_releases):
        """Test fetching versions from GitHub API"""
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_github_releases).encode()
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        versions = manager.fetch_available_versions()
        assert len(versions) == 6  # Pre-release should be filtered out
        assert "1.31.2" in versions
        assert "1.32.0-beta.1" not in versions  # Pre-release filtered
    
    def test_major_minor_versions(self, manager):
        """Test major.minor version grouping"""
        with patch.object(manager, 'fetch_available_versions') as mock_fetch:
            mock_fetch.return_value = ["1.31.2", "1.31.1", "1.30.8", "1.30.7", "1.29.12"]
            
            major_minor = manager.get_major_minor_versions(limit=3)
            expected = ["1.31.x", "1.30.x", "1.29.x"]
            assert major_minor == expected
    
    # === Security Tests ===
    
    def test_input_validation_cluster_name(self, manager):
        """Test cluster name validation prevents malicious input"""
        valid_names = ["prod", "staging-env", "dev_cluster", "cluster.local"]
        invalid_names = [
            "../../../etc", "cluster; rm -rf /", "cluster && curl evil.com",
            "cluster$(rm -rf /)", "cluster\x00hidden", "a" * 101  # Too long
        ]
        
        for name in valid_names:
            assert manager._validate_cluster_name(name), f"Valid name rejected: {name}"
        
        for name in invalid_names:
            assert not manager._validate_cluster_name(name), f"Invalid name accepted: {name}"
    
    def test_input_validation_version(self, manager):
        """Test version validation prevents malicious input"""
        valid_versions = ["1.31.0", "1.30.12", "1.29.1-beta.1"]
        invalid_versions = [
            "../../../etc/passwd", "1.30.0; rm -rf /", "$(rm -rf /)",
            "`curl evil.com`", "1.30.0 && curl evil.com"
        ]
        
        for version in valid_versions:
            assert manager._validate_version(version), f"Valid version rejected: {version}"
        
        for version in invalid_versions:
            assert not manager._validate_version(version), f"Invalid version accepted: {version}"
    
    def test_command_injection_prevention(self, manager):
        """Test kubectl command argument validation"""
        safe_args = [
            ["get", "pods"],
            ["describe", "pod", "nginx"],
            ["apply", "-f", "deployment.yaml"],
            ["logs", "pod-name", "-c", "container"]
        ]
        
        dangerous_args = [
            ["get", "pods", ";", "rm", "-rf", "/"],
            ["get", "pods", "&&", "curl", "evil.com"],
            ["get", "pods", "|", "grep", "secret"],
            ["get", "pods", "$(rm -rf /)"],
            ["get", "pods", "`curl evil.com`"]
        ]
        
        for args in safe_args:
            assert manager._validate_kubectl_args(args), f"Safe args rejected: {args}"
        
        for args in dangerous_args:
            assert not manager._validate_kubectl_args(args), f"Dangerous args accepted: {args}"
    
    def test_path_traversal_protection(self, manager):
        """Test path traversal attack prevention"""
        safe_paths = ["config.yaml", "clusters/prod.yaml", "valid-file.yaml"]
        dangerous_paths = [
            "../../../etc/passwd", "/etc/passwd", "../../etc/hosts",
            "/proc/self/environ", "../../../root/.ssh/id_rsa"
        ]
        
        for path in safe_paths:
            assert manager._validate_path(path), f"Safe path rejected: {path}"
        
        for path in dangerous_paths:
            assert not manager._validate_path(path), f"Dangerous path accepted: {path}"
    
    def test_ssl_context_security(self, manager):
        """Test SSL context uses secure settings"""
        context = manager._create_secure_context()
        
        # Check minimum TLS version
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
        assert context.check_hostname is True
        assert context.verify_mode == ssl.CERT_REQUIRED
    
    def test_environment_sanitization(self, manager):
        """Test dangerous environment variables are filtered"""
        dangerous_env = {
            'LD_PRELOAD': '/evil/lib.so',
            'LD_LIBRARY_PATH': '/evil/path',
            'KUBECTL_EXTERNAL_DIFF': 'rm -rf /',
            'EDITOR': 'rm -rf /',
            'VISUAL': 'curl evil.com',
            'PATH': '/usr/bin:/bin',  # This should be preserved
            'HOME': '/home/user',    # This should be preserved
        }
        
        safe_env = manager._sanitize_environment(dangerous_env)
        
        # Dangerous variables should be removed
        assert 'LD_PRELOAD' not in safe_env
        assert 'LD_LIBRARY_PATH' not in safe_env
        assert 'KUBECTL_EXTERNAL_DIFF' not in safe_env
        assert 'EDITOR' not in safe_env
        assert 'VISUAL' not in safe_env
        
        # Safe variables should be preserved
        assert safe_env['PATH'] == '/usr/bin:/bin'
        assert safe_env['HOME'] == '/home/user'
    
    # === Functionality Tests ===
    
    def test_cluster_addition(self, manager, temp_dir):
        """Test adding cluster configuration"""
        # Create mock kubeconfig
        kubeconfig = temp_dir / "test-config.yaml"
        kubeconfig.write_text("""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://test-cluster.example.com
  name: test
""")
        
        with patch.object(manager, 'detect_cluster_version') as mock_detect:
            mock_detect.return_value = "1.31.0"
            
            with patch.object(manager, 'get_installed_versions') as mock_installed:
                mock_installed.return_value = ["1.31.2"]
                
                success = manager.add_cluster("test-cluster", str(kubeconfig))
                assert success
                
                # Check cluster was added to config
                assert "test-cluster" in manager.config["clusters"]
                cluster_config = manager.config["clusters"]["test-cluster"]
                assert cluster_config["cluster_version"] == "1.31.0"
                assert cluster_config["kubectl_version"] in ["1.31.2", "1.31.0"]
    
    def test_manual_kubectl_version_assignment(self, manager, temp_dir):
        """Test manually specifying kubectl version"""
        kubeconfig = temp_dir / "test-config.yaml"
        kubeconfig.write_text("apiVersion: v1\nkind: Config")
        
        with patch.object(manager, 'get_installed_versions') as mock_installed:
            mock_installed.return_value = ["1.30.0"]
            
            success = manager.add_cluster("test", str(kubeconfig), "1.30.0")
            assert success
            
            cluster_config = manager.config["clusters"]["test"]
            assert cluster_config["kubectl_version"] == "1.30.0"
            assert cluster_config["cluster_version"] == "manual"
    
    def test_cluster_version_detection_fallback(self, manager, temp_dir):
        """Test fallback when cluster version detection fails"""
        kubeconfig = temp_dir / "unreachable-config.yaml"
        kubeconfig.write_text("apiVersion: v1\nkind: Config")
        
        with patch.object(manager, 'detect_cluster_version') as mock_detect:
            mock_detect.return_value = None  # Simulate detection failure
            
            with patch.object(manager, 'fetch_available_versions') as mock_fetch:
                mock_fetch.return_value = ["1.31.2", "1.31.1"]
                
                with patch.object(manager, 'get_installed_versions') as mock_installed:
                    mock_installed.return_value = []
                    
                    success = manager.add_cluster("unreachable", str(kubeconfig))
                    # Should still succeed with fallback version
                    cluster_config = manager.config["clusters"]["unreachable"]
                    assert cluster_config["cluster_version"] == "unknown"
    
    def test_kubectl_binary_discovery(self, manager):
        """Test finding available kubectl binary"""
        # Mock installed versions
        with patch.object(manager, 'get_installed_versions') as mock_installed:
            mock_installed.return_value = ["1.31.0", "1.30.8"]
            
            # Mock file existence
            mock_path = MagicMock()
            mock_path.exists.return_value = True
            
            with patch.object(manager.bin_dir, '__truediv__', return_value=mock_path):
                binary = manager._find_kubectl_binary()
                assert binary is not None
    
    # === Edge Cases and Error Handling ===
    
    def test_invalid_kubeconfig_path(self, manager):
        """Test handling of invalid kubeconfig paths"""
        success = manager.add_cluster("test", "/nonexistent/path/config.yaml")
        assert not success
    
    def test_malformed_github_response(self, manager):
        """Test handling malformed GitHub API response"""
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = b"invalid json"
            mock_urlopen.return_value.__enter__.return_value = mock_response
            
            versions = manager.fetch_available_versions()
            assert versions == []  # Should return empty list on error
    
    def test_network_timeout(self, manager):
        """Test handling of network timeouts"""
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = Exception("Connection timeout")
            
            versions = manager.fetch_available_versions()
            assert versions == []
    
    def test_version_caching(self, manager, temp_dir):
        """Test version caching mechanism"""
        cache_file = manager.cache_dir / "available_versions.json"
        cached_data = ["1.31.0", "1.30.8"]
        
        with open(cache_file, 'w') as f:
            json.dump(cached_data, f)
        
        # Set modification time to recent
        import time
        os.utime(cache_file, (time.time(), time.time()))
        
        # Should use cache without network call
        with patch('urllib.request.urlopen') as mock_urlopen:
            versions = manager.fetch_available_versions()
            assert versions == cached_data
            mock_urlopen.assert_not_called()
    
    # === Production Scenario Tests ===
    
    def test_multi_cluster_workflow(self, manager, temp_dir):
        """Test complete multi-cluster workflow"""
        # Create multiple kubeconfig files
        configs = {
            "prod": "1.31.0",
            "staging": "1.30.8", 
            "dev": "1.29.12"
        }
        
        for name, version in configs.items():
            kubeconfig = temp_dir / f"{name}-config.yaml"
            kubeconfig.write_text(f"apiVersion: v1\nkind: Config\n# {name} cluster")
            
            with patch.object(manager, 'detect_cluster_version') as mock_detect:
                mock_detect.return_value = version
                
                with patch.object(manager, 'get_installed_versions') as mock_installed:
                    mock_installed.return_value = [version]
                    
                    success = manager.add_cluster(name, str(kubeconfig))
                    assert success
        
        # Test cluster listing
        assert len(manager.config["clusters"]) == 3
        for name in configs.keys():
            assert name in manager.config["clusters"]
    
    def test_kubectl_version_compatibility(self, manager):
        """Test kubectl version compatibility logic"""
        test_cases = [
            ("1.31.0", "1.31.2"),  # Same minor, should get latest patch
            ("1.30.5", "1.30.8"),  # Same minor, should get latest patch  
            ("1.29.1", "1.29.12"), # Same minor, should get latest patch
        ]
        
        for cluster_version, expected_kubectl in test_cases:
            with patch.object(manager, 'fetch_available_versions') as mock_fetch:
                mock_fetch.return_value = ["1.31.2", "1.30.8", "1.29.12", "1.28.5"]
                
                recommended = manager.get_recommended_kubectl_version(cluster_version)
                assert recommended == expected_kubectl
    
    def test_security_vulnerability_checking(self, manager):
        """Test vulnerability checking for kubectl versions"""
        with patch.object(manager, '_fetch_cve_data') as mock_cve:
            mock_cve.return_value = {
                '1.30.0': {
                    'cves': ['CVE-2023-1234'],
                    'severity': 'HIGH',
                    'description': 'Test vulnerability'
                }
            }
            
            result = manager._check_version_security('1.30.0')
            assert result['is_vulnerable'] is True
            assert 'CVE-2023-1234' in result['cves']
            assert result['severity'] == 'HIGH'
    
    def test_concurrent_operations(self, manager, temp_dir):
        """Test handling of concurrent operations"""
        import threading
        import time
        
        results = []
        
        def add_cluster_worker(name, delay):
            time.sleep(delay)
            kubeconfig = temp_dir / f"{name}-config.yaml"
            kubeconfig.write_text("apiVersion: v1\nkind: Config")
            
            with patch.object(manager, 'detect_cluster_version') as mock_detect:
                mock_detect.return_value = "1.31.0"
                with patch.object(manager, 'get_installed_versions') as mock_installed:
                    mock_installed.return_value = ["1.31.0"]
                    result = manager.add_cluster(name, str(kubeconfig))
                    results.append((name, result))
        
        # Start multiple threads
        threads = []
        for i in range(3):
            t = threading.Thread(target=add_cluster_worker, args=(f"cluster-{i}", i * 0.1))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # All operations should succeed
        assert len(results) == 3
        for name, success in results:
            assert success

    # === Performance Tests ===
    
    def test_initialization_performance(self, temp_dir):
        """Test manager initialization is fast"""
        import time
        
        start_time = time.time()
        manager = KubectlManager()
        init_time = time.time() - start_time
        
        # Should initialize in under 100ms
        assert init_time < 0.1
    
    def test_version_validation_performance(self, manager):
        """Test version validation performance"""
        import time
        
        versions = ["1.31.0"] * 1000
        
        start_time = time.time()
        for version in versions:
            manager._validate_version(version)
        validation_time = time.time() - start_time
        
        # Should validate 1000 versions in under 50ms
        assert validation_time < 0.05
    
    # === Integration Tests ===
    
    @patch('subprocess.run')
    def test_kubectl_execution(self, mock_subprocess, manager):
        """Test kubectl command execution with proper security"""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "pods are running"
        mock_subprocess.return_value = mock_result
        
        # Create mock kubectl binary
        kubectl_path = manager.bin_dir / "kubectl-1.31.0"
        kubectl_path.parent.mkdir(exist_ok=True)
        kubectl_path.touch()
        
        # Test command execution
        with patch.object(manager, 'get_installed_versions') as mock_installed:
            mock_installed.return_value = ["1.31.0"]
            
            result = manager._execute_kubectl(["get", "pods"], kubectl_path)
            
            # Verify subprocess was called with secure parameters
            mock_subprocess.assert_called_once()
            args, kwargs = mock_subprocess.call_args
            
            # Check timeout is set
            assert 'timeout' in kwargs
            # Check environment is sanitized
            assert 'env' in kwargs
    
    def test_file_permissions(self, manager, temp_dir):
        """Test that created files have secure permissions"""
        kubeconfig = temp_dir / "test-config.yaml"
        kubeconfig.write_text("test config")
        
        with patch.object(manager, 'detect_cluster_version') as mock_detect:
            mock_detect.return_value = "1.31.0"
            
            with patch.object(manager, 'get_installed_versions') as mock_installed:
                mock_installed.return_value = ["1.31.0"]
                
                manager.add_cluster("test", str(kubeconfig))
                
                # Check config file permissions
                config_file = manager.configs_dir / "test.yaml"
                assert config_file.exists()
                
                # Get file permissions (octal)
                permissions = oct(config_file.stat().st_mode)[-3:]
                assert permissions == "600"  # Should be readable/writable by owner only


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])