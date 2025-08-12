#!/usr/bin/env python3
"""
Basic test suite for kubectl-manager.py - focuses on simple functionality tests
"""

import unittest
import tempfile
import shutil
import os
import sys
import importlib.util
from pathlib import Path

# Load the main module
spec = importlib.util.spec_from_file_location("kubectl_manager", "kubectl-manager.py")
kubectl_manager = importlib.util.module_from_spec(spec)
sys.modules["kubectl_manager"] = kubectl_manager
spec.loader.exec_module(kubectl_manager)
from kubectl_manager import KubectlManager


class TestBasicFunctionality(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        self.manager = KubectlManager()

    def tearDown(self):
        """Clean up test environment"""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_manager_initialization(self):
        """Test that KubectlManager initializes properly"""
        self.assertIsInstance(self.manager, KubectlManager)

    def test_directories_created(self):
        """Test that necessary directories are created"""
        self.assertTrue(self.manager.bin_dir.exists())
        self.assertTrue(self.manager.configs_dir.exists())
        self.assertTrue(self.manager.meta_dir.exists())

    def test_config_loaded(self):
        """Test that configuration is loaded"""
        self.assertIsInstance(self.manager.config, dict)
        self.assertIn('clusters', self.manager.config)

    def test_cluster_name_validation_valid(self):
        """Test valid cluster names"""
        valid_names = ["test-cluster", "cluster_123", "my.cluster"]
        for name in valid_names:
            self.assertTrue(self.manager._validate_cluster_name(name))

    def test_cluster_name_validation_invalid(self):
        """Test invalid cluster names"""
        invalid_names = ["../evil", "", "a" * 200, "cluster;rm"]
        for name in invalid_names:
            self.assertFalse(self.manager._validate_cluster_name(name))

    def test_version_validation_valid(self):
        """Test valid version strings"""
        valid_versions = ["1.30.0", "v1.30.0"]
        for version in valid_versions:
            self.assertTrue(self.manager._validate_version(version))

    def test_version_validation_invalid(self):
        """Test invalid version strings"""
        invalid_versions = ["", "invalid", "../etc", "1.30.0; rm -rf /"]
        for version in invalid_versions:
            self.assertFalse(self.manager._validate_version(version))

    def test_file_path_validation(self):
        """Test file path safety validation"""
        # Safe paths
        safe_paths = ["configs/cluster.yaml", "bin/kubectl"]
        for path in safe_paths:
            self.assertTrue(self.manager._is_safe_file_path(path))
        
        # Dangerous paths
        dangerous_paths = ["../../../etc/passwd", "/etc/passwd"]
        for path in dangerous_paths:
            self.assertFalse(self.manager._is_safe_file_path(path))

    def test_version_sorting(self):
        """Test version sorting functionality"""
        versions = ["1.29.0", "1.30.0", "1.28.5"]
        sorted_versions = sorted(versions, key=self.manager._version_sort_key)
        self.assertEqual(sorted_versions[0], "1.28.5")
        self.assertEqual(sorted_versions[-1], "1.30.0")

    def test_platform_info(self):
        """Test platform detection"""
        os_name, arch = self.manager.get_platform_info()
        self.assertIsInstance(os_name, str)
        self.assertIsInstance(arch, str)
        self.assertIn(os_name, ['linux', 'darwin', 'windows'])

    def test_get_installed_versions(self):
        """Test getting installed kubectl versions"""
        versions = self.manager.get_installed_versions()
        self.assertIsInstance(versions, list)

    def test_kubectl_args_validation_safe(self):
        """Test safe kubectl arguments pass validation"""
        safe_args = ["get", "pods", "-n", "default"]
        result = self.manager._validate_kubectl_args(safe_args)
        self.assertEqual(result, safe_args)

    def test_kubectl_args_validation_dangerous(self):
        """Test dangerous kubectl arguments are rejected"""
        dangerous_args = ["get", "pods;", "rm", "-rf", "/"]
        with self.assertRaises(ValueError):
            self.manager._validate_kubectl_args(dangerous_args)

    def test_security_check_version(self):
        """Test version security checking"""
        security_info = self.manager._check_version_security("1.30.0")
        self.assertIsInstance(security_info, dict)
        self.assertIn('is_vulnerable', security_info)

    def test_ssl_context_creation(self):
        """Test SSL context for secure downloads"""
        context = self.manager._create_secure_context()
        import ssl
        self.assertIsInstance(context, ssl.SSLContext)

    def test_secure_environment_creation(self):
        """Test creation of secure environment for subprocess"""
        env = self.manager._create_secure_environment()
        self.assertIsInstance(env, dict)
        
        # Should not contain dangerous variables
        dangerous_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'KUBECTL_EXTERNAL_DIFF']
        for var in dangerous_vars:
            self.assertNotIn(var, env)

    def test_diagnostics_system(self):
        """Test system diagnostics"""
        diagnostics = self.manager.diagnose_system()
        self.assertIsInstance(diagnostics, dict)
        self.assertIn('system', diagnostics)
        self.assertIn('kubectl_manager', diagnostics)


if __name__ == '__main__':
    unittest.main(verbosity=2)