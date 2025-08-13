#!/usr/bin/env python3
"""
Production Scenario Tests for kubectl-manager
Tests real-world usage patterns and edge cases
"""
import pytest
import os
import sys
import tempfile
import shutil
import json
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kubectl_manager import KubectlManager

class TestProductionScenarios:
    """Test real-world production scenarios"""
    
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

    # === Production Workflow Tests ===
    
    def test_complete_onboarding_workflow(self, manager, temp_dir):
        """Test complete user onboarding workflow from scratch"""
        # Simulate first-time user experience
        print("\n🚀 Testing complete onboarding workflow...")
        
        # 1. First run should auto-download kubectl
        with patch.object(manager, 'fetch_available_versions') as mock_fetch:
            mock_fetch.return_value = ["1.31.2", "1.31.1", "1.30.8"]
            
            with patch.object(manager, 'download_kubectl') as mock_download:
                mock_download.return_value = True
                
                # Fresh manager instance should trigger auto-download
                fresh_manager = KubectlManager()
                
                # Should have attempted download
                mock_download.assert_called_with("1.31.2", force=True)
        
        # 2. Add first cluster
        kubeconfig = temp_dir / "prod-config.yaml"
        kubeconfig.write_text("""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://prod-k8s.company.com
  name: production
contexts:
- context:
    cluster: production
    user: admin
  name: prod-admin
current-context: prod-admin
""")
        
        with patch.object(manager, 'detect_cluster_version') as mock_detect:
            mock_detect.return_value = "1.31.0"
            
            with patch.object(manager, 'get_installed_versions') as mock_installed:
                mock_installed.return_value = ["1.31.2"]
                
                success = manager.add_cluster("production", str(kubeconfig))
                assert success
                
                print("✅ Production cluster added successfully")
        
        # 3. Add staging cluster
        staging_config = temp_dir / "staging-config.yaml"
        staging_config.write_text("""
apiVersion: v1  
kind: Config
clusters:
- cluster:
    server: https://staging-k8s.company.com
  name: staging
""")
        
        with patch.object(manager, 'detect_cluster_version') as mock_detect:
            mock_detect.return_value = "1.30.8"
            
            with patch.object(manager, 'get_installed_versions') as mock_installed:
                mock_installed.return_value = ["1.31.2", "1.30.8"]
                
                success = manager.add_cluster("staging", str(staging_config))
                assert success
                
                print("✅ Staging cluster added successfully")
        
        # 4. Test cluster switching
        assert "production" in manager.config["clusters"]
        assert "staging" in manager.config["clusters"]
        
        # 5. Test status overview
        manager.list_clusters()
        
        print("🎉 Complete onboarding workflow test passed!")
    
    def test_enterprise_multi_cluster_management(self, manager, temp_dir):
        """Test managing multiple clusters in enterprise environment"""
        print("\n🏢 Testing enterprise multi-cluster management...")
        
        # Simulate enterprise with many clusters
        clusters = {
            "prod-us-east": ("1.31.0", "https://prod-use1.k8s.company.com"),
            "prod-us-west": ("1.31.0", "https://prod-usw1.k8s.company.com"),
            "prod-eu-west": ("1.30.8", "https://prod-euw1.k8s.company.com"),
            "staging-shared": ("1.31.2", "https://staging.k8s.company.com"),
            "dev-team-alpha": ("1.32.0", "https://dev-alpha.k8s.company.com"),
            "dev-team-beta": ("1.31.0", "https://dev-beta.k8s.company.com"),
            "test-integration": ("1.29.12", "https://test.k8s.company.com"),
            "dr-backup": ("1.30.8", "https://dr.k8s.company.com"),
        }
        
        # Add all clusters
        for name, (version, server) in clusters.items():
            kubeconfig = temp_dir / f"{name}-config.yaml"
            kubeconfig.write_text(f"""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: {server}
  name: {name}
contexts:
- context:
    cluster: {name}
    user: admin
  name: {name}-admin
current-context: {name}-admin
""")
            
            with patch.object(manager, 'detect_cluster_version') as mock_detect:
                mock_detect.return_value = version
                
                with patch.object(manager, 'get_installed_versions') as mock_installed:
                    # Simulate having some versions installed
                    mock_installed.return_value = ["1.31.2", "1.31.0", "1.30.8"]
                    
                    success = manager.add_cluster(name, str(kubeconfig))
                    assert success
        
        # Verify all clusters are managed
        assert len(manager.config["clusters"]) == len(clusters)
        
        # Test cluster listing with many clusters
        manager.list_clusters()
        
        # Test version diversity is handled
        unique_versions = set(version for version, _ in clusters.values())
        print(f"✅ Managing {len(clusters)} clusters with {len(unique_versions)} different K8s versions")
        
        print("🎉 Enterprise multi-cluster management test passed!")
    
    def test_cluster_connectivity_issues(self, manager, temp_dir):
        """Test handling of various cluster connectivity issues"""
        print("\n🔌 Testing cluster connectivity issues...")
        
        test_cases = [
            ("unreachable-cluster", None, "Cluster completely unreachable"),
            ("timeout-cluster", "timeout", "Cluster times out during detection"),
            ("auth-failed", "auth-error", "Authentication failures"),
            ("network-error", "network", "Network connectivity issues"),
        ]
        
        for cluster_name, error_type, description in test_cases:
            print(f"  Testing: {description}")
            
            kubeconfig = temp_dir / f"{cluster_name}-config.yaml"
            kubeconfig.write_text(f"""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://{cluster_name}.example.com
  name: {cluster_name}
""")
            
            with patch.object(manager, 'detect_cluster_version') as mock_detect:
                if error_type == "timeout":
                    mock_detect.side_effect = subprocess.TimeoutExpired("kubectl", 30)
                elif error_type == "auth-error":
                    mock_detect.side_effect = subprocess.CalledProcessError(1, "kubectl")
                elif error_type == "network":
                    mock_detect.side_effect = ConnectionError("Network unreachable")
                else:
                    mock_detect.return_value = None  # Unreachable
                
                with patch.object(manager, 'get_installed_versions') as mock_installed:
                    mock_installed.return_value = ["1.31.0"]
                    
                    with patch.object(manager, 'fetch_available_versions') as mock_fetch:
                        mock_fetch.return_value = ["1.31.2", "1.31.1"]
                        
                        # Should still succeed with fallback
                        success = manager.add_cluster(cluster_name, str(kubeconfig))
                        assert success
                        
                        # Should mark as unknown version
                        cluster_config = manager.config["clusters"][cluster_name]
                        assert cluster_config["cluster_version"] == "unknown"
        
        print("✅ All connectivity issue scenarios handled correctly")
        print("🎉 Cluster connectivity issues test passed!")
    
    def test_kubectl_version_conflicts(self, manager, temp_dir):
        """Test handling kubectl version conflicts and resolution"""
        print("\n⚔️  Testing kubectl version conflicts...")
        
        # Scenario: User has old kubectl versions, needs newer ones
        existing_versions = ["1.28.5", "1.29.0", "1.29.8"]
        
        with patch.object(manager, 'get_installed_versions') as mock_installed:
            mock_installed.return_value = existing_versions.copy()
            
            # Add cluster requiring newer kubectl
            kubeconfig = temp_dir / "new-cluster-config.yaml" 
            kubeconfig.write_text("""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://new-k8s.company.com
  name: new-cluster
""")
            
            with patch.object(manager, 'detect_cluster_version') as mock_detect:
                mock_detect.return_value = "1.31.0"  # Newer than installed versions
                
                with patch.object(manager, 'download_kubectl') as mock_download:
                    mock_download.return_value = True
                    
                    with patch.object(manager, 'fetch_available_versions') as mock_fetch:
                        mock_fetch.return_value = ["1.31.2", "1.31.1", "1.31.0"]
                        
                        success = manager.add_cluster("new-cluster", str(kubeconfig))
                        assert success
                        
                        # Should have attempted to download compatible version
                        mock_download.assert_called()
        
        print("✅ kubectl version conflict resolution working")
        print("🎉 kubectl version conflicts test passed!")
    
    def test_manual_version_override_scenarios(self, manager, temp_dir):
        """Test various manual version override scenarios"""
        print("\n🔧 Testing manual version override scenarios...")
        
        scenarios = [
            ("air-gapped-cluster", "1.30.5", "Air-gapped environment with specific kubectl"),
            ("legacy-cluster", "1.28.8", "Legacy cluster requiring older kubectl"), 
            ("beta-testing", "1.32.0", "Beta cluster with cutting-edge kubectl"),
            ("compliance-cluster", "1.30.12", "Compliance requirement for specific version"),
        ]
        
        for cluster_name, manual_version, description in scenarios:
            print(f"  Testing: {description}")
            
            kubeconfig = temp_dir / f"{cluster_name}-config.yaml"
            kubeconfig.write_text(f"""
apiVersion: v1
kind: Config  
clusters:
- cluster:
    server: https://{cluster_name}.company.com
  name: {cluster_name}
""")
            
            with patch.object(manager, 'get_installed_versions') as mock_installed:
                mock_installed.return_value = [manual_version]
                
                # Use manual version override
                success = manager.add_cluster(cluster_name, str(kubeconfig), manual_version)
                assert success
                
                # Verify manual version is used
                cluster_config = manager.config["clusters"][cluster_name]
                assert cluster_config["kubectl_version"] == manual_version
                assert cluster_config["cluster_version"] == "manual"
        
        # Test changing manual version for existing cluster
        print("  Testing version change for existing cluster...")
        
        with patch.object(manager, 'get_installed_versions') as mock_installed:
            mock_installed.return_value = ["1.31.0"]
            
            success = manager.set_cluster_kubectl_version("compliance-cluster", "1.31.0")
            assert success
            
            # Verify version was updated
            cluster_config = manager.config["clusters"]["compliance-cluster"]
            assert cluster_config["kubectl_version"] == "1.31.0"
        
        print("✅ All manual override scenarios working")
        print("🎉 Manual version override test passed!")
    
    def test_concurrent_cluster_operations(self, manager, temp_dir):
        """Test concurrent operations on clusters"""
        print("\n🔄 Testing concurrent cluster operations...")
        
        results = []
        errors = []
        
        def add_cluster_worker(worker_id):
            try:
                cluster_name = f"concurrent-cluster-{worker_id}"
                kubeconfig = temp_dir / f"{cluster_name}-config.yaml"
                kubeconfig.write_text(f"""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://{cluster_name}.company.com
  name: {cluster_name}
""")
                
                # Simulate some processing time
                time.sleep(worker_id * 0.1)
                
                with patch.object(manager, 'detect_cluster_version') as mock_detect:
                    mock_detect.return_value = f"1.3{worker_id}.0"
                    
                    with patch.object(manager, 'get_installed_versions') as mock_installed:
                        mock_installed.return_value = [f"1.3{worker_id}.0"]
                        
                        success = manager.add_cluster(cluster_name, str(kubeconfig))
                        results.append((worker_id, success))
                        
            except Exception as e:
                errors.append((worker_id, str(e)))
        
        # Start multiple worker threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=add_cluster_worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all to complete
        for t in threads:
            t.join()
        
        # Verify results
        assert len(results) == 5, f"Expected 5 results, got {len(results)}"
        assert len(errors) == 0, f"Got errors: {errors}"
        
        for worker_id, success in results:
            assert success, f"Worker {worker_id} failed"
            assert f"concurrent-cluster-{worker_id}" in manager.config["clusters"]
        
        print("✅ Concurrent operations handled correctly")
        print("🎉 Concurrent cluster operations test passed!")
    
    def test_resource_constraints(self, manager, temp_dir):
        """Test behavior under resource constraints"""
        print("\n💾 Testing resource constraint handling...")
        
        # Test with limited disk space simulation
        with patch('shutil.copy2') as mock_copy:
            mock_copy.side_effect = OSError("No space left on device")
            
            kubeconfig = temp_dir / "big-cluster-config.yaml"
            kubeconfig.write_text("apiVersion: v1\nkind: Config")
            
            success = manager.add_cluster("space-constrained", str(kubeconfig))
            assert not success  # Should fail gracefully
        
        # Test with network timeout simulation
        with patch.object(manager, 'fetch_available_versions') as mock_fetch:
            mock_fetch.side_effect = Exception("Network timeout")
            
            # Should handle network issues gracefully
            versions = manager.fetch_available_versions()
            assert versions == []
        
        print("✅ Resource constraints handled gracefully")
        print("🎉 Resource constraint test passed!")
    
    def test_security_policy_compliance(self, manager, temp_dir):
        """Test compliance with enterprise security policies"""
        print("\n🔐 Testing security policy compliance...")
        
        # Test file permissions compliance
        kubeconfig = temp_dir / "secure-config.yaml"
        kubeconfig.write_text("""
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://secure.company.com
  name: secure
""")
        
        with patch.object(manager, 'detect_cluster_version') as mock_detect:
            mock_detect.return_value = "1.31.0"
            
            with patch.object(manager, 'get_installed_versions') as mock_installed:
                mock_installed.return_value = ["1.31.0"]
                
                success = manager.add_cluster("secure", str(kubeconfig))
                assert success
                
                # Check that config file has secure permissions
                config_file = manager.configs_dir / "secure.yaml"
                if config_file.exists():
                    permissions = oct(config_file.stat().st_mode)[-3:]
                    assert permissions == "600", f"Insecure permissions: {permissions}"
        
        # Test rejection of dangerous inputs
        dangerous_inputs = [
            ("../../../etc", "passwd"),  # Path traversal
            ("test; rm -rf /", "config.yaml"),  # Command injection
            ("test$(rm -rf /)", "config.yaml"),  # Command substitution
        ]
        
        for cluster_name, config_file in dangerous_inputs:
            success = manager.add_cluster(cluster_name, config_file)
            assert not success, f"Dangerous input accepted: {cluster_name}, {config_file}"
        
        print("✅ Security policies enforced correctly")
        print("🎉 Security policy compliance test passed!")
    
    def test_disaster_recovery_scenarios(self, manager, temp_dir):
        """Test disaster recovery and backup/restore scenarios"""
        print("\n🆘 Testing disaster recovery scenarios...")
        
        # Set up initial clusters
        clusters = ["prod", "staging", "dev"]
        for cluster in clusters:
            kubeconfig = temp_dir / f"{cluster}-config.yaml"
            kubeconfig.write_text(f"apiVersion: v1\nkind: Config\n# {cluster}")
            
            with patch.object(manager, 'detect_cluster_version') as mock_detect:
                mock_detect.return_value = "1.31.0"
                
                with patch.object(manager, 'get_installed_versions') as mock_installed:
                    mock_installed.return_value = ["1.31.0"]
                    
                    manager.add_cluster(cluster, str(kubeconfig))
        
        # Backup configuration
        backup_data = manager.config.copy()
        
        # Simulate disaster - corrupt configuration
        manager.config = {"clusters": {}, "settings": manager.config["settings"]}
        manager.save_config()
        
        # Verify data loss
        assert len(manager.config["clusters"]) == 0
        
        # Restore from backup
        manager.config = backup_data
        manager.save_config()
        
        # Verify recovery
        assert len(manager.config["clusters"]) == 3
        for cluster in clusters:
            assert cluster in manager.config["clusters"]
        
        print("✅ Disaster recovery successful")
        print("🎉 Disaster recovery test passed!")
    
    def test_upgrade_compatibility(self, manager, temp_dir):
        """Test compatibility across version upgrades"""
        print("\n🔄 Testing upgrade compatibility...")
        
        # Simulate old config format
        old_config = {
            "clusters": {
                "legacy": {
                    "cluster_version": "1.28.0",
                    "kubectl_version": "1.28.5",
                    "config_path": "legacy.yaml"
                    # Missing new fields that might be added in future versions
                }
            },
            "settings": manager.config["settings"]
        }
        
        # Save old format config
        with open(manager.config_file, 'w') as f:
            json.dump(old_config, f)
        
        # Load config with new manager version
        new_manager = KubectlManager()
        
        # Should handle old format gracefully
        assert "legacy" in new_manager.config["clusters"]
        assert new_manager.config["clusters"]["legacy"]["cluster_version"] == "1.28.0"
        
        # Adding new cluster should work with mixed formats
        kubeconfig = temp_dir / "new-config.yaml"
        kubeconfig.write_text("apiVersion: v1\nkind: Config")
        
        with patch.object(new_manager, 'detect_cluster_version') as mock_detect:
            mock_detect.return_value = "1.31.0"
            
            with patch.object(new_manager, 'get_installed_versions') as mock_installed:
                mock_installed.return_value = ["1.31.0"]
                
                success = new_manager.add_cluster("new", str(kubeconfig))
                assert success
        
        # Both old and new clusters should coexist
        assert "legacy" in new_manager.config["clusters"]
        assert "new" in new_manager.config["clusters"]
        
        print("✅ Upgrade compatibility maintained")
        print("🎉 Upgrade compatibility test passed!")

    # === Performance Under Load Tests ===
    
    def test_large_scale_cluster_management(self, manager, temp_dir):
        """Test managing large numbers of clusters"""
        print("\n📊 Testing large-scale cluster management...")
        
        # Create 50 clusters (simulating large enterprise)
        cluster_count = 50
        
        start_time = time.time()
        
        for i in range(cluster_count):
            cluster_name = f"cluster-{i:03d}"
            kubeconfig = temp_dir / f"{cluster_name}-config.yaml"
            kubeconfig.write_text(f"apiVersion: v1\nkind: Config\n# cluster {i}")
            
            with patch.object(manager, 'detect_cluster_version') as mock_detect:
                mock_detect.return_value = f"1.{30 + (i % 3)}.0"  # Mix of versions
                
                with patch.object(manager, 'get_installed_versions') as mock_installed:
                    mock_installed.return_value = ["1.30.0", "1.31.0", "1.32.0"]
                    
                    success = manager.add_cluster(cluster_name, str(kubeconfig))
                    assert success
        
        total_time = time.time() - start_time
        
        # Verify all clusters added
        assert len(manager.config["clusters"]) == cluster_count
        
        # Performance check - should handle 50 clusters in reasonable time
        avg_time_per_cluster = total_time / cluster_count
        assert avg_time_per_cluster < 0.1, f"Too slow: {avg_time_per_cluster:.3f}s per cluster"
        
        # Test listing performance with many clusters
        list_start = time.time()
        manager.list_clusters()
        list_time = time.time() - list_start
        assert list_time < 1.0, f"Cluster listing too slow: {list_time:.3f}s"
        
        print(f"✅ Managed {cluster_count} clusters in {total_time:.2f}s")
        print(f"✅ Average {avg_time_per_cluster:.3f}s per cluster")
        print("🎉 Large-scale management test passed!")


if __name__ == "__main__":
    # Run production scenario tests
    pytest.main([__file__, "-v", "-s", "--tb=short"])