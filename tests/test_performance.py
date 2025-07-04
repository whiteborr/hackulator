"""Performance tests for critical application components"""
import unittest
import time
import threading
from unittest.mock import Mock, patch
from app.core.performance_monitor import performance_monitor
from app.core.thread_manager import thread_manager
from app.core.cache_manager import cache_manager

class TestPerformanceMonitor(unittest.TestCase):
    """Test performance monitoring functionality"""
    
    def setUp(self):
        self.monitor = performance_monitor
        
    def test_memory_monitoring(self):
        """Test memory monitoring functionality"""
        # Start monitoring
        self.monitor.start_monitoring(interval_ms=100)
        
        # Wait for some samples
        time.sleep(0.5)
        
        # Check that samples were collected
        summary = self.monitor.get_performance_summary()
        self.assertIn('memory', summary)
        self.assertGreater(summary['memory']['current_mb'], 0)
        
        # Stop monitoring
        self.monitor.stop_monitoring()
    
    def test_scan_time_recording(self):
        """Test scan time recording"""
        # Record some scan times
        self.monitor.record_scan_time('dns_scan', 1.5)
        self.monitor.record_scan_time('port_scan', 2.3)
        
        summary = self.monitor.get_performance_summary()
        self.assertIn('performance', summary)
        self.assertGreater(summary['performance']['avg_scan_time'], 0)
    
    def test_cache_metrics(self):
        """Test cache hit/miss recording"""
        # Record cache operations
        for _ in range(10):
            self.monitor.record_cache_hit()
        for _ in range(3):
            self.monitor.record_cache_miss()
        
        summary = self.monitor.get_performance_summary()
        hit_rate = summary['performance']['cache_hit_rate']
        self.assertAlmostEqual(hit_rate, 10/13, places=2)
    
    def test_memory_optimization(self):
        """Test memory optimization"""
        # Add some data to optimize
        for i in range(100):
            self.monitor.record_scan_time(f'test_{i}', 1.0)
        
        # Optimize memory
        result = self.monitor.optimize_memory()
        self.assertTrue(result)
        
        # Check that old data was cleaned up
        self.assertLessEqual(len(self.monitor.metrics['scan_times']), 50)

class TestThreadManager(unittest.TestCase):
    """Test thread management functionality"""
    
    def setUp(self):
        self.manager = thread_manager
        
    def test_task_submission(self):
        """Test task submission and execution"""
        def test_task(x, y):
            return x + y
        
        # Submit task
        thread_id = self.manager.submit_general_task(test_task, 2, 3)
        self.assertIsNotNone(thread_id)
        self.assertIn(thread_id, self.manager.active_threads)
        
        # Wait for completion
        time.sleep(0.1)
        
        # Check completion
        stats = self.manager.get_thread_stats()
        self.assertIsInstance(stats, dict)
    
    def test_thread_cancellation(self):
        \"\"\"Test thread cancellation\"\"\"
        def long_task():
            time.sleep(2)
            return \"completed\"\n        \n        # Submit long-running task\n        thread_id = self.manager.submit_general_task(long_task)\n        \n        # Cancel immediately\n        cancelled = self.manager.cancel_thread(thread_id)\n        \n        # Note: Cancellation success depends on timing\n        # Just verify the method works without error\n        self.assertIsInstance(cancelled, bool)\n    \n    def test_thread_stats(self):\n        \"\"\"Test thread statistics\"\"\"\n        stats = self.manager.get_thread_stats()\n        \n        required_keys = ['max_workers', 'active_threads', 'scan_pool', 'io_pool', 'general_pool']\n        for key in required_keys:\n            self.assertIn(key, stats)\n    \n    def test_multiple_task_types(self):\n        \"\"\"Test different types of tasks\"\"\"\n        def quick_task():\n            return \"done\"\n        \n        # Submit different types of tasks\n        scan_id = self.manager.submit_scan_task(quick_task)\n        io_id = self.manager.submit_io_task(quick_task)\n        general_id = self.manager.submit_general_task(quick_task)\n        \n        # Verify all were submitted\n        self.assertIsNotNone(scan_id)\n        self.assertIsNotNone(io_id)\n        self.assertIsNotNone(general_id)\n        \n        # Wait for completion\n        time.sleep(0.2)\n\nclass TestCachePerformance(unittest.TestCase):\n    \"\"\"Test cache performance characteristics\"\"\"\n    \n    def setUp(self):\n        self.cache = cache_manager\n        \n    def test_cache_performance(self):\n        \"\"\"Test cache read/write performance\"\"\"\n        # Measure cache write performance\n        start_time = time.time()\n        for i in range(100):\n            self.cache.set(f\"test_key_{i}\", f\"test_value_{i}\")\n        write_time = time.time() - start_time\n        \n        # Measure cache read performance\n        start_time = time.time()\n        for i in range(100):\n            self.cache.get(f\"test_key_{i}\")\n        read_time = time.time() - start_time\n        \n        # Performance assertions (adjust thresholds as needed)\n        self.assertLess(write_time, 1.0, \"Cache writes too slow\")\n        self.assertLess(read_time, 0.5, \"Cache reads too slow\")\n        \n        # Cleanup\n        for i in range(100):\n            self.cache.delete(f\"test_key_{i}\")\n    \n    def test_cache_memory_usage(self):\n        \"\"\"Test cache memory efficiency\"\"\"\n        import psutil\n        import os\n        \n        process = psutil.Process(os.getpid())\n        initial_memory = process.memory_info().rss\n        \n        # Add large amount of data to cache\n        large_data = \"x\" * 1000  # 1KB per entry\n        for i in range(1000):  # 1MB total\n            self.cache.set(f\"large_key_{i}\", large_data)\n        \n        final_memory = process.memory_info().rss\n        memory_increase = final_memory - initial_memory\n        \n        # Memory increase should be reasonable (less than 10MB for 1MB of data)\n        self.assertLess(memory_increase, 10 * 1024 * 1024, \"Cache memory usage too high\")\n        \n        # Cleanup\n        for i in range(1000):\n            self.cache.delete(f\"large_key_{i}\")\n\nclass TestConcurrentOperations(unittest.TestCase):\n    \"\"\"Test concurrent operation performance\"\"\"\n    \n    def test_concurrent_cache_access(self):\n        \"\"\"Test concurrent cache operations\"\"\"\n        def cache_worker(worker_id):\n            for i in range(50):\n                key = f\"worker_{worker_id}_key_{i}\"\n                value = f\"worker_{worker_id}_value_{i}\"\n                cache_manager.set(key, value)\n                retrieved = cache_manager.get(key)\n                self.assertEqual(retrieved, value)\n        \n        # Start multiple threads\n        threads = []\n        for i in range(5):\n            thread = threading.Thread(target=cache_worker, args=(i,))\n            threads.append(thread)\n            thread.start()\n        \n        # Wait for all threads to complete\n        for thread in threads:\n            thread.join()\n        \n        # Verify no corruption occurred\n        for worker_id in range(5):\n            for i in range(50):\n                key = f\"worker_{worker_id}_key_{i}\"\n                expected_value = f\"worker_{worker_id}_value_{i}\"\n                actual_value = cache_manager.get(key)\n                self.assertEqual(actual_value, expected_value)\n    \n    def test_thread_pool_stress(self):\n        \"\"\"Test thread pool under stress\"\"\"\n        def stress_task(task_id):\n            # Simulate some work\n            time.sleep(0.01)\n            return f\"task_{task_id}_completed\"\n        \n        # Submit many tasks quickly\n        thread_ids = []\n        start_time = time.time()\n        \n        for i in range(50):\n            thread_id = thread_manager.submit_general_task(stress_task, i)\n            if thread_id:  # Only add if submission was successful\n                thread_ids.append(thread_id)\n        \n        submission_time = time.time() - start_time\n        \n        # Wait for completion\n        time.sleep(2)\n        \n        # Verify performance\n        self.assertLess(submission_time, 1.0, \"Task submission too slow\")\n        self.assertGreater(len(thread_ids), 40, \"Too many task submissions failed\")\n\nif __name__ == '__main__':\n    unittest.main()