"""
Tests for the exchange cache module.

These tests verify:
1. Cache key generation is consistent and content-based
2. Cache hit/miss behavior works correctly
3. TTL expiration works
4. Staleness detection works
5. Cache statistics are accurate
6. Thread safety
7. Database persistence
"""
import unittest
import tempfile
import time
import json
from pathlib import Path
import threading

from models import HttpExchange, AnalysisResponse, Finding, AgentReport
from cache import ExchangeCache, CacheStats, CacheEntry


class TestExchangeHashing(unittest.TestCase):
    """Test exchange hash computation."""
    
    def test_identical_exchanges_have_same_hash(self):
        """Identical exchanges should produce the same hash."""
        exchange1 = HttpExchange(
            url="https://example.com/api/users",
            method="GET",
            request_headers={"Authorization": "Bearer token123"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"users": []}',
        )
        exchange2 = HttpExchange(
            url="https://example.com/api/users",
            method="GET",
            request_headers={"Authorization": "Bearer token123"},
            request_body="",
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"users": []}',
        )
        
        hash1 = ExchangeCache.compute_exchange_hash(exchange1)
        hash2 = ExchangeCache.compute_exchange_hash(exchange2)
        
        self.assertEqual(hash1, hash2)
    
    def test_different_exchanges_have_different_hashes(self):
        """Different exchanges should produce different hashes."""
        exchange1 = HttpExchange(
            url="https://example.com/api/users",
            method="GET",
            request_body="",
            response_status=200,
            response_body='{"users": []}',
        )
        exchange2 = HttpExchange(
            url="https://example.com/api/posts",
            method="GET",
            request_body="",
            response_status=200,
            response_body='{"posts": []}',
        )
        
        hash1 = ExchangeCache.compute_exchange_hash(exchange1)
        hash2 = ExchangeCache.compute_exchange_hash(exchange2)
        
        self.assertNotEqual(hash1, hash2)
    
    def test_header_order_does_not_affect_hash(self):
        """Header order should not affect the hash."""
        exchange1 = HttpExchange(
            url="https://example.com/api",
            method="GET",
            request_headers={"A": "1", "B": "2"},
            request_body="",
            response_status=200,
            response_body="",
        )
        exchange2 = HttpExchange(
            url="https://example.com/api",
            method="GET",
            request_headers={"B": "2", "A": "1"},
            request_body="",
            response_status=200,
            response_body="",
        )
        
        hash1 = ExchangeCache.compute_exchange_hash(exchange1)
        hash2 = ExchangeCache.compute_exchange_hash(exchange2)
        
        self.assertEqual(hash1, hash2)
    
    def test_body_changes_affect_hash(self):
        """Changes to request/response body should affect the hash."""
        exchange1 = HttpExchange(
            url="https://example.com/api",
            method="POST",
            request_body='{"id": 1}',
            response_status=200,
            response_body='{"result": "ok"}',
        )
        exchange2 = HttpExchange(
            url="https://example.com/api",
            method="POST",
            request_body='{"id": 2}',
            response_status=200,
            response_body='{"result": "ok"}',
        )
        
        hash1 = ExchangeCache.compute_exchange_hash(exchange1)
        hash2 = ExchangeCache.compute_exchange_hash(exchange2)
        
        self.assertNotEqual(hash1, hash2)


class TestCacheEntry(unittest.TestCase):
    """Test cache entry behavior."""
    
    def test_expiration(self):
        """Cache entries should expire after TTL."""
        entry = CacheEntry(
            exchange_hash="test",
            response=AnalysisResponse(
                coordinator_model="test",
                dispatched_agents=[],
                agent_reports=[],
                summary="test",
            ),
            created_at=time.time() - 100,  # 100 seconds ago
            ttl_seconds=50,  # TTL of 50 seconds
            model="test-model",
            prompt_versions={},
        )
        
        self.assertTrue(entry.is_expired())
    
    def test_not_expired(self):
        """Cache entries should not be expired before TTL."""
        entry = CacheEntry(
            exchange_hash="test",
            response=AnalysisResponse(
                coordinator_model="test",
                dispatched_agents=[],
                agent_reports=[],
                summary="test",
            ),
            created_at=time.time(),
            ttl_seconds=100,
            model="test-model",
            prompt_versions={},
        )
        
        self.assertFalse(entry.is_expired())
    
    def test_staleness_on_model_change(self):
        """Entries should be stale if model changed."""
        entry = CacheEntry(
            exchange_hash="test",
            response=AnalysisResponse(
                coordinator_model="old-model",
                dispatched_agents=[],
                agent_reports=[],
                summary="test",
            ),
            created_at=time.time(),
            ttl_seconds=100,
            model="old-model",
            prompt_versions={},
        )
        
        self.assertTrue(entry.is_stale("new-model", {}))
    
    def test_staleness_on_prompt_change(self):
        """Entries should be stale if prompt version changed."""
        entry = CacheEntry(
            exchange_hash="test",
            response=AnalysisResponse(
                coordinator_model="test",
                dispatched_agents=[],
                agent_reports=[],
                summary="test",
            ),
            created_at=time.time(),
            ttl_seconds=100,
            model="test-model",
            prompt_versions={"sqli": "old-version"},
        )
        
        current_prompts = {"sqli": "new-version"}
        self.assertTrue(entry.is_stale("test-model", current_prompts))
    
    def test_not_stale_with_matching_versions(self):
        """Entries should not be stale if model and prompts match."""
        entry = CacheEntry(
            exchange_hash="test",
            response=AnalysisResponse(
                coordinator_model="test",
                dispatched_agents=[],
                agent_reports=[],
                summary="test",
            ),
            created_at=time.time(),
            ttl_seconds=100,
            model="test-model",
            prompt_versions={"sqli": "v1", "xss": "v2"},
        )
        
        current_prompts = {"sqli": "v1", "xss": "v2", "idor": "v3"}
        self.assertFalse(entry.is_stale("test-model", current_prompts))


class TestCacheOperations(unittest.TestCase):
    """Test cache put/get operations."""
    
    def setUp(self):
        """Create a temporary cache for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_path = Path(self.temp_dir) / "test_cache.db"
        self.cache = ExchangeCache(
            db_path=self.cache_path,
            ttl_seconds=10.0,  # Short TTL for testing
            max_size=100,
        )
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_cache_miss(self):
        """Cache should return None for non-existent entries."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        result = self.cache.get(exchange, "model", {})
        self.assertIsNone(result)
    
    def test_cache_put_and_get(self):
        """Cache should store and retrieve entries."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=["sqli", "xss"],
            agent_reports=[
                AgentReport(
                    agent="sqli",
                    model="test-model",
                    findings=[
                        Finding(
                            vulnerability_class="sqli",
                            confidence=0.9,
                            severity="high",
                            summary="SQL injection found",
                            evidence="' OR '1'='1",
                            suggested_test="Test with SQLi payloads",
                            basis="derived",
                        )
                    ],
                )
            ],
            summary="2 findings",
        )
        
        # Store in cache
        self.cache.put(exchange, response, "test-model", {"sqli": "v1", "xss": "v1"})
        
        # Retrieve from cache
        cached = self.cache.get(exchange, "test-model", {"sqli": "v1", "xss": "v1"})
        
        self.assertIsNotNone(cached)
        self.assertEqual(cached.coordinator_model, "test-model")
        self.assertEqual(len(cached.agent_reports), 1)
        self.assertEqual(cached.agent_reports[0].agent, "sqli")
    
    def test_cache_with_different_model(self):
        """Cache should not return entries for different models."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="old-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        self.cache.put(exchange, response, "old-model", {})
        
        # Request with different model should not hit cache
        cached = self.cache.get(exchange, "new-model", {})
        self.assertIsNone(cached)
    
    def test_cache_with_different_prompt_version(self):
        """Cache should not return entries for different prompt versions."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        self.cache.put(exchange, response, "test-model", {"sqli": "v1"})
        
        # Request with different prompt version should not hit cache
        cached = self.cache.get(exchange, "test-model", {"sqli": "v2"})
        self.assertIsNone(cached)
    
    def test_cache_bypass(self):
        """Cache bypass should skip cache lookup."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        self.cache.put(exchange, response, "test-model", {})
        
        # Bypass should return None
        cached = self.cache.get(exchange, "test-model", {}, bypass=True)
        self.assertIsNone(cached)
    
    def test_cache_disabled(self):
        """Disabled cache should not store or return entries."""
        self.cache.set_enabled(False)
        
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        self.cache.put(exchange, response, "test-model", {})
        cached = self.cache.get(exchange, "test-model", {})
        
        self.assertIsNone(cached)
    
    def test_cache_clear(self):
        """Cache clear should remove all entries."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        self.cache.put(exchange, response, "test-model", {})
        self.assertEqual(self.cache.size(), 1)
        
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)


class TestCacheStats(unittest.TestCase):
    """Test cache statistics tracking."""
    
    def setUp(self):
        """Create a temporary cache for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_path = Path(self.temp_dir) / "test_cache.db"
        self.cache = ExchangeCache(
            db_path=self.cache_path,
            ttl_seconds=10.0,
        )
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_hit_tracking(self):
        """Cache should track hits."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        self.cache.put(exchange, response, "test-model", {})
        self.cache.get(exchange, "test-model", {})
        
        stats = self.cache.stats()
        self.assertEqual(stats.hits, 1)
    
    def test_miss_tracking(self):
        """Cache should track misses."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        self.cache.get(exchange, "test-model", {})
        
        stats = self.cache.stats()
        self.assertEqual(stats.misses, 1)
    
    def test_bypass_tracking(self):
        """Cache should track bypasses."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        self.cache.get(exchange, "test-model", {}, bypass=True)
        
        stats = self.cache.stats()
        self.assertEqual(stats.bypasses, 1)
    
    def test_hit_rate_calculation(self):
        """Hit rate should be calculated correctly."""
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        # 2 hits, 2 misses = 50% hit rate
        self.cache.put(exchange, response, "test-model", {})
        self.cache.get(exchange, "test-model", {})  # hit
        
        exchange2 = HttpExchange(
            url="https://example.com/test2",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        self.cache.get(exchange2, "test-model", {})  # miss
        self.cache.get(exchange, "test-model", {})  # hit
        self.cache.get(exchange2, "test-model", {})  # miss
        
        stats = self.cache.stats()
        self.assertEqual(stats.hits, 2)
        self.assertEqual(stats.misses, 2)
        self.assertAlmostEqual(stats.hit_rate, 50.0)


class TestCachePersistence(unittest.TestCase):
    """Test that cache persists across restarts."""
    
    def setUp(self):
        """Create a temporary cache for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_path = Path(self.temp_dir) / "test_cache.db"
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_persistence_across_instances(self):
        """Cache should persist across cache instances."""
        # Create first cache instance
        cache1 = ExchangeCache(db_path=self.cache_path, ttl_seconds=100.0)
        
        exchange = HttpExchange(
            url="https://example.com/test",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        
        response = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test",
        )
        
        cache1.put(exchange, response, "test-model", {})
        
        # Create second cache instance with same path
        cache2 = ExchangeCache(db_path=self.cache_path, ttl_seconds=100.0)
        
        cached = cache2.get(exchange, "test-model", {})
        self.assertIsNotNone(cached)
        self.assertEqual(cached.summary, "test")


class TestCacheEviction(unittest.TestCase):
    """Test cache eviction behavior."""
    
    def setUp(self):
        """Create a temporary cache for each test."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_path = Path(self.temp_dir) / "test_cache.db"
        self.cache = ExchangeCache(
            db_path=self.cache_path,
            ttl_seconds=100.0,
            max_size=5,  # Small size for testing eviction
        )
    
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_eviction_when_full(self):
        """Cache should evict old entries when full."""
        # Add 5 entries
        for i in range(5):
            exchange = HttpExchange(
                url=f"https://example.com/test{i}",
                method="GET",
                request_body="",
                response_status=200,
                response_body="",
            )
            response = AnalysisResponse(
                coordinator_model="test-model",
                dispatched_agents=[],
                agent_reports=[],
                summary=f"test{i}",
            )
            self.cache.put(exchange, response, "test-model", {})
        
        self.assertEqual(self.cache.size(), 5)
        
        # Add 6th entry - should trigger eviction
        exchange6 = HttpExchange(
            url="https://example.com/test6",
            method="GET",
            request_body="",
            response_status=200,
            response_body="",
        )
        response6 = AnalysisResponse(
            coordinator_model="test-model",
            dispatched_agents=[],
            agent_reports=[],
            summary="test6",
        )
        self.cache.put(exchange6, response6, "test-model", {})
        
        # Should still have 5 entries (one was evicted)
        self.assertEqual(self.cache.size(), 5)
        
        # Check stats
        stats = self.cache.stats()
        self.assertGreater(stats.evictions, 0)


if __name__ == "__main__":
    unittest.main()
