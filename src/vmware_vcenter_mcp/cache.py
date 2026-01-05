"""
Intelligent Caching System for VMware vCenter MCP Server
Provides multi-level caching with TTL, LRU eviction, and cache warming.
"""

import time
import threading
import hashlib
import json
from typing import Any, Dict, Optional, Callable, Union
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    value: Any
    created_at: float
    last_accessed: float
    access_count: int
    ttl: Optional[float] = None
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl


class LRUCache:
    """Thread-safe LRU cache with TTL support."""
    
    def __init__(self, max_size: int = 1000, default_ttl: Optional[float] = None):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expired': 0
        }
    
    def _generate_key(self, key: Union[str, tuple, dict]) -> str:
        """Generate cache key from various input types."""
        if isinstance(key, str):
            return key
        elif isinstance(key, (tuple, list)):
            return hashlib.md5(str(key).encode()).hexdigest()
        elif isinstance(key, dict):
            sorted_items = sorted(key.items())
            return hashlib.md5(str(sorted_items).encode()).hexdigest()
        else:
            return hashlib.md5(str(key).encode()).hexdigest()
    
    def get(self, key: Union[str, tuple, dict]) -> Optional[Any]:
        """Get value from cache."""
        cache_key = self._generate_key(key)
        
        with self.lock:
            if cache_key not in self.cache:
                self.stats['misses'] += 1
                return None
            
            entry = self.cache[cache_key]
            
            # Check if expired
            if entry.is_expired():
                del self.cache[cache_key]
                self.stats['expired'] += 1
                self.stats['misses'] += 1
                return None
            
            # Update access info and move to end (most recently used)
            entry.last_accessed = time.time()
            entry.access_count += 1
            self.cache.move_to_end(cache_key)
            
            self.stats['hits'] += 1
            return entry.value
    
    def put(self, key: Union[str, tuple, dict], value: Any, ttl: Optional[float] = None) -> None:
        """Put value in cache."""
        cache_key = self._generate_key(key)
        ttl = ttl or self.default_ttl
        
        with self.lock:
            now = time.time()
            entry = CacheEntry(
                value=value,
                created_at=now,
                last_accessed=now,
                access_count=0,
                ttl=ttl
            )
            
            if cache_key in self.cache:
                # Update existing entry
                self.cache[cache_key] = entry
                self.cache.move_to_end(cache_key)
            else:
                # Add new entry
                self.cache[cache_key] = entry
                
                # Evict oldest if over capacity
                if len(self.cache) > self.max_size:
                    self.cache.popitem(last=False)
                    self.stats['evictions'] += 1
    
    def delete(self, key: Union[str, tuple, dict]) -> bool:
        """Delete entry from cache."""
        cache_key = self._generate_key(key)
        
        with self.lock:
            if cache_key in self.cache:
                del self.cache[cache_key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.stats = {
                'hits': 0,
                'misses': 0,
                'evictions': 0,
                'expired': 0
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0
            
            return {
                **self.stats,
                'size': len(self.cache),
                'max_size': self.max_size,
                'hit_rate': round(hit_rate, 2),
                'total_requests': total_requests
            }


class CacheManager:
    """Multi-level cache manager with different cache policies."""
    
    def __init__(self):
        self.caches: Dict[str, LRUCache] = {}
        self.cache_warmers: Dict[str, Callable] = {}
        self.lock = threading.Lock()
    
    def create_cache(self, name: str, max_size: int = 1000, 
                    default_ttl: Optional[float] = None) -> LRUCache:
        """Create a named cache."""
        with self.lock:
            cache = LRUCache(max_size=max_size, default_ttl=default_ttl)
            self.caches[name] = cache
            return cache
    
    def get_cache(self, name: str) -> Optional[LRUCache]:
        """Get cache by name."""
        return self.caches.get(name)
    
    def register_cache_warmer(self, cache_name: str, warmer_func: Callable) -> None:
        """Register cache warming function."""
        self.cache_warmers[cache_name] = warmer_func
    
    def warm_cache(self, cache_name: str) -> None:
        """Warm cache using registered warmer function."""
        if cache_name in self.cache_warmers:
            warmer = self.cache_warmers[cache_name]
            try:
                warmer()
            except Exception as e:
                print(f"Cache warming failed for {cache_name}: {e}")
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all caches."""
        return {name: cache.get_stats() for name, cache in self.caches.items()}


def cached(cache_name: str, ttl: Optional[float] = None, 
          key_func: Optional[Callable] = None):
    """Decorator for caching function results."""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Get or create cache
            cache = cache_manager.get_cache(cache_name)
            if cache is None:
                cache = cache_manager.create_cache(cache_name, default_ttl=ttl)
            
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = (func.__name__, args, tuple(sorted(kwargs.items())))
            
            # Try to get from cache
            result = cache.get(cache_key)
            if result is not None:
                return result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache.put(cache_key, result, ttl=ttl)
            return result
        
        return wrapper
    return decorator


# Global cache manager instance
cache_manager = CacheManager()

# Create default caches
VM_CACHE = cache_manager.create_cache('vm_cache', max_size=5000, default_ttl=300)  # 5 minutes
HOST_CACHE = cache_manager.create_cache('host_cache', max_size=1000, default_ttl=600)  # 10 minutes
DATACENTER_CACHE = cache_manager.create_cache('datacenter_cache', max_size=100, default_ttl=1800)  # 30 minutes
PERFORMANCE_CACHE = cache_manager.create_cache('performance_cache', max_size=10000, default_ttl=60)  # 1 minute
CONFIG_CACHE = cache_manager.create_cache('config_cache', max_size=500, default_ttl=3600)  # 1 hour