"""
API Rate Limiting Module for VMware vCenter MCP Server
Implements token bucket and sliding window rate limiting algorithms.
"""

import time
import threading
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, deque


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""
    requests_per_minute: int = 60
    burst_capacity: int = 10
    window_size_seconds: int = 60


class TokenBucket:
    """Token bucket rate limiter implementation."""
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from the bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False otherwise
        """
        with self.lock:
            now = time.time()
            # Add tokens based on elapsed time
            elapsed = now - self.last_refill
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate
            )
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation."""
    
    def __init__(self, window_size: int, max_requests: int):
        self.window_size = window_size
        self.max_requests = max_requests
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()
    
    def is_allowed(self, identifier: str) -> Tuple[bool, Dict[str, int]]:
        """
        Check if request is allowed for given identifier.
        
        Args:
            identifier: Unique identifier (e.g., user ID, IP address)
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        with self.lock:
            now = time.time()
            window_start = now - self.window_size
            
            # Remove old requests outside the window
            user_requests = self.requests[identifier]
            while user_requests and user_requests[0] < window_start:
                user_requests.popleft()
            
            # Check if under limit
            current_count = len(user_requests)
            is_allowed = current_count < self.max_requests
            
            if is_allowed:
                user_requests.append(now)
            
            # Calculate reset time
            reset_time = int(window_start + self.window_size) if user_requests else int(now)
            
            rate_limit_info = {
                'limit': self.max_requests,
                'remaining': max(0, self.max_requests - current_count - (1 if is_allowed else 0)),
                'reset': reset_time,
                'retry_after': max(0, int(user_requests[0] + self.window_size - now)) if not is_allowed and user_requests else 0
            }
            
            return is_allowed, rate_limit_info


class RateLimitManager:
    """Centralized rate limit management."""
    
    def __init__(self):
        self.limiters: Dict[str, SlidingWindowRateLimiter] = {}
        self.token_buckets: Dict[str, TokenBucket] = {}
        self.configs: Dict[str, RateLimitConfig] = {}
        self.lock = threading.Lock()
    
    def add_rate_limit(self, endpoint: str, config: RateLimitConfig) -> None:
        """Add rate limiting for an endpoint."""
        with self.lock:
            self.configs[endpoint] = config
            self.limiters[endpoint] = SlidingWindowRateLimiter(
                window_size=config.window_size_seconds,
                max_requests=config.requests_per_minute
            )
            self.token_buckets[endpoint] = TokenBucket(
                capacity=config.burst_capacity,
                refill_rate=config.requests_per_minute / 60.0  # per second
            )
    
    def check_rate_limit(self, endpoint: str, identifier: str) -> Tuple[bool, Dict[str, int]]:
        """
        Check rate limit for endpoint and identifier.
        
        Args:
            endpoint: API endpoint name
            identifier: User/client identifier
            
        Returns:
            Tuple of (is_allowed, rate_limit_headers)
        """
        if endpoint not in self.limiters:
            # No rate limit configured, allow request
            return True, {}
        
        # Check sliding window limit
        sliding_allowed, sliding_info = self.limiters[endpoint].is_allowed(identifier)
        
        # Check token bucket for burst protection
        bucket_allowed = self.token_buckets[endpoint].consume()
        
        is_allowed = sliding_allowed and bucket_allowed
        
        headers = {
            'X-RateLimit-Limit': sliding_info['limit'],
            'X-RateLimit-Remaining': sliding_info['remaining'] if is_allowed else 0,
            'X-RateLimit-Reset': sliding_info['reset']
        }
        
        if not is_allowed and sliding_info.get('retry_after', 0) > 0:
            headers['Retry-After'] = sliding_info['retry_after']
        
        return is_allowed, headers
    
    def get_rate_limit_status(self, endpoint: str, identifier: str) -> Dict[str, int]:
        """Get current rate limit status without consuming quota."""
        if endpoint not in self.limiters:
            return {}
        
        with self.limiters[endpoint].lock:
            now = time.time()
            window_start = now - self.limiters[endpoint].window_size
            
            user_requests = self.limiters[endpoint].requests[identifier]
            # Clean old requests
            while user_requests and user_requests[0] < window_start:
                user_requests.popleft()
            
            current_count = len(user_requests)
            config = self.configs[endpoint]
            
            return {
                'limit': config.requests_per_minute,
                'remaining': max(0, config.requests_per_minute - current_count),
                'reset': int(window_start + config.window_size_seconds),
                'window_size': config.window_size_seconds
            }


# Global rate limit manager instance
rate_limit_manager = RateLimitManager()

# Default rate limit configurations
DEFAULT_CONFIGS = {
    'vm_operations': RateLimitConfig(requests_per_minute=30, burst_capacity=5),
    'host_operations': RateLimitConfig(requests_per_minute=20, burst_capacity=3),
    'datacenter_operations': RateLimitConfig(requests_per_minute=10, burst_capacity=2),
    'performance_metrics': RateLimitConfig(requests_per_minute=100, burst_capacity=20),
    'configuration_changes': RateLimitConfig(requests_per_minute=5, burst_capacity=1)
}

# Initialize default rate limits
for endpoint, config in DEFAULT_CONFIGS.items():
    rate_limit_manager.add_rate_limit(endpoint, config)