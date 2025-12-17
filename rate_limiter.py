#!/usr/bin/env python3
"""
Rate Limiter for HTTP Requests
==============================
Token bucket implementation for request throttling.
For educational and authorized testing purposes only.
"""

import time
import threading
from typing import Optional
from dataclasses import dataclass


@dataclass
class RateLimiterConfig:
    """Configuration for rate limiting."""
    requests_per_second: float = 3.0
    burst_size: int = 5
    delay_between_requests: float = 0.0  # Additional fixed delay


class TokenBucketRateLimiter:
    """
    Thread-safe token bucket rate limiter.
    
    The token bucket algorithm allows for burst traffic while
    maintaining an average rate limit over time.
    """
    
    def __init__(
        self,
        rate: float = 3.0,  # Tokens per second
        capacity: int = 5,   # Maximum burst size
    ):
        """
        Initialize the rate limiter.
        
        Args:
            rate: Number of tokens (requests) allowed per second
            capacity: Maximum number of tokens that can accumulate
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity  # Start with full bucket
        self.last_update = time.monotonic()
        self._lock = threading.Lock()
    
    def _add_tokens(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        new_tokens = elapsed * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_update = now
    
    def acquire(self, timeout: Optional[float] = None) -> bool:
        """
        Acquire a token, blocking if necessary.
        
        Args:
            timeout: Maximum time to wait for a token (None = wait forever)
            
        Returns:
            True if token acquired, False if timeout
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        
        while True:
            with self._lock:
                self._add_tokens()
                
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
                
                # Calculate wait time for next token
                wait_time = (1.0 - self.tokens) / self.rate
            
            # Check timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                wait_time = min(wait_time, remaining)
            
            time.sleep(wait_time)
    
    def try_acquire(self) -> bool:
        """
        Try to acquire a token without blocking.
        
        Returns:
            True if token acquired, False if no tokens available
        """
        with self._lock:
            self._add_tokens()
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            
            return False
    
    @property
    def available_tokens(self) -> float:
        """Get current number of available tokens."""
        with self._lock:
            self._add_tokens()
            return self.tokens


class SimpleRateLimiter:
    """
    Simple fixed-delay rate limiter.
    Ensures minimum delay between requests.
    """
    
    def __init__(self, delay: float = 0.3):
        """
        Initialize with fixed delay.
        
        Args:
            delay: Minimum seconds between requests
        """
        self.delay = delay
        self.last_request = 0.0
        self._lock = threading.Lock()
    
    def wait(self) -> float:
        """
        Wait if necessary and return actual wait time.
        
        Returns:
            Seconds waited
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_request
            
            if elapsed < self.delay:
                wait_time = self.delay - elapsed
                time.sleep(wait_time)
                self.last_request = time.monotonic()
                return wait_time
            
            self.last_request = now
            return 0.0


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts based on server responses.
    Slows down on errors, speeds up on successful requests.
    """
    
    def __init__(
        self,
        initial_rate: float = 5.0,
        min_rate: float = 0.5,
        max_rate: float = 10.0,
        decrease_factor: float = 0.5,
        increase_factor: float = 1.1,
    ):
        """
        Initialize adaptive rate limiter.
        
        Args:
            initial_rate: Starting requests per second
            min_rate: Minimum rate floor
            max_rate: Maximum rate ceiling
            decrease_factor: Multiplier when slowing down
            increase_factor: Multiplier when speeding up
        """
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.decrease_factor = decrease_factor
        self.increase_factor = increase_factor
        self._limiter = TokenBucketRateLimiter(rate=initial_rate)
        self._lock = threading.Lock()
        self.consecutive_errors = 0
        self.consecutive_successes = 0
    
    def acquire(self) -> bool:
        """Acquire a token."""
        return self._limiter.acquire()
    
    def report_success(self) -> None:
        """Report a successful request."""
        with self._lock:
            self.consecutive_successes += 1
            self.consecutive_errors = 0
            
            # Speed up after 5 consecutive successes
            if self.consecutive_successes >= 5:
                self.current_rate = min(
                    self.max_rate,
                    self.current_rate * self.increase_factor
                )
                self._limiter.rate = self.current_rate
                self.consecutive_successes = 0
    
    def report_error(self) -> None:
        """Report a failed request or server error."""
        with self._lock:
            self.consecutive_errors += 1
            self.consecutive_successes = 0
            
            # Slow down immediately on error
            self.current_rate = max(
                self.min_rate,
                self.current_rate * self.decrease_factor
            )
            self._limiter.rate = self.current_rate
    
    @property
    def rate(self) -> float:
        """Get current rate."""
        return self.current_rate


def create_rate_limiter(
    requests_per_second: float = 3.0,
    burst_size: int = 5,
    adaptive: bool = False,
) -> TokenBucketRateLimiter:
    """
    Factory function to create appropriate rate limiter.
    
    Args:
        requests_per_second: Target rate
        burst_size: Maximum burst
        adaptive: Whether to use adaptive limiting
        
    Returns:
        Configured rate limiter
    """
    if adaptive:
        return AdaptiveRateLimiter(initial_rate=requests_per_second)
    return TokenBucketRateLimiter(rate=requests_per_second, capacity=burst_size)


if __name__ == "__main__":
    # Demo: Rate limiter behavior
    print("=" * 60)
    print("Rate Limiter Demo")
    print("=" * 60)
    
    limiter = TokenBucketRateLimiter(rate=3.0, capacity=3)
    
    print(f"\nConfiguration: 3 requests/second, burst capacity 3")
    print(f"Starting tokens: {limiter.available_tokens:.1f}")
    
    print("\nMaking 10 requests...")
    for i in range(10):
        start = time.monotonic()
        limiter.acquire()
        elapsed = time.monotonic() - start
        print(f"  Request {i+1}: waited {elapsed:.3f}s, tokens left: {limiter.available_tokens:.1f}")
    
    print("\nDemo complete!")
