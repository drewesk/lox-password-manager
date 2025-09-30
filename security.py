#!/usr/bin/env python3
"""
Lox Security Utilities
Clipboard management, password breach checking, and additional security features
"""

import hashlib
import time
import threading
import pyperclip
import requests
from typing import Optional


class SecureClipboard:
    """
    Secure clipboard management with automatic clearing
    """
    
    DEFAULT_TIMEOUT = 45  # seconds
    
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._timer = None
        self._original_content = None
    
    def copy(self, text: str, clear_after: bool = True):
        """Copy text to clipboard and optionally clear after timeout"""
        # Store original clipboard content
        try:
            self._original_content = pyperclip.paste()
        except:
            self._original_content = ""
        
        # Copy new content
        pyperclip.copy(text)
        
        if clear_after:
            # Cancel existing timer if any
            if self._timer:
                self._timer.cancel()
            
            # Set new timer to clear clipboard
            self._timer = threading.Timer(self.timeout, self._clear_clipboard)
            self._timer.daemon = True
            self._timer.start()
    
    def _clear_clipboard(self):
        """Clear the clipboard by restoring original content or empty string"""
        try:
            # Restore original content if it was safe (not password-like)
            if self._original_content and len(self._original_content) < 100:
                pyperclip.copy(self._original_content)
            else:
                pyperclip.copy("")
        except:
            pass
    
    def cancel_clear(self):
        """Cancel scheduled clipboard clearing"""
        if self._timer:
            self._timer.cancel()
            self._timer = None


class PasswordBreachChecker:
    """
    Check if passwords have been compromised using Have I Been Pwned API
    Uses k-anonymity to maintain privacy - only first 5 chars of hash sent
    """
    
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    
    def check_breach(self, password: str) -> Optional[int]:
        """
        Check if password has been breached
        Returns: Number of times password was seen in breaches, or None if error
        """
        # Hash the password with SHA-1 (as required by HIBP API)
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Use k-anonymity: send only first 5 characters
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        try:
            # Query the API
            response = requests.get(
                f"{self.HIBP_API_URL}{hash_prefix}",
                timeout=5,
                headers={'User-Agent': 'lox-password-manager'}
            )
            
            if response.status_code != 200:
                return None
            
            # Parse response to find our hash suffix
            for line in response.text.splitlines():
                parts = line.split(':')
                if len(parts) == 2:
                    suffix, count = parts
                    if suffix == hash_suffix:
                        return int(count)
            
            # Password not found in breaches
            return 0
            
        except Exception:
            # Network error or timeout
            return None
    
    def is_breached(self, password: str, threshold: int = 1) -> bool:
        """
        Check if password is breached above a threshold
        Returns: True if breached more than threshold times
        """
        count = self.check_breach(password)
        if count is None:
            # Couldn't check, assume safe but warn user
            return False
        return count >= threshold


class PasswordStrengthAnalyzer:
    """
    Analyze password strength based on entropy and composition
    """
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate Shannon entropy of password"""
        if not password:
            return 0.0
        
        # Count character frequency
        freq = {}
        for char in password:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        import math
        entropy = 0.0
        length = len(password)
        
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Multiply by length to get total entropy in bits
        return entropy * length
    
    @staticmethod
    def analyze_strength(password: str) -> dict:
        """
        Analyze password strength
        Returns dict with score (0-100) and feedback
        """
        if not password:
            return {'score': 0, 'feedback': ['Password is empty']}
        
        score = 0
        feedback = []
        
        # Length check
        length = len(password)
        if length < 8:
            feedback.append('Password is too short (minimum 8 characters)')
        elif length < 12:
            score += 20
            feedback.append('Consider using a longer password (12+ characters recommended)')
        elif length < 16:
            score += 30
        else:
            score += 40
        
        # Character diversity
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        diversity = sum([has_lower, has_upper, has_digit, has_special])
        
        if diversity < 2:
            feedback.append('Use a mix of character types (lowercase, uppercase, digits, symbols)')
        elif diversity == 2:
            score += 10
        elif diversity == 3:
            score += 20
        else:
            score += 30
        
        # Entropy check
        entropy = PasswordStrengthAnalyzer.calculate_entropy(password)
        if entropy < 30:
            feedback.append('Password has low entropy (too repetitive)')
        elif entropy < 50:
            score += 10
        elif entropy < 70:
            score += 15
        else:
            score += 30
        
        # Common patterns check
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        password_lower = password.lower()
        
        for pattern in common_patterns:
            if pattern in password_lower:
                score = max(0, score - 20)
                feedback.append(f'Avoid common patterns like "{pattern}"')
                break
        
        # Final assessment
        if score < 30:
            strength = 'Weak'
        elif score < 60:
            strength = 'Fair'
        elif score < 80:
            strength = 'Good'
        else:
            strength = 'Strong'
        
        if not feedback:
            feedback.append(f'Password strength is {strength}')
        
        return {
            'score': min(100, score),
            'strength': strength,
            'entropy_bits': round(entropy, 2),
            'feedback': feedback
        }


class RateLimiter:
    """
    Rate limiter to prevent brute force attacks on master password
    """
    
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts = []
    
    def record_attempt(self):
        """Record a failed attempt"""
        current_time = time.time()
        self.attempts.append(current_time)
        
        # Clean old attempts outside window
        self.attempts = [
            t for t in self.attempts
            if current_time - t < self.window_seconds
        ]
    
    def is_limited(self) -> bool:
        """Check if rate limit is exceeded"""
        current_time = time.time()
        
        # Clean old attempts
        self.attempts = [
            t for t in self.attempts
            if current_time - t < self.window_seconds
        ]
        
        return len(self.attempts) >= self.max_attempts
    
    def time_until_reset(self) -> int:
        """Get seconds until rate limit resets"""
        if not self.attempts:
            return 0
        
        current_time = time.time()
        oldest_attempt = min(self.attempts)
        time_until = self.window_seconds - (current_time - oldest_attempt)
        
        return max(0, int(time_until))