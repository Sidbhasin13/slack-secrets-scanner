"""Tests for entropy calculation."""

import pytest
from slack_secrets_scanner.entropy import (
    calculate_entropy,
    is_high_entropy,
    get_entropy_score,
    calculate_base64_entropy,
    calculate_hex_entropy
)


def test_calculate_entropy():
    """Test entropy calculation."""
    # Low entropy (repeating characters)
    assert calculate_entropy("aaaa") < calculate_entropy("abcd")
    
    # High entropy (random string)
    random_string = "aB3dEf9gHiJkLmNoPqRsTuVwXyZ"
    assert calculate_entropy(random_string) > 3.0
    
    # Empty string
    assert calculate_entropy("") == 0.0


def test_is_high_entropy():
    """Test high entropy detection."""
    # Low entropy strings (should return False)
    assert not is_high_entropy("your-api-key-here")
    assert not is_high_entropy("CHANGEME")
    assert not is_high_entropy("password123")
    
    # High entropy strings (should return True)
    assert is_high_entropy("ghp_TESTTOKEN1234567890abcdefghijklmnopqrstuvwxyz")
    assert is_high_entropy("xoxb-TESTTOKEN123-TESTTOKEN456-TESTTOKEN789abcdefghijklmnopqrstuvwxyz")
    
    # Short strings (should return False)
    assert not is_high_entropy("short", min_length=20)


def test_base64_entropy():
    """Test base64 entropy calculation."""
    base64_string = "SGVsbG8gV29ybGQ="
    entropy = calculate_base64_entropy(base64_string)
    assert entropy > 0


def test_hex_entropy():
    """Test hex entropy calculation."""
    hex_string = "deadbeef1234567890abcdef"
    entropy = calculate_hex_entropy(hex_string)
    assert entropy > 0


def test_get_entropy_score():
    """Test entropy score retrieval."""
    score = get_entropy_score("test_string_12345")
    assert score >= 0
    assert score <= 8  # Reasonable upper bound

