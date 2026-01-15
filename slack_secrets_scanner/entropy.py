"""Entropy calculation for detecting high-entropy strings."""

import math
from typing import Dict


def calculate_entropy(data: str) -> float:
    """Calculate entropy of a string."""
    if not data:
        return 0.0
    
    char_freq: Dict[str, int] = {}
    for char in data:
        char_freq[char] = char_freq.get(char, 0) + 1
    
    entropy = 0.0
    data_len = len(data)
    
    for count in char_freq.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def calculate_base64_entropy(data: str) -> float:
    """Calculate entropy for base64 strings."""
    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    filtered_data = "".join(c for c in data if c in base64_chars)
    
    if not filtered_data or len(filtered_data) < len(data) * 0.8:
        return calculate_entropy(data)
    
    return calculate_entropy(filtered_data)


def calculate_hex_entropy(data: str) -> float:
    """Calculate entropy for hex strings."""
    hex_chars = set("0123456789abcdefABCDEF")
    filtered_data = "".join(c for c in data if c in hex_chars)
    
    if not filtered_data or len(filtered_data) < len(data) * 0.8:
        return calculate_entropy(data)
    
    return calculate_entropy(filtered_data)


def is_high_entropy(data: str, min_entropy: float = 4.5, min_length: int = 20) -> bool:
    """Check if string has high entropy."""
    if len(data) < min_length:
        return False
    
    cleaned = data.strip()
    
    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    is_base64 = any(c in cleaned for c in "+/=") or all(c in base64_chars for c in cleaned)
    
    hex_chars = set("0123456789abcdefABCDEF")
    is_hex = all(c in hex_chars for c in cleaned)
    
    if is_base64:
        entropy = calculate_base64_entropy(cleaned)
        threshold = 4.5
    elif is_hex:
        entropy = calculate_hex_entropy(cleaned)
        threshold = 3.0
    else:
        entropy = calculate_entropy(cleaned)
        threshold = min_entropy
    
    return entropy >= threshold


def get_entropy_score(data: str) -> float:
    """Get entropy score for a string."""
    if not data:
        return 0.0
    
    cleaned = data.strip()
    
    if any(c in cleaned for c in "+/="):
        return calculate_base64_entropy(cleaned)
    elif all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return calculate_hex_entropy(cleaned)
    else:
        return calculate_entropy(cleaned)

