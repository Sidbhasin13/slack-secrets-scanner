"""Secret detectors using regex patterns and entropy analysis."""

import re
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass

from .entropy import is_high_entropy, get_entropy_score


@dataclass
class SecretMatch:
    """Represents a detected secret match."""
    secret_type: str
    value: str
    context: str
    location: str
    line_number: Optional[int] = None
    entropy_score: float = 0.0
    verified: bool = False
    verification_status: str = "unverified"
    verification_details: Optional[str] = None


class SecretDetector:
    """Base class for secret detectors."""
    
    def __init__(self, name: str, pattern: str, min_entropy: float = 4.5):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.min_entropy = min_entropy
    
    def detect(self, text: str, location: str = "") -> List[SecretMatch]:
        """Detect secrets in text."""
        matches = []
        for match in self.pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            
            if not is_high_entropy(value, min_entropy=self.min_entropy):
                continue
            
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            context = text[start:end].replace('\n', ' ').strip()
            
            line_number = text[:match.start()].count('\n') + 1
            
            matches.append(SecretMatch(
                secret_type=self.name,
                value=value,
                context=context,
                location=location,
                line_number=line_number,
                entropy_score=get_entropy_score(value)
            ))
        
        return matches


class SecretScanner:
    """Main scanner class that uses all detectors."""
    
    def __init__(
        self, 
        custom_patterns: Optional[Dict[str, SecretDetector]] = None,
        disabled_detectors: Optional[Set[str]] = None
    ):
        from .signatures import COMPREHENSIVE_SIGNATURES
        self.detectors = COMPREHENSIVE_SIGNATURES.copy()
        
        if disabled_detectors:
            for detector_id in disabled_detectors:
                self.detectors.pop(detector_id, None)
        
        if custom_patterns:
            self.detectors.update(custom_patterns)
    
    def scan_text(self, text: str, location: str = "") -> List[SecretMatch]:
        """Scan text for secrets."""
        all_matches = []
        
        for detector in self.detectors.values():
            matches = detector.detect(text, location)
            all_matches.extend(matches)
        
        seen = set()
        unique_matches = []
        for match in all_matches:
            key = (match.value, match.location, match.secret_type)
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)
        
        return unique_matches

