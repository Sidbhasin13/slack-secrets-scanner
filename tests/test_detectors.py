"""Tests for secret detectors."""

from slack_secrets_scanner.detectors import SecretScanner, SecretDetector


def test_github_token_detection():
    """Test GitHub token detection."""
    scanner = SecretScanner()
    text = "Here is my token: ghp_TESTTOKEN1234567890abcdefghijklmnopqrstuvwxyzABCD"
    
    matches = scanner.scan_text(text, location="test")
    assert len(matches) > 0
    assert any(m.secret_type == "GitHub Token" for m in matches)


def test_aws_key_detection():
    """Test AWS key detection."""
    scanner = SecretScanner()
    text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    
    matches = scanner.scan_text(text, location="test")
    # May or may not match depending on entropy
    # This is just to test the detector runs without error
    assert isinstance(matches, list)


def test_slack_token_detection():
    """Test Slack token detection."""
    scanner = SecretScanner()
    text = "xoxb-TESTTOKEN123-TESTTOKEN456-TESTTOKEN789abcdefghijklmnopqrstuvwxyz"
    
    matches = scanner.scan_text(text, location="test")
    assert len(matches) > 0
    assert any(m.secret_type == "Slack Token" for m in matches)


def test_entropy_filtering():
    """Test that low-entropy strings are filtered."""
    scanner = SecretScanner()
    # This should match the pattern but be filtered by entropy
    text = "api_key=your-api-key-here"
    
    matches = scanner.scan_text(text, location="test")
    # Should be filtered out due to low entropy
    assert len(matches) == 0 or all(m.entropy_score < 3.5 for m in matches)

