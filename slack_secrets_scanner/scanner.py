"""Main scanner that combines Slack API, detection, and verification."""

import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from .slack_client import SlackScanner
from .detectors import SecretScanner, SecretMatch
from .verifier import SecretVerifier


class SlackSecretsScanner:
    """Main scanner class that orchestrates scanning and verification."""
    
    def __init__(
        self,
        slack_token: str,
        verify_secrets: bool = True,
        verify_ssl: bool = True,
        custom_patterns: Optional[Dict] = None,
        disabled_detectors: Optional[List[str]] = None
    ):
        """
        Initialize the scanner.
        
        Args:
            slack_token: Slack OAuth token
            verify_secrets: Whether to verify secrets via API calls
            verify_ssl: Whether to verify SSL certificates
            custom_patterns: Custom secret detection patterns
            disabled_detectors: List of detector IDs to disable
        """
        from typing import Set
        disabled_set = set(disabled_detectors) if disabled_detectors else None
        self.slack = SlackScanner(slack_token)
        self.detector = SecretScanner(custom_patterns, disabled_detectors=disabled_set)
        self.verifier = SecretVerifier(verify_ssl=verify_ssl) if verify_secrets else None
        self.verify_secrets = verify_secrets
    
    def scan_timeframe(
        self,
        timeframe: str = "a",
        channels: Optional[List[str]] = None,
        include_dms: bool = False,
        include_files: bool = True
    ) -> List[SecretMatch]:
        """Scan Slack workspace for secrets."""
        now = datetime.now()
        if timeframe.lower() == "d":
            oldest = (now - timedelta(days=1)).timestamp()
        elif timeframe.lower() == "w":
            oldest = (now - timedelta(weeks=1)).timestamp()
        elif timeframe.lower() == "m":
            oldest = (now - timedelta(days=30)).timestamp()
        elif timeframe.lower() == "a":
            oldest = None
        else:
            print(f"Warning: Invalid timeframe '{timeframe}', defaulting to 'a' (all time)")
            oldest = None
        
        all_matches = []
        
        if not self.slack.test_connection():
            print("Error: Failed to connect to Slack. Please check your token.")
            return all_matches
        
        print("Starting scan...")
        
        if channels:
            channel_list = [{"id": cid} for cid in channels]
        else:
            channel_list = self.slack.get_channels(include_private=True)
            if include_dms:
                channel_list.extend(self.slack.get_direct_messages())
        
        print(f"Scanning {len(channel_list)} channels/conversations...")
        
        for idx, channel in enumerate(channel_list, 1):
            channel_id = channel["id"]
            channel_name = channel.get("name", f"channel_{channel_id}")
            
            print(f"[{idx}/{len(channel_list)}] Scanning {channel_name}...")
            
            messages = self.slack.get_channel_messages(
                channel_id=channel_id,
                oldest=oldest
            )
            
            for message in messages:
                text = message.get("text", "")
                if text:
                    matches = self.detector.scan_text(text, location=f"#{channel_name}")
                    all_matches.extend(matches)
                
                if include_files and "files" in message:
                    for file_info in message["files"]:
                        file_name = file_info.get("name", "unknown")
                        file_id = file_info.get("id")
                        
                        if file_id:
                            file_content = self.slack.get_file_content(file_id)
                            if file_content:
                                matches = self.detector.scan_text(
                                    file_content,
                                    location=f"#{channel_name}/file:{file_name}"
                                )
                                all_matches.extend(matches)
        
        print(f"Found {len(all_matches)} potential secrets. Verifying...")
        
        if self.verify_secrets and self.verifier:
            verified_matches = []
            for idx, match in enumerate(all_matches, 1):
                print(f"Verifying [{idx}/{len(all_matches)}] {match.secret_type}...")
                verified_match = self.verifier.verify(match)
                verified_matches.append(verified_match)
                time.sleep(0.2)
            
            all_matches = verified_matches
        
        return all_matches
    
    def scan_text(self, text: str, location: str = "") -> List[SecretMatch]:
        """Scan a text string for secrets."""
        matches = self.detector.scan_text(text, location)
        
        if self.verify_secrets and self.verifier:
            verified_matches = []
            for match in matches:
                verified_match = self.verifier.verify(match)
                verified_matches.append(verified_match)
            return verified_matches
        
        return matches

