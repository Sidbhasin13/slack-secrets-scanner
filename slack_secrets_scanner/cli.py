"""Command-line interface for Slack Secrets Scanner."""

import json
import os
import sys
from pathlib import Path
from typing import Optional
import click
from colorama import init, Fore, Style

from .scanner import SlackSecretsScanner
from . import __version__

init(autoreset=True)

if sys.platform == "win32":
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        except (AttributeError, ValueError):
            pass


def load_config() -> dict:
    """Load configuration from watchman.conf file."""
    config = {}
    home = Path.home()
    config_file = home / "watchman.conf"
    
    if config_file.exists():
        try:
            try:
                import yaml
            except ImportError:
                return config
            
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
                if config_data and "slack_secrets_scanner" in config_data:
                    config = config_data["slack_secrets_scanner"]
        except Exception as e:
            print(f"Warning: Could not load config file: {e}", file=sys.stderr)
    
    return config


def get_token() -> Optional[str]:
    """Get Slack token from environment or config."""
    token = os.getenv("SLACK_WATCHMAN_TOKEN") or os.getenv("SLACK_SECRETS_SCANNER_TOKEN")
    if not token:
        config = load_config()
        token = config.get("token")
    return token


def print_match_stdout(match, verbose: bool = False):
    """Print a secret match in human-readable format."""
    status_colors = {
        "verified": Fore.RED + Style.BRIGHT,
        "unverified": Fore.YELLOW,
        "false_positive": Fore.GREEN
    }
    
    status_color = status_colors.get(match.verification_status, Fore.WHITE)
    status_symbol = {
        "verified": "VERIFIED",
        "unverified": "UNVERIFIED",
        "false_positive": "FALSE POSITIVE"
    }.get(match.verification_status, "UNVERIFIED")
    
    print(f"\n{status_color}{status_symbol}{Style.RESET_ALL}")
    print(f"Type: {match.secret_type}")
    print(f"Location: {match.location}")
    if match.line_number:
        print(f"Line: {match.line_number}")
    print(f"Entropy Score: {match.entropy_score:.2f}")
    print(f"Value: {match.value[:50]}{'...' if len(match.value) > 50 else ''}")
    
    if verbose or match.verification_details:
        print(f"Context: {match.context[:200]}{'...' if len(match.context) > 200 else ''}")
        if match.verification_details:
            print(f"Verification: {match.verification_details}")


def print_match_json(match, verbose: bool = False):
    """Convert a secret match to JSON format."""
    match_dict = {
        "secret_type": match.secret_type,
        "value": match.value,
        "location": match.location,
        "entropy_score": match.entropy_score,
        "verified": match.verified,
        "verification_status": match.verification_status,
    }
    
    if match.line_number:
        match_dict["line_number"] = match.line_number
    
    if verbose:
        match_dict["context"] = match.context
    
    if match.verification_details:
        match_dict["verification_details"] = match.verification_details
    
    return match_dict


@click.command()
@click.option(
    "--timeframe", "-t",
    type=click.Choice(["d", "w", "m", "a"], case_sensitive=False),
    default="a",
    help="How far back to search: d=24 hours, w=7 days, m=30 days, a=all time (same as slack-watchman)"
)
@click.option(
    "--output", "-o",
    type=click.Choice(["json", "stdout"], case_sensitive=False),
    default="stdout",
    help="Output format: json or stdout"
)
@click.option(
    "--channels", "-c",
    help="Comma-separated list of channel IDs to scan (default: all channels)"
)
@click.option(
    "--no-verify",
    is_flag=True,
    help="Skip API verification of detected secrets"
)
@click.option(
    "--no-ssl-verify",
    is_flag=True,
    help="Skip SSL certificate verification (not recommended)"
)
@click.option(
    "--verbose", "-V",
    is_flag=True,
    help="Include more details in output"
)
@click.option(
    "--version", "-v",
    is_flag=True,
    help="Show version and exit"
)
def main(timeframe, output, channels, no_verify, no_ssl_verify, verbose, version):
    """Slack Secrets Scanner - Scan Slack workspaces for exposed secrets with entropy-based verification."""
    
    if version:
        print(f"slack-secrets-scanner v{__version__}")
        sys.exit(0)
    
    token = get_token()
    if not token:
        print("Error: Slack token not found.")
        print("Set SLACK_WATCHMAN_TOKEN or SLACK_SECRETS_SCANNER_TOKEN environment variable,")
        print("or add 'token' to ~/watchman.conf file.")
        sys.exit(1)
    
    config = load_config()
    disabled_detectors = config.get("disabled_detectors", [])
    if disabled_detectors:
        print(f"Disabled detectors: {', '.join(disabled_detectors)}")
    
    channel_list = None
    if channels:
        channel_list = [c.strip() for c in channels.split(",")]
    
    scanner = SlackSecretsScanner(
        slack_token=token,
        verify_secrets=not no_verify,
        verify_ssl=not no_ssl_verify,
        disabled_detectors=disabled_detectors
    )
    
    try:
        matches = scanner.scan_timeframe(
            timeframe=timeframe,
            channels=channel_list,
            include_dms=False,
            include_files=True
        )
        
        if output == "json":
            results = {
                "scan_info": {
                    "timeframe": timeframe,
                    "total_matches": len(matches),
                    "verified": sum(1 for m in matches if m.verification_status == "verified"),
                    "unverified": sum(1 for m in matches if m.verification_status == "unverified"),
                    "false_positives": sum(1 for m in matches if m.verification_status == "false_positive")
                },
                "matches": [print_match_json(m, verbose) for m in matches]
            }
            print(json.dumps(results, indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"Scan Results: {len(matches)} potential secrets found")
            print(f"{'='*60}")
            
            verified = [m for m in matches if m.verification_status == "verified"]
            unverified = [m for m in matches if m.verification_status == "unverified"]
            false_positives = [m for m in matches if m.verification_status == "false_positive"]
            
            print(f"\nSummary:")
            print(f"  {Fore.RED}VERIFIED: {len(verified)}{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}UNVERIFIED: {len(unverified)}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}FALSE POSITIVES: {len(false_positives)}{Style.RESET_ALL}")
            
            if matches:
                print(f"\n{'='*60}")
                print("Details:")
                print(f"{'='*60}")
                
                for match in verified:
                    print_match_stdout(match, verbose)
                
                for match in unverified:
                    print_match_stdout(match, verbose)
                
                for match in false_positives:
                    print_match_stdout(match, verbose)
            else:
                print("\nNo secrets detected.")
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

