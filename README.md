# Slack Secrets Scanner

Automatically identifies exposed secrets and high-risk data in Slack workspaces with entropy-based filtering and API verification to reduce false positives.

## Installation

### Recommended: pipx
```bash
pipx install slack-secrets-scanner
```

### Alternative: pip
```bash
pip install slack-secrets-scanner
```

### Docker
```bash
docker pull sidbhasin13/slack-secrets-scanner:latest
docker run --rm -e SLACK_WATCHMAN_TOKEN=xoxp... sidbhasin13/slack-secrets-scanner --timeframe a
```

## Authentication

You need a Slack OAuth token with these scopes:
- `channels:read`, `files:read`, `groups:read`, `im:read`, `mpim:read`, `search:read`, `users:read`

### Provide Token

**Option 1: Environment Variable**
```bash
export SLACK_SECRETS_SCANNER_TOKEN=xoxp-your-token-here
```

**Option 2: Configuration File**

Create `~/watchman.conf`:
```yaml
slack_secrets_scanner:
  token: xoxp-your-token-here
  disabled_detectors:
    - api_key_generic
    - password
```

See `docs/example.conf` for complete example.

## Usage

### Basic Scan
```bash
# Scan last 7 days
slack-secrets-scanner --timeframe w

# Scan all time
slack-secrets-scanner --timeframe a

# JSON output
slack-secrets-scanner --timeframe a --output json > results.json

# Skip verification (faster)
slack-secrets-scanner --timeframe a --no-verify

# Scan specific channels
slack-secrets-scanner --timeframe a --channels C1234567890,C0987654321
```

## Command-Line Options

```
Options:
  -t, --timeframe [d|w|m|a]    How far back to search:
                                d = 24 hours
                                w = 7 days
                                m = 30 days
                                a = all time (default)
  
  -o, --output [json|stdout]    Output format (default: stdout)
  
  -c, --channels TEXT           Comma-separated channel IDs to scan
  
  --no-verify                   Skip API verification of secrets
  
  --no-ssl-verify               Skip SSL verification (not recommended)
  
  -V, --verbose                 Include more details in output
  
  -v, --version                 Show version and exit
```

## Output

### Status Types
- **VERIFIED** (red) - Valid, active secrets requiring immediate action
- **UNVERIFIED** (yellow) - Detected secrets that couldn't be verified (needs review)
- **FALSE POSITIVE** (green) - Invalid/expired secrets (can be ignored)

### JSON Output
```json
{
  "scan_info": {
    "timeframe": "a",
    "total_matches": 10,
    "verified": 2,
    "unverified": 5,
    "false_positives": 3
  },
  "matches": [...]
}
```

## Features

- **Entropy-Based Filtering**: Filters out low-entropy strings (dummy/generic secrets)
- **API Verification**: Verifies detected secrets via live API calls
- **50+ Secret Types**: AWS, GitHub, Slack, Stripe, Google, SendGrid, Twilio, Mailgun, Azure, and more
- **Configurable**: Disable specific detectors via `watchman.conf`
- **Optimized**: Handles large workspaces with improved rate limiting

## Configuration

Create `~/watchman.conf` in your home directory:

**Windows**: `C:\Users\<username>\watchman.conf`  
**macOS/Linux**: `~/.watchman.conf`

```yaml
slack_secrets_scanner:
  token: xoxp-your-token-here
  disabled_detectors:
    - api_key_generic
    - password
    - bearer_token
```

## AWS Verification

For AWS secret verification, install optional dependency:
```bash
pip install boto3
# or
pip install slack-secrets-scanner[aws]
```

## License

GNU General Public License v2.0 - see LICENSE file for details.

## Disclaimer

This tool is not associated with Slack Technologies. Use responsibly and only on workspaces you have permission to scan.
