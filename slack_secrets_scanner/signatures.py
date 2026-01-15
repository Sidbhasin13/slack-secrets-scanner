"""Secret detection signatures."""

from .detectors import SecretDetector

COMPREHENSIVE_SIGNATURES = {
    "aws_access_key": SecretDetector(
        "AWS Access Key",
        r'(?:aws_access_key_id|aws_access_key|accesskeyid|AWS_ACCESS_KEY_ID|AWS_ACCESS_KEY)\s*[=:]\s*([A-Z0-9]{20})',
        min_entropy=4.5
    ),
    "aws_secret_key": SecretDetector(
        "AWS Secret Key",
        r'(?:aws_secret_access_key|aws_secret_key|secretaccesskey|AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY)\s*[=:]\s*([A-Za-z0-9/+=]{40})',
        min_entropy=4.5
    ),
    "aws_session_token": SecretDetector(
        "AWS Session Token",
        r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*([A-Za-z0-9/+=]{100,})',
        min_entropy=4.5
    ),
    
    # GitHub
    "github_token": SecretDetector(
        "GitHub Token",
        r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}',
        min_entropy=4.5
    ),
    "github_pat": SecretDetector(
        "GitHub Personal Access Token",
        r'github_pat_[A-Za-z0-9_]{82}',
        min_entropy=4.5
    ),
    "github_oauth": SecretDetector(
        "GitHub OAuth Token",
        r'gho_[A-Za-z0-9]{36}',
        min_entropy=4.5
    ),
    
    # Slack
    "slack_token": SecretDetector(
        "Slack Token",
        r'(?:xox[baprs]-[0-9a-zA-Z-]{10,})',
        min_entropy=4.5
    ),
    "slack_webhook": SecretDetector(
        "Slack Webhook URL",
        r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+',
        min_entropy=3.5
    ),
    
    # Stripe
    "stripe_key": SecretDetector(
        "Stripe API Key",
        r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}',
        min_entropy=4.5
    ),
    "stripe_restricted_key": SecretDetector(
        "Stripe Restricted Key",
        r'rk_(?:test|live)_[A-Za-z0-9]{24,}',
        min_entropy=4.5
    ),
    
    # Google
    "google_api_key": SecretDetector(
        "Google API Key",
        r'AIza[0-9A-Za-z\-_]{35}',
        min_entropy=4.5
    ),
    "google_oauth": SecretDetector(
        "Google OAuth Token",
        r'ya29\.[A-Za-z0-9_-]{100,}',
        min_entropy=4.5
    ),
    "firebase_key": SecretDetector(
        "Firebase Key",
        r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        min_entropy=4.5
    ),
    
    # Azure
    "azure_key": SecretDetector(
        "Azure Key",
        r'[a-z0-9]{32}=',
        min_entropy=4.5
    ),
    "azure_client_secret": SecretDetector(
        "Azure Client Secret",
        r'(?:azure_client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*([A-Za-z0-9+/=]{32,})',
        min_entropy=4.5
    ),
    
    # Database URLs
    "postgres_url": SecretDetector(
        "PostgreSQL URL",
        r'postgres(?:ql)?://[^\s\'"<>]+',
        min_entropy=3.0
    ),
    "mysql_url": SecretDetector(
        "MySQL URL",
        r'mysql://[^\s\'"<>]+',
        min_entropy=3.0
    ),
    "mongodb_url": SecretDetector(
        "MongoDB URL",
        r'mongodb(?:\+srv)?://[^\s\'"<>]+',
        min_entropy=3.0
    ),
    "redis_url": SecretDetector(
        "Redis URL",
        r'redis://[^\s\'"<>]+',
        min_entropy=3.0
    ),
    
    # Email Services
    "sendgrid_key": SecretDetector(
        "SendGrid API Key",
        r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}',
        min_entropy=4.5
    ),
    "mailgun_key": SecretDetector(
        "Mailgun API Key",
        r'key-[A-Za-z0-9]{32}',
        min_entropy=4.5
    ),
    "mailgun_webhook": SecretDetector(
        "Mailgun Webhook",
        r'https://api\.mailgun\.net/v3/[^\s\'"<>]+',
        min_entropy=3.5
    ),
    
    # Communication Services
    "twilio_key": SecretDetector(
        "Twilio API Key",
        r'AC[a-z0-9]{32}',
        min_entropy=4.5
    ),
    "twilio_auth_token": SecretDetector(
        "Twilio Auth Token",
        r'(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*([A-Za-z0-9]{32})',
        min_entropy=4.5
    ),
    
    # Cloud Platforms
    "heroku_key": SecretDetector(
        "Heroku API Key",
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        min_entropy=3.0
    ),
    "digitalocean_token": SecretDetector(
        "DigitalOcean Token",
        r'(?:digitalocean_token|DIGITALOCEAN_TOKEN)\s*[=:]\s*([A-Za-z0-9]{64})',
        min_entropy=4.5
    ),
    
    # Generic Patterns
    "api_key_generic": SecretDetector(
        "Generic API Key",
        r'(?:api[_-]?key|apikey|API_KEY|APIKEY)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
        min_entropy=4.5
    ),
    "bearer_token": SecretDetector(
        "Bearer Token",
        r'bearer\s+([A-Za-z0-9_\-\.]{20,})',
        min_entropy=4.5
    ),
    "authorization_token": SecretDetector(
        "Authorization Token",
        r'authorization\s*:\s*([A-Za-z0-9_\-\.]{20,})',
        min_entropy=4.5
    ),
    
    # Security Keys
    "private_key": SecretDetector(
        "Private Key",
        r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE KEY-----',
        min_entropy=4.5
    ),
    "jwt_token": SecretDetector(
        "JWT Token",
        r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        min_entropy=4.5
    ),
    "ssh_key": SecretDetector(
        "SSH Key",
        r'ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/=]{100,}',
        min_entropy=4.5
    ),
    
    # Passwords
    "password": SecretDetector(
        "Password",
        r'(?:password|passwd|pwd|PASSWORD|PASSWD)\s*[=:]\s*["\']?([A-Za-z0-9@#$%^&+=]{12,})["\']?',
        min_entropy=4.5
    ),
    
    # Social Media
    "facebook_token": SecretDetector(
        "Facebook Token",
        r'EAAB[A-Za-z0-9]{100,}',
        min_entropy=4.5
    ),
    "twitter_token": SecretDetector(
        "Twitter Token",
        r'(?:twitter_token|TWITTER_TOKEN)\s*[=:]\s*([A-Za-z0-9]{50,})',
        min_entropy=4.5
    ),
    
    # Payment Processors
    "paypal_token": SecretDetector(
        "PayPal Token",
        r'access_token\$production\$[A-Za-z0-9]{22}\$[A-Za-z0-9]{86}',
        min_entropy=4.5
    ),
    "square_token": SecretDetector(
        "Square Token",
        r'sq0atp-[A-Za-z0-9_-]{22}',
        min_entropy=4.5
    ),
    
    # CI/CD
    "jenkins_token": SecretDetector(
        "Jenkins Token",
        r'(?:jenkins_token|JENKINS_TOKEN)\s*[=:]\s*([A-Za-z0-9]{32,})',
        min_entropy=4.5
    ),
    "circleci_token": SecretDetector(
        "CircleCI Token",
        r'CIRCLE_TOKEN\s*[=:]\s*([A-Za-z0-9]{40})',
        min_entropy=4.5
    ),
    "travis_token": SecretDetector(
        "Travis CI Token",
        r'TRAVIS_TOKEN\s*[=:]\s*([A-Za-z0-9]{22})',
        min_entropy=4.5
    ),
    
    # Monitoring
    "datadog_key": SecretDetector(
        "Datadog API Key",
        r'(?:datadog_api_key|DATADOG_API_KEY)\s*[=:]\s*([A-Za-z0-9]{32})',
        min_entropy=4.5
    ),
    "newrelic_key": SecretDetector(
        "New Relic Key",
        r'(?:newrelic_key|NEW_RELIC_KEY)\s*[=:]\s*([A-Za-z0-9]{40})',
        min_entropy=4.5
    ),
    
    # Storage
    "s3_access_key": SecretDetector(
        "S3 Access Key",
        r'(?:s3_access_key|S3_ACCESS_KEY)\s*[=:]\s*([A-Z0-9]{20})',
        min_entropy=4.5
    ),
    "dropbox_token": SecretDetector(
        "Dropbox Token",
        r'sl\.[A-Za-z0-9_-]{135}',
        min_entropy=4.5
    ),
}

