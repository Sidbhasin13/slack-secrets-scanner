"""Verification logic for detected secrets."""

import re
import requests
from typing import Optional
from .detectors import SecretMatch


class SecretVerifier:
    """Verifies detected secrets by attempting API calls."""
    
    def __init__(self, verify_ssl: bool = True, timeout: int = 5):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
    
    def verify(self, match: SecretMatch) -> SecretMatch:
        """Verify a secret match by attempting API calls."""
        verifier_map = {
            "AWS Access Key": self._verify_aws,
            "AWS Secret Key": self._verify_aws,
            "AWS Session Token": self._verify_aws,
            "GitHub Token": self._verify_github,
            "GitHub Personal Access Token": self._verify_github,
            "GitHub OAuth Token": self._verify_github,
            "Slack Token": self._verify_slack,
            "Google API Key": self._verify_google_api,
            "Google OAuth Token": self._verify_google_oauth,
            "Stripe API Key": self._verify_stripe,
            "Stripe Restricted Key": self._verify_stripe,
            "SendGrid API Key": self._verify_sendgrid,
            "Twilio API Key": self._verify_twilio,
            "Twilio Auth Token": self._verify_twilio,
            "Mailgun API Key": self._verify_mailgun,
            "Azure Key": self._verify_azure,
            "Azure Client Secret": self._verify_azure,
        }
        
        verifier = verifier_map.get(match.secret_type)
        if verifier:
            try:
                return verifier(match)
            except Exception as e:
                match.verification_details = f"Verification error: {str(e)}"
                match.verification_status = "unverified"
        else:
            match = self._verify_generic(match)
        
        return match
    
    def _verify_generic(self, match: SecretMatch) -> SecretMatch:
        """Generic verification for unknown/custom secret types."""
        if match.entropy_score >= 4.5:
            match.verification_status = "unverified"
            match.verification_details = "High entropy detected - likely valid secret (manual review recommended)"
        elif match.entropy_score >= 3.5:
            match.verification_status = "unverified"
            match.verification_details = "Medium entropy - review recommended"
        else:
            match.verification_status = "false_positive"
            match.verification_details = "Low entropy - likely false positive"
        
        return match
    
    def _verify_aws(self, match: SecretMatch) -> SecretMatch:
        """Verify AWS credentials using boto3."""
        access_key_match = None
        secret_key_match = None
        
        full_text = f"{match.context} {match.value}"
        
        access_key_match = re.search(r'AKIA[0-9A-Z]{16}', full_text)
        secret_key_match = re.search(r'[A-Za-z0-9/+=]{40}', full_text)
        
        if not access_key_match or not secret_key_match:
            match.verification_status = "unverified"
            match.verification_details = "Incomplete AWS credentials (need both access key and secret)"
            return match
        
        access_key = access_key_match.group(0)
        secret_key = secret_key_match.group(0)
        
        # Try to verify using boto3 (same as TruffleHog)
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Create STS client with the credentials
            sts_client = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name='us-east-1'  # Default region
            )
            
            # Call GetCallerIdentity to verify credentials
            response = sts_client.get_caller_identity()
            
            # If successful, credentials are valid
            account_id = response.get('Account', 'unknown')
            user_arn = response.get('Arn', 'unknown')
            
            match.verified = True
            match.verification_status = "verified"
            match.verification_details = f"Valid AWS credentials for account: {account_id}, ARN: {user_arn}"
            
        except ImportError:
            # boto3 not installed
            match.verification_status = "unverified"
            match.verification_details = "AWS verification requires boto3 library (install with: pip install boto3)"
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['InvalidClientTokenId', 'SignatureDoesNotMatch']:
                match.verification_status = "false_positive"
                match.verification_details = f"Invalid AWS credentials: {error_code}"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"AWS API error: {error_code}"
        except NoCredentialsError:
            match.verification_status = "unverified"
            match.verification_details = "AWS credentials not properly formatted"
        except Exception as e:
            match.verification_status = "unverified"
            match.verification_details = f"AWS verification error: {str(e)}"
        
        return match
    
    def _verify_github(self, match: SecretMatch) -> SecretMatch:
        """Verify GitHub token."""
        token = match.value
        if token.startswith('github_pat_'):
            token = token
        elif '_' in token:
            token = token.split('_', 1)[1] if len(token.split('_')) > 1 else token
        
        headers = {
            "Authorization": f"token {match.value}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = self.session.get(
                "https://api.github.com/user",
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                user_data = response.json()
                match.verified = True
                match.verification_status = "verified"
                match.verification_details = f"Valid token for user: {user_data.get('login', 'unknown')}"
            elif response.status_code == 401:
                match.verification_status = "false_positive"
                match.verification_details = "Invalid/expired token"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"API returned status {response.status_code}"
        except requests.exceptions.RequestException as e:
            match.verification_status = "unverified"
            match.verification_details = f"Verification failed: {str(e)}"
        
        return match
    
    def _verify_slack(self, match: SecretMatch) -> SecretMatch:
        """Verify Slack token."""
        headers = {
            "Authorization": f"Bearer {match.value}"
        }
        
        try:
            response = self.session.post(
                "https://slack.com/api/auth.test",
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("ok"):
                    match.verified = True
                    match.verification_status = "verified"
                    match.verification_details = f"Valid token for workspace: {data.get('team', 'unknown')}"
                else:
                    match.verification_status = "false_positive"
                    match.verification_details = f"Invalid token: {data.get('error', 'unknown error')}"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"API returned status {response.status_code}"
        except requests.exceptions.RequestException as e:
            match.verification_status = "unverified"
            match.verification_details = f"Verification failed: {str(e)}"
        
        return match
    
    def _verify_google_api(self, match: SecretMatch) -> SecretMatch:
        """Verify Google API key."""
        # Test with a simple API call
        try:
            response = self.session.get(
                "https://www.googleapis.com/discovery/v1/apis",
                params={"key": match.value},
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                match.verified = True
                match.verification_status = "verified"
                match.verification_details = "Valid Google API key"
            elif response.status_code == 403:
                match.verification_status = "false_positive"
                match.verification_details = "Invalid or restricted API key"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"API returned status {response.status_code}"
        except requests.exceptions.RequestException as e:
            match.verification_status = "unverified"
            match.verification_details = f"Verification failed: {str(e)}"
        
        return match
    
    def _verify_google_oauth(self, match: SecretMatch) -> SecretMatch:
        """Verify Google OAuth token."""
        headers = {
            "Authorization": f"Bearer {match.value}"
        }
        
        try:
            response = self.session.get(
                "https://www.googleapis.com/oauth2/v1/userinfo",
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                match.verified = True
                match.verification_status = "verified"
                match.verification_details = "Valid Google OAuth token"
            elif response.status_code == 401:
                match.verification_status = "false_positive"
                match.verification_details = "Invalid/expired OAuth token"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"API returned status {response.status_code}"
        except requests.exceptions.RequestException as e:
            match.verification_status = "unverified"
            match.verification_details = f"Verification failed: {str(e)}"
        
        return match
    
    def _verify_stripe(self, match: SecretMatch) -> SecretMatch:
        """Verify Stripe API key."""
        headers = {
            "Authorization": f"Bearer {match.value}"
        }
        
        try:
            # Use a lightweight endpoint
            response = self.session.get(
                "https://api.stripe.com/v1/account",
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                match.verified = True
                match.verification_status = "verified"
                match.verification_details = "Valid Stripe API key"
            elif response.status_code == 401:
                match.verification_status = "false_positive"
                match.verification_details = "Invalid Stripe API key"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"API returned status {response.status_code}"
        except requests.exceptions.RequestException as e:
            match.verification_status = "unverified"
            match.verification_details = f"Verification failed: {str(e)}"
        
        return match
    
    def _verify_sendgrid(self, match: SecretMatch) -> SecretMatch:
        """Verify SendGrid API key."""
        headers = {
            "Authorization": f"Bearer {match.value}"
        }
        
        try:
            response = self.session.get(
                "https://api.sendgrid.com/v3/user/profile",
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                match.verified = True
                match.verification_status = "verified"
                match.verification_details = "Valid SendGrid API key"
            elif response.status_code == 401:
                match.verification_status = "false_positive"
                match.verification_details = "Invalid SendGrid API key"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"API returned status {response.status_code}"
        except requests.exceptions.RequestException as e:
            match.verification_status = "unverified"
            match.verification_details = f"Verification failed: {str(e)}"
        
        return match
    
    def _verify_twilio(self, match: SecretMatch) -> SecretMatch:
        """Verify Twilio API key or auth token."""
        # Try to determine if it's an API key (starts with AC) or auth token
        if match.value.startswith('AC'):
            # API Key - use Account API
            try:
                response = self.session.get(
                    f"https://api.twilio.com/2010-04-01/Accounts/{match.value}.json",
                    auth=(match.value, match.value),  # Will fail but tests format
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                # If we get here, format is valid (actual auth would need both key and token)
                match.verification_status = "unverified"
                match.verification_details = "Twilio API key format valid (requires auth token for full verification)"
            except requests.exceptions.RequestException:
                match.verification_status = "unverified"
                match.verification_details = "Could not verify Twilio credentials"
        else:
            # Auth token - mark as unverified (needs account SID to verify)
            match.verification_status = "unverified"
            match.verification_details = "Twilio auth token detected (requires account SID for verification)"
        
        return match
    
    def _verify_mailgun(self, match: SecretMatch) -> SecretMatch:
        """Verify Mailgun API key."""
        try:
            response = self.session.get(
                "https://api.mailgun.net/v3/domains",
                auth=("api", match.value),
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                match.verified = True
                match.verification_status = "verified"
                match.verification_details = "Valid Mailgun API key"
            elif response.status_code == 401:
                match.verification_status = "false_positive"
                match.verification_details = "Invalid Mailgun API key"
            else:
                match.verification_status = "unverified"
                match.verification_details = f"API returned status {response.status_code}"
        except requests.exceptions.RequestException as e:
            match.verification_status = "unverified"
            match.verification_details = f"Verification failed: {str(e)}"
        
        return match
    
    def _verify_azure(self, match: SecretMatch) -> SecretMatch:
        """Verify Azure credentials."""
        # Azure verification is complex and requires tenant ID
        # Mark as unverified but provide guidance
        match.verification_status = "unverified"
        match.verification_details = "Azure verification requires tenant ID and additional context (manual review recommended)"
        return match
