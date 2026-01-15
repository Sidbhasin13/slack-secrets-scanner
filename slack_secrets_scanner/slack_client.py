"""Slack API client for scanning workspaces."""

import time
import random
from typing import List, Optional, Dict, Any
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

try:
    from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler
    HAS_RETRY_HANDLERS = True
except ImportError:
    HAS_RETRY_HANDLERS = False


class SlackScanner:
    """Client for scanning Slack workspaces."""
    
    def __init__(
        self,
        token: str,
        cookie: Optional[str] = None,
        workspace_url: Optional[str] = None,
        max_retries: int = 10,
        base_delay: float = 1.0,
        timeout: int = 60
    ):
        self.token = token
        self.cookie = cookie
        self.workspace_url = workspace_url
        
        client_kwargs = {
            "token": token,
            "timeout": timeout
        }
        
        if HAS_RETRY_HANDLERS:
            client_kwargs["retry_handlers"] = [
                RateLimitErrorRetryHandler(max_retry_count=max_retries)
            ]
        
        self.client = WebClient(**client_kwargs)
        
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.max_retries = max_retries
        self.retry_delay = 2.0
        self.max_delay = 300
        
        self.api_call_count = 0
        self.rate_limit_count = 0
        self.last_rate_limit_time = 0
    
    def _handle_rate_limit(self, retry_after: Optional[int] = None) -> None:
        """Handle rate limiting with exponential backoff."""
        if retry_after:
            wait_time = retry_after
        else:
            wait_time = min(
                self.retry_delay * (2 ** self.rate_limit_count),
                self.max_delay
            )
            jitter = wait_time * 0.2 * random.random()
            wait_time += jitter
        
        self.rate_limit_count += 1
        self.last_rate_limit_time = time.time()
        self.current_delay = min(wait_time, self.max_delay)
        
        print(f"Rate limited. Waiting {wait_time:.1f} seconds... (attempt {self.rate_limit_count})")
        time.sleep(wait_time)
    
    def _adaptive_delay(self) -> None:
        """Apply adaptive delay based on API call history."""
        time_since_rate_limit = time.time() - self.last_rate_limit_time
        if time_since_rate_limit < 60:
            delay = self.current_delay
        else:
            delay = max(self.base_delay, self.current_delay * 0.9)
            self.current_delay = delay
        
        time.sleep(delay)
        self.api_call_count += 1
    
    def _retry_with_backoff(self, func, *args, **kwargs):
        """Execute a function with exponential backoff retry logic."""
        retries = 0
        last_exception = None
        
        while retries <= self.max_retries:
            try:
                return func(*args, **kwargs)
            except SlackApiError as e:
                error = e.response.get("error", "unknown")
                
                if error == "rate_limited":
                    retry_after = 60
                    try:
                        if hasattr(e, 'response') and e.response:
                            if hasattr(e.response, 'headers'):
                                headers = e.response.headers
                                if headers and "Retry-After" in headers:
                                    retry_after = int(headers["Retry-After"])
                            elif isinstance(e.response, dict):
                                headers = e.response.get("headers", {})
                                if isinstance(headers, dict) and "Retry-After" in headers:
                                    retry_after = int(headers["Retry-After"])
                    except (ValueError, AttributeError, TypeError, KeyError):
                        retry_after = 60
                    
                    self._handle_rate_limit(retry_after)
                    retries += 1
                    continue
                
                elif error in ["timeout", "request_timeout", "internal_error", "server_error"]:
                    wait_time = min(self.retry_delay * (2 ** retries), self.max_delay)
                    print(f"Server error ({error}), retrying in {wait_time:.1f}s... (attempt {retries + 1}/{self.max_retries + 1})")
                    time.sleep(wait_time)
                    retries += 1
                    last_exception = e
                    continue
                
                else:
                    raise
            
            except (ConnectionError, TimeoutError, OSError) as e:
                wait_time = min(self.retry_delay * (2 ** retries), self.max_delay)
                print(f"Network error, retrying in {wait_time:.1f}s... (attempt {retries + 1}/{self.max_retries + 1})")
                time.sleep(wait_time)
                retries += 1
                last_exception = e
                continue
            
            except Exception as e:
                raise
        
        if last_exception:
            raise last_exception
        raise Exception("Max retries exceeded")
    
    def get_channels(self, include_private: bool = True) -> List[Dict[str, Any]]:
        """
        Get all channels in the workspace with robust pagination and rate limiting.
        
        Args:
            include_private: Whether to include private channels
            
        Returns:
            List of channel dictionaries
        """
        channels = []
        cursor = None
        
        try:
            while True:
                def fetch_public():
                    return self.client.conversations_list(
                        types="public_channel",
                        limit=200,
                        cursor=cursor
                    )
                
                response = self._retry_with_backoff(fetch_public)
                channels.extend(response.get("channels", []))
                cursor = response.get("response_metadata", {}).get("next_cursor")
                
                if not cursor:
                    break
                
                self._adaptive_delay()
            
            if include_private:
                cursor = None
                while True:
                    def fetch_private():
                        return self.client.conversations_list(
                            types="private_channel",
                            limit=200,
                            cursor=cursor
                        )
                    
                    response = self._retry_with_backoff(fetch_private)
                    channels.extend(response.get("channels", []))
                    cursor = response.get("response_metadata", {}).get("next_cursor")
                    
                    if not cursor:
                        break
                    
                    self._adaptive_delay()
        
        except Exception as e:
            print(f"Error fetching channels: {str(e)}")
        
        return channels
    
    def get_direct_messages(self) -> List[Dict[str, Any]]:
        """
        Get all direct message conversations with pagination support.
        
        Returns:
            List of DM conversation dictionaries
        """
        conversations = []
        cursor = None
        
        try:
            while True:
                def fetch_dms():
                    return self.client.conversations_list(
                        types="im",
                        limit=200,
                        cursor=cursor
                    )
                
                response = self._retry_with_backoff(fetch_dms)
                conversations.extend(response.get("channels", []))
                cursor = response.get("response_metadata", {}).get("next_cursor")
                
                if not cursor:
                    break
                
                self._adaptive_delay()
        
        except Exception as e:
            print(f"Error fetching DMs: {str(e)}")
        
        return conversations
    
    def get_channel_messages(
        self,
        channel_id: str,
        oldest: Optional[float] = None,
        latest: Optional[float] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Get messages from a channel with robust rate limiting, retry logic, and timeout handling.
        
        Args:
            channel_id: Channel ID
            oldest: Unix timestamp of oldest message (optional)
            latest: Unix timestamp of latest message (optional)
            limit: Maximum number of messages to retrieve
            
        Returns:
            List of message dictionaries
        """
        all_messages = []
        cursor = None
        
        try:
            while len(all_messages) < limit:
                def fetch_messages():
                    return self.client.conversations_history(
                        channel=channel_id,
                        oldest=oldest,
                        latest=latest,
                        limit=min(200, limit - len(all_messages)),
                        cursor=cursor
                    )
                
                try:
                    response = self._retry_with_backoff(fetch_messages)
                    
                    messages = response.get("messages", [])
                    if not messages:
                        break
                    
                    all_messages.extend(messages)
                    
                    cursor = response.get("response_metadata", {}).get("next_cursor")
                    if not cursor:
                        break
                    
                    self._adaptive_delay()
                    
                except SlackApiError as e:
                    error = e.response.get("error", "unknown")
                    
                    if error == "channel_not_found":
                        break
                    
                    print(f"Failed to fetch messages from channel {channel_id} after retries: {error}")
                    break
                        
        except Exception as e:
            print(f"Unexpected error fetching messages from channel {channel_id}: {str(e)}")
        
        return all_messages[:limit]
    
    def get_file_content(self, file_id: str) -> Optional[str]:
        """
        Get content of a file with retry logic.
        
        Args:
            file_id: File ID
            
        Returns:
            File content as string, or None if error
        """
        try:
            def fetch_file():
                return self.client.files_info(file=file_id)
            
            response = self._retry_with_backoff(fetch_file)
            file_info = response.get("file", {})
            
            file_url = file_info.get("url_private")
            if not file_url:
                return None
            
            return f"File: {file_info.get('name', 'unknown')} - URL: {file_url}"
        
        except Exception as e:
            print(f"Error fetching file {file_id}: {str(e)}")
            return None
    
    def search_messages(
        self,
        query: str,
        oldest: Optional[float] = None,
        latest: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Search messages across the workspace with robust pagination.
        
        Args:
            query: Search query
            oldest: Unix timestamp of oldest message (optional)
            latest: Unix timestamp of latest message (optional)
            
        Returns:
            List of matching messages
        """
        all_messages = []
        page = 1
        
        try:
            while True:
                def search():
                    return self.client.search_messages(
                        query=query,
                        sort="timestamp",
                        sort_dir="desc",
                        count=100,
                        page=page
                    )
                
                response = self._retry_with_backoff(search)
                matches = response.get("messages", {}).get("matches", [])
                
                if not matches:
                    break
                
                all_messages.extend(matches)
                page += 1
                self._adaptive_delay()
        
        except Exception as e:
            print(f"Error searching messages: {str(e)}")
        
        return all_messages
    
    def get_workspace_info(self) -> Dict[str, Any]:
        """
        Get workspace information with retry logic.
        
        Returns:
            Workspace information dictionary
        """
        try:
            def fetch_info():
                return self.client.team_info()
            
            response = self._retry_with_backoff(fetch_info)
            return response.get("team", {})
        
        except Exception as e:
            print(f"Error fetching workspace info: {str(e)}")
            return {}
    
    def test_connection(self) -> bool:
        """
        Test the connection to Slack with retry logic.
        
        Returns:
            True if connection is successful
        """
        try:
            def test():
                return self.client.auth_test()
            
            response = self._retry_with_backoff(test)
            return response.get("ok", False)
        
        except Exception:
            return False

