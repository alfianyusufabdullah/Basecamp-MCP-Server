"""
Token storage module for securely storing OAuth tokens.

This module provides a multi-user interface for storing and retrieving OAuth tokens,
while maintaining full backward compatibility for single-user setups.
"""

import os
import json
import threading
import secrets
from datetime import datetime, timedelta
import logging

# Determine directory where script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_token_file_env = os.environ.get('BASECAMP_MCP_TOKEN_FILE')
TOKEN_FILE = (
    os.path.expanduser(os.path.expandvars(_token_file_env))
    if _token_file_env
    else os.path.join(SCRIPT_DIR, 'oauth_tokens.json')
)

# Lock for thread-safe operations
_lock = threading.Lock()
_logger = logging.getLogger(__name__)


def _read_tokens():
    """Read tokens from storage with automatic migration for legacy format."""
    try:
        with open(TOKEN_FILE, 'r') as f:
            data = json.load(f)

        # Migrate legacy format if 'users' dict is not present
        if 'users' not in data and 'basecamp' in data:
            legacy_data = data['basecamp']
            user_id = str(legacy_data.get('account_id') or 'default')
            data['users'] = {
                user_id: {
                    'user_id': user_id,
                    'account_id': legacy_data.get('account_id'),
                    'access_token': legacy_data.get('access_token'),
                    'refresh_token': legacy_data.get('refresh_token'),
                    'expires_at': legacy_data.get('expires_at'),
                    'updated_at': legacy_data.get('updated_at', datetime.now().isoformat()),
                    'email': legacy_data.get('email', 'default@basecamp.local'),
                    'name': legacy_data.get('name', 'Default User'),
                    'api_key': legacy_data.get('api_key') or f"mcp_key_{secrets.token_hex(8)}"
                }
            }
            data['default_user_id'] = user_id

        if 'users' not in data:
            data['users'] = {}

        return data
    except FileNotFoundError:
        _logger.info(f"{TOKEN_FILE} not found. Returning empty tokens.")
        return {'users': {}, 'default_user_id': None}
    except json.JSONDecodeError:
        _logger.warning(f"Error decoding JSON from {TOKEN_FILE}. Returning empty tokens.")
        return {'users': {}, 'default_user_id': None}


def _write_tokens(tokens):
    """Write tokens to storage securely."""
    os.makedirs(os.path.dirname(TOKEN_FILE) if os.path.dirname(TOKEN_FILE) else '.', exist_ok=True)

    # Maintain legacy 'basecamp' key for backward compatibility
    default_user_id = tokens.get('default_user_id')
    users = tokens.get('users', {})
    if default_user_id and default_user_id in users:
        tokens['basecamp'] = users[default_user_id]
    elif users:
        first_user_id = next(iter(users))
        tokens['basecamp'] = users[first_user_id]

    with open(TOKEN_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)

    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception:
        pass


def store_user_token(
    user_id: str,
    access_token: str,
    refresh_token: str = None,
    expires_in: int = None,
    account_id: str = None,
    email: str = None,
    name: str = None,
    api_key: str = None,
    set_as_default: bool = True
) -> bool:
    """Store OAuth token for a specific user ID."""
    if not access_token or not user_id:
        return False

    user_id = str(user_id)

    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})

        expires_at = None
        if expires_in:
            expires_at = (datetime.now() + timedelta(seconds=expires_in)).isoformat()

        existing_user = users.get(user_id, {})
        user_api_key = api_key or existing_user.get('api_key') or f"mcp_key_{secrets.token_hex(12)}"

        users[user_id] = {
            'user_id': user_id,
            'account_id': str(account_id) if account_id else existing_user.get('account_id'),
            'access_token': access_token,
            'refresh_token': refresh_token or existing_user.get('refresh_token'),
            'expires_at': expires_at or existing_user.get('expires_at'),
            'updated_at': datetime.now().isoformat(),
            'email': email or existing_user.get('email'),
            'name': name or existing_user.get('name'),
            'api_key': user_api_key
        }

        tokens['users'] = users

        if set_as_default or not tokens.get('default_user_id'):
            tokens['default_user_id'] = user_id

        _write_tokens(tokens)
        return True


def get_token():
    """Get the stored OAuth token for default/active user (legacy & mock friendly)."""
    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})
        default_id = tokens.get('default_user_id')

        if default_id and default_id in users:
            return users[default_id]

        if users:
            first_key = next(iter(users))
            return users[first_key]

        return tokens.get('basecamp')


def get_user_token(user_id: str = None) -> dict:
    """Get stored OAuth token for a specific API Key or user ID.
    
    To prevent user impersonation in multi-user environments, matching by secret API Key
    is prioritized.
    """
    if user_id is None:
        return get_token()

    user_id = str(user_id)
    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})

        # Priority 1: Match secret API Key (Cryptographically secure token)
        for uid, udata in users.items():
            if udata.get('api_key') == user_id:
                return udata

        # Priority 2: Direct lookup by user_id
        if user_id in users:
            return users[user_id]

        # Priority 3: Lookup by account_id or email
        for uid, udata in users.items():
            if str(udata.get('account_id')) == user_id or udata.get('email') == user_id:
                return udata

        return None


def get_user_by_api_key(api_key: str) -> dict:
    """Find user profile by MCP API Key."""
    if not api_key:
        return None
    with _lock:
        tokens = _read_tokens()
        for udata in tokens.get('users', {}).values():
            if udata.get('api_key') == api_key:
                return udata
    return None


def list_users() -> list:
    """List all registered users and their session status."""
    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})
        default_id = tokens.get('default_user_id')

        user_list = []
        for uid, udata in users.items():
            user_list.append({
                'user_id': uid,
                'account_id': udata.get('account_id'),
                'email': udata.get('email'),
                'name': udata.get('name'),
                'api_key': udata.get('api_key'),
                'updated_at': udata.get('updated_at'),
                'expires_at': udata.get('expires_at'),
                'is_default': uid == default_id,
                'is_expired': _check_expired(udata.get('expires_at'))
            })
        return user_list


def set_default_user(user_id: str) -> bool:
    """Set default active user ID."""
    user_id = str(user_id)
    with _lock:
        tokens = _read_tokens()
        if user_id in tokens.get('users', {}):
            tokens['default_user_id'] = user_id
            _write_tokens(tokens)
            return True
        return False


def _check_expired(expires_at_str: str) -> bool:
    """Helper to check expiration time with 5-minute buffer."""
    if not expires_at_str:
        return True
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        return datetime.now() > (expires_at - timedelta(minutes=5))
    except (ValueError, TypeError):
        return True


def is_token_expired():
    """Check if default token is expired (legacy & mock friendly)."""
    token_data = get_token()
    if not token_data or not token_data.get('expires_at'):
        return True
    return _check_expired(token_data.get('expires_at'))


def is_user_token_expired(user_id: str = None) -> bool:
    """Check if token for specific user (or default user) is expired."""
    if user_id is None:
        return is_token_expired()
    user_data = get_user_token(user_id)
    if not user_data:
        return is_token_expired()
    expires_at = user_data.get('expires_at')
    if not expires_at:
        return is_token_expired()
    return _check_expired(expires_at)


def remove_user_token(user_id: str) -> bool:
    """Remove a user token session."""
    user_id = str(user_id)
    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})
        if user_id in users:
            del users[user_id]
            if tokens.get('default_user_id') == user_id:
                tokens['default_user_id'] = next(iter(users)) if users else None
            tokens['users'] = users
            _write_tokens(tokens)
            return True
        return False


def store_token(access_token, refresh_token=None, expires_in=None, account_id=None):
    """Legacy wrapper."""
    user_id = str(account_id or 'default')
    return store_user_token(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        account_id=account_id
    )


def clear_tokens():
    """Clear all stored tokens."""
    with _lock:
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
        return True
