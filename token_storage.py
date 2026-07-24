"""
Token storage module with Multi-User support, Encrypted Tokens (Fernet AES),
Redis Storage backend, and automatic fallback to file storage.
"""

import os
import json
import base64
import hashlib
import threading
import secrets
from datetime import datetime, timedelta
import logging
from typing import Optional, Dict, List, Any
from cryptography.fernet import Fernet

try:
    import redis  # type: ignore[import-untyped, import-not-found]
    HAS_REDIS = True
except Exception:
    redis = None  # type: ignore[assignment]
    HAS_REDIS = False

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


def _get_fernet_cipher() -> Fernet:
    """Get Fernet cipher instance using TOKEN_ENCRYPTION_KEY or fallback secret."""
    raw_key = (
        os.getenv('TOKEN_ENCRYPTION_KEY') or
        os.getenv('FLASK_SECRET_KEY') or
        os.getenv('BASECAMP_CLIENT_SECRET') or
        'default_basecamp_mcp_encryption_secret_key_12345'
    )
    key_bytes = hashlib.sha256(raw_key.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def encrypt_val(val: str) -> str:
    """Encrypt sensitive token string."""
    if not val:
        return val
    try:
        cipher = _get_fernet_cipher()
        return cipher.encrypt(val.encode('utf-8')).decode('utf-8')
    except Exception as e:
        _logger.error(f"Token encryption failed: {e}")
        return val


def decrypt_val(val: str) -> str:
    """Decrypt sensitive token string (with fallback for unencrypted legacy tokens)."""
    if not val:
        return val
    try:
        cipher = _get_fernet_cipher()
        return cipher.decrypt(val.encode('utf-8')).decode('utf-8')
    except Exception:
        return val


def _get_redis_client() -> Any:
    """Get connected Redis client if REDIS_URL is configured. Raises RuntimeError if connection fails."""
    redis_url = os.getenv('REDIS_URL')
    if not redis_url:
        return None
    if not HAS_REDIS or redis is None:
        raise RuntimeError("REDIS_URL is configured but 'redis' package is not installed.")
    try:
        redis_cls: Any = getattr(redis, 'Redis', None)
        if redis_cls is not None:
            r: Any = redis_cls.from_url(redis_url, socket_timeout=2)
            r.ping()
            return r
        raise RuntimeError("redis.Redis class not found.")
    except Exception as e:
        _logger.error(f"Redis connection failed for URL {redis_url}: {e}")
        raise RuntimeError(f"Failed to connect to Redis at {redis_url}: {e}") from e


def _decrypt_user_data(udata: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return copy of user dict with decrypted tokens."""
    if not udata:
        return None
    data = dict(udata)
    if 'access_token' in data and data['access_token']:
        data['access_token'] = decrypt_val(data['access_token'])
    if 'refresh_token' in data and data['refresh_token']:
        data['refresh_token'] = decrypt_val(data['refresh_token'])
    return data


def _read_tokens() -> Dict[str, Any]:
    """Read tokens from Redis if REDIS_URL is set, otherwise from local JSON file storage."""
    redis_url = os.getenv('REDIS_URL')
    if redis_url:
        r = _get_redis_client()  # Raises RuntimeError if Redis connection fails
        raw_data = r.get("basecamp:tokens")
        if raw_data:
            data = json.loads(raw_data.decode('utf-8'))
            if 'users' in data:
                return data
        return {'users': {}, 'default_user_id': None}

    # File storage only used when REDIS_URL is unconfigured
    try:
        with open(TOKEN_FILE, 'r') as f:
            data = json.load(f)

        # Migrate legacy single-user format if 'users' dict not present
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
        return {'users': {}, 'default_user_id': None}
    except json.JSONDecodeError:
        return {'users': {}, 'default_user_id': None}


def _write_tokens(tokens: Dict[str, Any]) -> None:
    """Write tokens to Redis if REDIS_URL is set, otherwise to local file storage."""
    # Maintain legacy 'basecamp' key for backward compatibility
    default_user_id = tokens.get('default_user_id')
    users = tokens.get('users', {})
    if default_user_id and default_user_id in users:
        tokens['basecamp'] = users[default_user_id]
    elif users:
        first_user_id = next(iter(users))
        tokens['basecamp'] = users[first_user_id]
    else:
        tokens.pop('basecamp', None)

    redis_url = os.getenv('REDIS_URL')
    if redis_url:
        r = _get_redis_client()  # Raises RuntimeError if Redis connection fails
        r.set("basecamp:tokens", json.dumps(tokens))
        _logger.info("Successfully persisted encrypted tokens to Redis.")
        return

    # File storage only used when REDIS_URL is unconfigured
    os.makedirs(os.path.dirname(TOKEN_FILE) if os.path.dirname(TOKEN_FILE) else '.', exist_ok=True)
    with open(TOKEN_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)

    try:
        os.chmod(TOKEN_FILE, 0o600)
    except Exception:
        pass


def store_user_token(
    user_id: str,
    access_token: str,
    refresh_token: Optional[str] = None,
    expires_in: Optional[int] = None,
    account_id: Optional[str] = None,
    email: Optional[str] = None,
    name: Optional[str] = None,
    api_key: Optional[str] = None,
    set_as_default: bool = True
) -> bool:
    """Store OAuth token for a specific user ID with token encryption."""
    if not access_token or not user_id:
        return False

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
            'account_id': account_id if account_id is not None else existing_user.get('account_id'),
            'access_token': encrypt_val(access_token),
            'refresh_token': encrypt_val(refresh_token) if refresh_token else existing_user.get('refresh_token'),
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


def get_token() -> Optional[Dict[str, Any]]:
    """Get the stored OAuth token for default/active user (decrypted)."""
    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})
        default_id = tokens.get('default_user_id')

        if default_id and default_id in users:
            return _decrypt_user_data(users[default_id])

        if users:
            first_key = next(iter(users))
            return _decrypt_user_data(users[first_key])

        return _decrypt_user_data(tokens.get('basecamp'))


def get_user_token(user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get stored OAuth token for a specific API Key or user ID (decrypted)."""
    if user_id is None:
        return get_token()

    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})

        # Priority 1: Match secret API Key (Cryptographically secure token)
        for uid, udata in users.items():
            if udata.get('api_key') == user_id:
                return _decrypt_user_data(udata)

        # Priority 2: Direct lookup by user_id
        if user_id in users:
            return _decrypt_user_data(users[user_id])

        # Priority 3: Lookup by account_id or email
        for uid, udata in users.items():
            if str(udata.get('account_id')) == user_id or udata.get('email') == user_id:
                return _decrypt_user_data(udata)

        return None


def get_user_by_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Find user profile by MCP API Key."""
    return get_user_token(api_key)


def list_users() -> List[Dict[str, Any]]:
    """List all registered users and their session status."""
    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})
        default_id = tokens.get('default_user_id')

        user_list = []
        for uid, udata in users.items():
            expires_at_val = udata.get('expires_at')
            expires_at_str = expires_at_val if isinstance(expires_at_val, str) else None
            user_list.append({
                'user_id': uid,
                'account_id': udata.get('account_id'),
                'email': udata.get('email'),
                'name': udata.get('name'),
                'api_key': udata.get('api_key'),
                'updated_at': udata.get('updated_at'),
                'expires_at': expires_at_val,
                'is_default': uid == default_id,
                'is_expired': _check_expired(expires_at_str)
            })
        return user_list


def set_default_user(user_id: str) -> bool:
    """Set default active user ID."""
    with _lock:
        tokens = _read_tokens()
        if user_id in tokens.get('users', {}):
            tokens['default_user_id'] = user_id
            _write_tokens(tokens)
            return True
        return False


def _check_expired(expires_at_str: Optional[str]) -> bool:
    """Helper to check expiration time with 5-minute buffer."""
    if not expires_at_str:
        return True
    try:
        expires_at = datetime.fromisoformat(expires_at_str)
        return datetime.now() > (expires_at - timedelta(minutes=5))
    except (ValueError, TypeError):
        return True


def is_token_expired() -> bool:
    """Check if default token is expired."""
    token_data = get_token()
    if not token_data:
        return True
    expires_at = token_data.get('expires_at')
    expires_at_str = expires_at if isinstance(expires_at, str) else None
    return _check_expired(expires_at_str)


def is_user_token_expired(user_id: Optional[str] = None) -> bool:
    """Check if token for specific user (or default user) is expired."""
    if user_id is None:
        return is_token_expired()
    user_data = get_user_token(user_id)
    if not user_data:
        return is_token_expired()
    expires_at = user_data.get('expires_at')
    expires_at_str = expires_at if isinstance(expires_at, str) else None
    return _check_expired(expires_at_str)


def remove_user_token(user_id: str) -> bool:
    """Remove a user token session."""
    with _lock:
        tokens = _read_tokens()
        users = tokens.get('users', {})
        target_uid = None
        if user_id in users:
            target_uid = user_id
        else:
            for uid, udata in users.items():
                if str(udata.get('account_id')) == user_id or udata.get('email') == user_id or udata.get('api_key') == user_id:
                    target_uid = uid
                    break

        if target_uid and target_uid in users:
            del users[target_uid]
            if tokens.get('default_user_id') == target_uid:
                tokens['default_user_id'] = next(iter(users)) if users else None
            tokens['users'] = users
            if not users:
                tokens.pop('basecamp', None)
                tokens['default_user_id'] = None
            _write_tokens(tokens)
            return True
        return False


def store_token(access_token: str, refresh_token: Optional[str] = None, expires_in: Optional[int] = None, account_id: Optional[str] = None) -> bool:
    """Legacy wrapper."""
    user_id = str(account_id or 'default')
    return store_user_token(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        account_id=account_id
    )


def clear_tokens() -> bool:
    """Clear all stored tokens."""
    with _lock:
        r = _get_redis_client()
        if r:
            try:
                r.delete("basecamp:tokens")
            except Exception:
                pass
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
        return True
