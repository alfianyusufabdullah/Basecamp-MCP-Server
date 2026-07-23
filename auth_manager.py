"""
Auth manager for Basecamp MCP server.
Handles automatic multi-user token refresh logic.
"""

import logging
import os
import token_storage
from basecamp_oauth import BasecampOAuth
from datetime import datetime

logger = logging.getLogger(__name__)

def ensure_authenticated(user_id: str = None) -> bool:
    """
    Checks if the token for the specified user_id (or default active user) is valid
    and automatically refreshes it if necessary.

    Args:
        user_id (str, optional): The user ID, account ID, or API key to check.

    Returns:
        bool: True if authenticated (or successfully refreshed), False otherwise.
    """
    token_data = token_storage.get_user_token(user_id)

    if not token_data or not token_data.get('access_token'):
        logger.error(f"No token data found for user_id={user_id}. Initial authentication required.")
        return False

    resolved_user_id = token_data.get('user_id') or user_id or token_data.get('account_id') or 'default'

    if not token_storage.is_user_token_expired(resolved_user_id):
        logger.debug(f"Token for user_id={resolved_user_id} is still valid.")
        return True

    # Token is expired, try to refresh
    refresh_token = token_data.get('refresh_token')
    if not refresh_token:
        logger.error(f"Token expired and no refresh token available for user_id={resolved_user_id}.")
        return False

    logger.info(f"Token expired for user_id={resolved_user_id}. Attempting automatic refresh...")

    try:
        oauth = BasecampOAuth()
        new_token_data = oauth.refresh_token(refresh_token)

        new_access_token = new_token_data.get('access_token')
        new_refresh_token = new_token_data.get('refresh_token') or refresh_token
        expires_in = new_token_data.get('expires_in')
        account_id = token_data.get('account_id')

        token_storage.store_user_token(
            user_id=resolved_user_id,
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            expires_in=expires_in,
            account_id=account_id,
            email=token_data.get('email'),
            name=token_data.get('name'),
            api_key=token_data.get('api_key')
        )

        logger.info(f"Successfully refreshed and stored new tokens for user_id={resolved_user_id}.")
        return True
    except Exception as e:
        logger.error(f"Failed to refresh token for user_id={resolved_user_id}: {e}")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if ensure_authenticated():
        print("Authenticated default user!")
    else:
        print("Authentication failed.")
