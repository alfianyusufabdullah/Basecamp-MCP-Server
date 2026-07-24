"""
Unit tests for multi-user token storage operations.
"""

import os
import tempfile
import pytest
from unittest import mock
import token_storage


@pytest.fixture
def temp_token_file(monkeypatch):
    """Fixture creating a temporary token file for clean testing."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        temp_path = tf.name

    monkeypatch.setattr(token_storage, 'TOKEN_FILE', temp_path)
    yield temp_path

    if os.path.exists(temp_path):
        os.remove(temp_path)


def test_store_and_retrieve_multiple_users(temp_token_file):
    # Store user 1
    res1 = token_storage.store_user_token(
        user_id="user_1",
        access_token="token_1",
        refresh_token="refresh_1",
        expires_in=3600,
        account_id="acc_1",
        email="user1@example.com",
        name="User One",
        set_as_default=True
    )
    assert res1 is True

    # Store user 2
    res2 = token_storage.store_user_token(
        user_id="user_2",
        access_token="token_2",
        refresh_token="refresh_2",
        expires_in=3600,
        account_id="acc_2",
        email="user2@example.com",
        name="User Two",
        set_as_default=False
    )
    assert res2 is True

    # Retrieve user 1 explicitly
    u1 = token_storage.get_user_token("user_1")
    assert u1 is not None
    assert u1['access_token'] == "token_1"
    assert u1['email'] == "user1@example.com"

    # Retrieve user 2 explicitly
    u2 = token_storage.get_user_token("user_2")
    assert u2 is not None
    assert u2['access_token'] == "token_2"
    assert u2['email'] == "user2@example.com"

    # Retrieve default user (should be user_1 because set_as_default=True)
    default_user = token_storage.get_token()
    assert default_user['user_id'] == "user_1"

    # List users
    user_list = token_storage.list_users()
    assert len(user_list) == 2


def test_set_default_user_and_removal(temp_token_file):
    token_storage.store_user_token("u1", "token1", account_id="acc1", set_as_default=True)
    token_storage.store_user_token("u2", "token2", account_id="acc2", set_as_default=False)

    assert token_storage.get_token()['user_id'] == "u1"

    # Switch default user
    assert token_storage.set_default_user("u2") is True
    assert token_storage.get_token()['user_id'] == "u2"

    # Remove default user
    assert token_storage.remove_user_token("u2") is True
    assert token_storage.get_token()['user_id'] == "u1"
    assert len(token_storage.list_users()) == 1


def test_get_user_token_strict_isolation_when_none(temp_token_file):
    token_storage.store_user_token("u1", "token1", account_id="acc1")
    assert token_storage.get_user_token(None) is None
    assert token_storage.get_user_token("") is None
    assert token_storage.get_user_token("invalid_key_123") is None

